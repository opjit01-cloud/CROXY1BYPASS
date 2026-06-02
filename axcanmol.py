import sys
import os
import uuid
import threading
import time
import random
import base64
import binascii
import re
import json
import sqlite3
from pathlib import Path
from mitmproxy import http
from mitmproxy.tools.main import mitmdump
from src.core.majorlogin_ob53_pb2 import MajorLoginOb53, MajorLoginResOb53
from src.core.login_pb2 import getUID, LoginReq
from src.utils.proto_utils import ProtobufUtils
from src.utils.decrypt import AESUtils
import requests
import urllib3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timezone

# Try to import nickname modifier proto
try:
    from src.core import CSGetAccountBriefInfoBeforeLoginRes_pb2
except ImportError:
    CSGetAccountBriefInfoBeforeLoginRes_pb2 = None
    print("[!] CSGetAccountBriefInfoBeforeLoginRes_pb2 not available")

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = Path(__file__).parent
UID_FILE = BASE_DIR / "uid.txt"
LOG_FILE = BASE_DIR / "access_token_log.txt"
WHITELIST_FILE = BASE_DIR / "whitelist.json"
DB_FILE = BASE_DIR / "logins.db"
FIREBASE_URL = ""

protoUtils = ProtobufUtils()
aesUtils = AESUtils()

UID_CACHE = set()
CACHE_LOCK = threading.Lock()
LAST_REFRESH = 0
REFRESH_INTERVAL = 300

STATS = {
    "allowed": 0,
    "blocked": 0,
    "total": 0
}
STATS_LOCK = threading.Lock()

HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length"
}

UNK_102_OB53 = bytes.fromhex("655c1616704a0b0f24515e165a13")

# Anti-detection: Expanded device profiles with randomization
REGION_PROFILES = {
    "IN": {
        "country": "IN",
        "language": "en",
        "carriers": ["40445", "40551", "40552", "40553", "40462", "40547", "40471"],
        "devices": ["SM-S918B", "CPH2581", "Pixel 8 Pro", "2211133G", "SM-S928B", "Pixel 7 Pro", "M2007J20CG"],
        "network": ["5G", "4G", "5G", "Wi-Fi", "5G", "4G"],
        "user_agents": [
            "Dalvik/2.1.0 (Linux; U; Android 14; SM-S918B Build/UP1A.231005.007)",
            "Dalvik/2.1.0 (Linux; U; Android 14; CPH2581 Build/UP1A.231005.007)",
            "Dalvik/2.1.0 (Linux; U; Android 13; Pixel 8 Pro Build/TQ3A.230805.001)",
            "Dalvik/2.1.0 (Linux; U; Android 14; SM-S928B Build/UP1A.231005.007)",
        ]
    },
    "US": {
        "country": "US",
        "language": "en-US",
        "carriers": ["310260", "310410", "311480", "310150", "310120", "310090", "310280"],
        "devices": ["Pixel 8 Pro", "SM-S928B", "CPH2581", "SM-S918B", "Pixel 7 Pro", "Pixel 9 Pro"],
        "network": ["5G", "5G", "4G", "Wi-Fi", "5G", "4G"],
        "user_agents": [
            "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Pro Build/AP1A.240505.005)",
            "Dalvik/2.1.0 (Linux; U; Android 14; SM-S928B Build/UP1A.231005.007)",
            "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 7 Pro Build/TQ3A.230805.001)",
        ]
    },
    "BR": {
        "country": "BR",
        "language": "pt-BR",
        "carriers": ["72405", "72406", "72410", "72415", "72400", "72408", "72411"],
        "devices": ["SM-S918B", "M2007J20CG", "CPH2581", "2211133G", "M2101K7BG", "Pixel 6 Pro"],
        "network": ["4G", "4G", "5G", "Wi-Fi", "4G", "5G"],
        "user_agents": [
            "Dalvik/2.1.0 (Linux; U; Android 14; SM-S918B Build/UP1A.231005.007)",
            "Dalvik/2.1.0 (Linux; U; Android 13; M2007J20CG Build/TQ3A.230805.001)",
            "Dalvik/2.1.0 (Linux; U; Android 14; CPH2581 Build/UP1A.231005.007)",
        ]
    },
    "SG": {
        "country": "SG",
        "language": "en-SG",
        "carriers": ["52501", "52502", "52503", "52505", "52500", "52504", "52506"],
        "devices": ["CPH2581", "SM-S918B", "Pixel 8 Pro", "2211133G", "SM-S928B", "Pixel 7 Pro"],
        "network": ["5G", "5G", "4G", "Wi-Fi", "5G", "4G"],
        "user_agents": [
            "Dalvik/2.1.0 (Linux; U; Android 14; CPH2581 Build/UP1A.231005.007)",
            "Dalvik/2.1.0 (Linux; U; Android 14; SM-S918B Build/UP1A.231005.007)",
            "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Pro Build/AP1A.240505.005)",
        ]
    },
    "EU": {
        "country": "GB",
        "language": "en-GB",
        "carriers": ["23410", "23415", "23420", "23430", "23450", "23455", "23433"],
        "devices": ["SM-S928B", "Pixel 8 Pro", "CPH2581", "SM-S918B", "Pixel 7 Pro", "SM-S938B"],
        "network": ["5G", "4G", "5G", "Wi-Fi", "4G", "5G"],
        "user_agents": [
            "Dalvik/2.1.0 (Linux; U; Android 14; SM-S928B Build/UP1A.231005.007)",
            "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Pro Build/AP1A.240505.005)",
            "Dalvik/2.1.0 (Linux; U; Android 14; CPH2581 Build/UP1A.231005.007)",
        ]
    },
    "DEFAULT": {
        "country": "IN",
        "language": "en",
        "carriers": ["40445", "40551", "310260"],
        "devices": ["SM-S918B", "Pixel 8 Pro", "CPH2581"],
        "network": ["5G", "4G", "Wi-Fi"],
        "user_agents": [
            "Dalvik/2.1.0 (Linux; U; Android 14; SM-S918B Build/UP1A.231005.007)",
            "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Pro Build/AP1A.240505.005)",
        ]
    }
}

# Expanded Android versions
ANDROID_VERSIONS = [
    "Android OS 15 / API-35 (TP1A.220905.001/U.R4T2.1c822c2_1_3)",
    "Android OS 14 / API-34 (UP1A.231005.007)",
    "Android OS 14 / API-34 (AP1A.240505.005)",
    "Android OS 13 / API-33 (TQ3A.230805.001)",
    "Android OS 14 / API-34 (UKQ1.230918.001)",
    "Android OS 15 / API-35 (AP3A.240905.015)",
    "Android OS 14 / API-34 (UQ1A.240105.004)",
]

# Random GPU renderers
GPU_RENDERERS = [
    "Adreno (TM) 740", "Adreno (TM) 730", "Mali-G710", "Adreno (TM) 750",
    "Mali-G715", "Adreno (TM) 660", "PowerVR Rogue", "Adreno (TM) 690"
]

# Random processor details
PROCESSOR_DETAILS = [
    "ARM64 FP ASIMD AES | 5260 | 8",
    "ARMv8.2 FP ASIMD | 8 cores",
    "ARM64 FP ASIMD AES | 8 cores",
    "ARM64 FP ASIMD | 8 cores 2.84GHz",
    "ARMv8.2 FP ASIMD | 10 cores"
]

# Create a session with retry strategy
session = requests.Session()
session.verify = False
session.headers.update({
    'Connection': 'keep-alive',
    'Accept-Encoding': 'gzip, deflate, br',
})
adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=3)
session.mount('https://', adapter)

def init_database():
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS logins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uid TEXT NOT NULL,
                ip TEXT,
                country TEXT,
                region TEXT,
                city TEXT,
                status TEXT,
                timestamp REAL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                uid TEXT PRIMARY KEY,
                reason TEXT,
                added_at REAL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS stats (
                key TEXT PRIMARY KEY,
                value INTEGER
            )
        """)
        conn.commit()
        conn.close()
        print("[✓] Database initialized")
    except Exception as e:
        print(f"[!] Database init error: {e}")

def inc_stat(stat_name):
    with STATS_LOCK:
        STATS[stat_name] = STATS.get(stat_name, 0) + 1
        STATS["total"] += 1

def log_login_db(uid, ip, country, region, city, status):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO logins (uid, ip, country, region, city, status, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (uid, ip, country, region, city, status, time.time())
        )
        conn.commit()
        conn.close()
    except:
        pass

def check_uid_exists(uid):
    uid = str(uid).strip()
    if uid == "0":
        return True
    with CACHE_LOCK:
        return uid in UID_CACHE

def is_blacklisted(uid):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM blacklist WHERE uid=?", (str(uid),))
        result = cur.fetchone() is not None
        conn.close()
        return result
    except:
        return False

def add_to_blacklist(uid, reason="Auto-blacklisted"):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO blacklist (uid, reason, added_at) VALUES (?, ?, ?)",
            (str(uid), reason, time.time())
        )
        conn.commit()
        conn.close()
        print(f"[BLACKLIST] Added UID {uid}")
    except:
        pass

def get_region_from_jwt(flow):
    try:
        auth_header = flow.request.headers.get("Authorization", "")
        if auth_header:
            match = re.search(r"Bearer\s+([\w\-\.]+)", auth_header)
            if match:
                token = match.group(1)
                payload = token.split(".")[1]
                payload += "=" * (4 - len(payload) % 4)
                decoded = json.loads(base64.urlsafe_b64decode(payload))
                region = decoded.get("lock_region", decoded.get("region", "DEFAULT"))
                if region in REGION_PROFILES:
                    return region
    except:
        pass
    return "DEFAULT"

def get_region_profile(flow):
    region = get_region_from_jwt(flow)
    profile = REGION_PROFILES.get(region, REGION_PROFILES["DEFAULT"]).copy()
    profile["network"] = random.choice(profile["network"])
    profile["user_agent"] = random.choice(profile["user_agents"])
    return profile, region

def get_random_device(profile):
    return random.choice(profile["devices"])

def get_random_carrier(profile):
    return random.choice(profile["carriers"])

def get_random_android():
    return random.choice(ANDROID_VERSIONS)

def get_random_ram():
    return random.randint(4096, 16384)

def get_random_google_account():
    return f"Google|{uuid.uuid4().hex}"

def get_random_session_id():
    return uuid.uuid4().hex[:32]

def get_random_loading_time():
    return random.randint(8000, 45000)

def get_random_delay():
    return random.uniform(0.05, 0.15)

def get_random_oaid():
    return f"{uuid.uuid4().hex[:8]}-{uuid.uuid4().hex[:4]}-{uuid.uuid4().hex[:4]}-{uuid.uuid4().hex[:4]}-{uuid.uuid4().hex[:12]}"

def get_random_gpu():
    return random.choice(GPU_RENDERERS)

def get_random_processor():
    return random.choice(PROCESSOR_DETAILS)

def get_random_screen_resolution():
    resolutions = [(1080, 2400), (1080, 2412), (1200, 2640), (1440, 3200), (1080, 2340), (1440, 3120), (1220, 2712)]
    return random.choice(resolutions)

def get_random_density():
    return str(random.choice([420, 440, 480, 560, 400, 500]))

def get_random_storage():
    return random.choice([128, 256, 512, 1024])

def load_whitelist():
    global UID_CACHE, LAST_REFRESH
    new_uids = set()
    
    if UID_FILE.exists():
        try:
            with open(UID_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and line.isdigit():
                        new_uids.add(line)
                        print(f"[✓] uid.txt: {line}")
        except:
            pass
    
    if WHITELIST_FILE.exists():
        try:
            with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                whitelisted = data.get("whitelisted_uids", {})
                for uid, expiry in whitelisted.items():
                    if expiry > time.time():
                        new_uids.add(str(uid))
                        print(f"[✓] whitelist.json: {uid}")
        except:
            pass
    
    if FIREBASE_URL:
        try:
            resp = requests.get(FIREBASE_URL, timeout=10)
            if resp.status_code == 200:
                users = resp.json()
                if users:
                    for user_data in users.values():
                        uids = user_data.get("uids", {})
                        if isinstance(uids, dict):
                            for uid_data in uids.values():
                                if isinstance(uid_data, dict) and "uid" in uid_data:
                                    new_uids.add(str(uid_data["uid"]))
        except:
            pass
    
    with CACHE_LOCK:
        UID_CACHE = new_uids
        LAST_REFRESH = time.time()
    print(f"[✓] Total UIDs in whitelist: {len(UID_CACHE)}")

def check_uid(uid):
    uid = str(uid).strip()
    if uid == "0":
        return True
    with CACHE_LOCK:
        if time.time() - LAST_REFRESH > REFRESH_INTERVAL:
            threading.Thread(target=load_whitelist, daemon=True).start()
        return uid in UID_CACHE

# Initialize
init_database()
load_whitelist()
threading.Thread(target=load_whitelist, daemon=True).start()

def save_mitmproxy_cert():
    try:
        home = os.path.expanduser("~/.mitmproxy")
        ca_cert = os.path.join(home, "mitmproxy-ca-cert.pem")
        output_file = BASE_DIR / "certificat_mitmproxy.pem"
        if os.path.exists(ca_cert):
            with open(ca_cert, "rb") as src, open(output_file, "wb") as dst:
                dst.write(src.read())
    except:
        pass

def log_access_token(open_id, access_token, platform="", uid="", status=""):
    try:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        line = f"[{ts}] open_id={open_id} | token={access_token[:50] if access_token else 'None'}... | platform={platform}"
        if uid:
            line += f" | uid={uid}"
        if status:
            line += f" | status={status}"
        line += "\n"
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line)
    except:
        pass

def build_majorlogin_ob53(open_id, access_token, platform_type, real_ip, profile, region):
    pt = str(platform_type) if platform_type else "3"
    event_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    
    session_device = get_random_device(profile)
    session_carrier = get_random_carrier(profile)
    session_android = get_random_android()
    session_ram = get_random_ram()
    session_google = get_random_google_account()
    session_id = get_random_session_id()
    loading_time = get_random_loading_time()
    oaid = get_random_oaid()
    screen_width, screen_height = get_random_screen_resolution()
    gpu_renderer = get_random_gpu()
    processor = get_random_processor()
    density = get_random_density()
    storage_total = get_random_storage() * 1000
    storage_available = random.randint(storage_total // 3, storage_total)
    
    msg = MajorLoginOb53()
    msg.event_time = event_time
    msg.game_name = "free fire"
    msg.client_version = random.choice(["1.123.6", "1.123.7"])
    msg.system_software = session_android
    msg.system_hardware = random.choice(["qcom", "mediatek", "exynos"])
    msg.telecom_operator = session_carrier
    msg.network_type = profile["network"]
    msg.screen_width = screen_width
    msg.screen_height = screen_height
    msg.screen_dpi = density
    msg.processor_details = processor
    msg.memory = session_ram
    msg.gpu_renderer = gpu_renderer
    msg.gpu_version = random.choice([
        "OpenGL ES 3.2 V@0676.65",
        "OpenGL ES 3.2 V@0525.30",
        "Vulkan 1.3",
    ])
    msg.unique_device_id = uuid.uuid4().hex
    msg.client_ip = real_ip
    msg.language = profile["language"]
    msg.open_id = open_id
    msg.open_id_type = pt
    msg.device_type = "Handheld"
    msg.device_model = session_device
    msg.country = profile["country"]
    msg.access_token = access_token
    msg.platform_sdk_id = random.choice([1, 2, 3])
    msg.internal_storage_total = storage_total
    msg.internal_storage_available = storage_available
    msg.reg_avatar = random.randint(1, 15)
    msg.library_token = random.choice(["AndroidDevice", "MobileSDK", "GameClient"])
    msg.channel_type = random.choice([1, 2, 3])
    msg.cpu_type = random.choice([1, 2, 3])
    msg.client_version_code = random.choice(["2019120273", "2020011522", "2021050678"])
    msg.graphics_api = random.choice(["OpenGL ES 3.2", "Vulkan"])
    msg.supported_astc_bitset = random.choice([255, 511, 127])
    msg.login_open_id_type = 3
    msg.loading_time = loading_time
    msg.release_channel = random.choice(["android", "googleplay"])
    msg.extra_info = "KqsHT7MUjyjjnA/jcWo74TjG04IMJoCAYFBIAOaqjgev7SOLjHCkzmg2MVIU4w9Hoxb4LQ=="
    msg.origin_platform_type = pt
    msg.primary_platform_type = pt
    msg.unk_102 = UNK_102_OB53
    
    if hasattr(msg, 'oaid'):
        msg.oaid = oaid
    
    return msg.SerializeToString()

def ob53_request_headers(access_token, profile):
    return {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": random.choice([f"{profile['language']},{profile['language'].split('-')[0]};q=0.9", "en-US,en;q=0.9"]),
        "Authorization": f"Bearer {access_token}",
        "Connection": "keep-alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Host": "loginbp.ggpolarbear.com",
        "ReleaseVersion": "OB53",
        "User-Agent": profile["user_agent"],
        "X-GA": f"v1 {random.randint(1,5)}",
        "X-Unity-Version": random.choice(["2022.3.47f1", "2022.3.46f1"]),
        "Cache-Control": "no-cache",
        "X-Requested-With": "com.dts.freefireth",
    }

KEY = base64.b64decode("WWcmdGMlREV1aDYlWmNeOA==")
IV = base64.b64decode("Nm95WkRyMjJFM3ljaGpNJQ==")

def _aes_cbc_decrypt_nopad(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    return cipher.decryptor().update(data) + cipher.decryptor().finalize()

def _strip_pkcs7(data):
    pad = data[-1]
    if 1 <= pad <= 16 and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return data

def _try_proto(data, proto_cls):
    msg = proto_cls()
    msg.ParseFromString(data)
    oid = getattr(msg, "open_id", "") or ""
    tok = getattr(msg, "access_token", "") or getattr(msg, "login_token", "") or ""
    otyp = getattr(msg, "open_id_type", "") or ""
    ptype = getattr(msg, "origin_platform_type", "") or ""
    if not ptype and otyp:
        ptype = otyp
    return oid, tok, otyp, ptype

def try_parse_loginreq_decrypted(raw_body):
    if len(raw_body) % 16 != 0:
        return None
    try:
        dec = _aes_cbc_decrypt_nopad(raw_body, KEY, IV)
        dec = _strip_pkcs7(dec)
        r = LoginReq()
        r.ParseFromString(dec)
        if r.open_id:
            return r
    except:
        pass
    return None

def try_parse_loginreq_plain(raw_body):
    try:
        r = LoginReq()
        r.ParseFromString(raw_body)
        if r.open_id:
            return r
    except:
        pass
    return None

def extract_credentials(raw_body):
    for proto_cls in (MajorLoginOb53, LoginReq):
        try:
            oid, tok, otyp, ptype = _try_proto(raw_body, proto_cls)
            if oid:
                return oid, tok, otyp, ptype
        except:
            pass
    if len(raw_body) % 16 == 0:
        try:
            dec = _aes_cbc_decrypt_nopad(raw_body, KEY, IV)
            dec = _strip_pkcs7(dec)
            for proto_cls in (MajorLoginOb53, LoginReq):
                try:
                    oid, tok, otyp, ptype = _try_proto(dec, proto_cls)
                    if oid:
                        return oid, tok, otyp, ptype
                except:
                    pass
        except:
            pass
    raise ValueError("Cannot parse MajorLogin body")

def create_colored_error_message(uid):
    """Create the exact colored error message that Free Fire can display"""
    message = (
        f"[44A2FF]⧉───────────────────────────────────────────────⧉\n"
        f"[44A2FF]⟡  INFO :   [FFFFFF]UID NOT AUTHORISED\n"
        f"[44A2FF]⟡  TIME  :   [FFFFFF]{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())}\n"
        f"[44A2FF]⟡  UID     :   [FFFFFF]{uid}\n"
        f"[44A2FF]⟡  DEV  :   [FFFFFF]CROXY CHEATS\n"
        f"[44A2FF]⧉───────────────────────────────────────────────⧉\n"
    )
    return message.encode('utf-8')

class MajorLoginInterceptor:
    def request(self, flow):
        try:
            if flow.request.method.upper() != "POST":
                return
            if "/MajorLogin" not in flow.request.path:
                return
            
            # Random delay to avoid pattern detection
            time.sleep(random.uniform(0.05, 0.15))
            
            real_ip = flow.client_conn.address[0]
            profile, region = get_region_profile(flow)
            
            print(f"\n[→] MajorLogin from {real_ip}")
            print(f"[REGION] {region}")
            
            raw = flow.request.content
            
            login_orig = try_parse_loginreq_plain(raw) or try_parse_loginreq_decrypted(raw)
            if login_orig:
                access_token = login_orig.login_token
                open_id = login_orig.open_id
                pt = login_orig.open_id_type or "3"
                print(f"[PARSE] LoginReq — open_id={open_id[:20]}...")
            else:
                open_id, access_token, open_id_type, platform_type = extract_credentials(raw)
                pt = platform_type or open_id_type or "3"
                print(f"[PARSE] Fallback — open_id={open_id[:20]}...")
            
            log_access_token(open_id, access_token, platform=pt)
            
            plain = build_majorlogin_ob53(open_id, access_token, pt, real_ip, profile, region)
            encrypted_body = aesUtils.encrypt_aes_cbc(plain)
            hdrs = ob53_request_headers(access_token, profile)
            
            # Random delay before sending
            time.sleep(random.uniform(0.03, 0.08))
            
            # Send request with retry
            resp = None
            for attempt in range(3):
                try:
                    resp = session.post(
                        "https://loginbp.ggblueshark.com/MajorLogin",
                        data=bytes.fromhex(encrypted_body.hex()),
                        headers=hdrs,
                        timeout=25
                    )
                    if resp.status_code != 500:
                        break
                    print(f"[!] Retry {attempt + 1}/3...")
                    time.sleep(1)
                except Exception as e:
                    print(f"[!] Attempt {attempt + 1} failed: {e}")
                    time.sleep(1)
            
            if resp is None:
                raise Exception("All retries failed")
            
            out_h = {}
            for k, v in resp.headers.items():
                if k.lower() not in HOP_BY_HOP and k.lower() not in ("transfer-encoding", "content-encoding"):
                    out_h[k] = v
            out_h["Content-Length"] = str(len(resp.content))
            
            flow.response = http.Response.make(resp.status_code, resp.content, out_h)
            
            if resp.status_code == 200:
                print(f"[✓] Request successful")
            else:
                print(f"[!] HTTP {resp.status_code}")
                
        except Exception as e:
            print(f"[ERROR] Request: {e}")
            # Forward original request on error
            flow.response = http.Response.make(200, b"", {})
    
    def response(self, flow):
        try:
            # ===== MajorLogin Response Handler =====
            if flow.request.method.upper() == "POST" and "majorlogin" in flow.request.path.lower():
                if flow.response.status_code != 200:
                    return
                
                # Random delay
                time.sleep(random.uniform(0.03, 0.08))
                
                uid_str = None
                try:
                    decrypted_resp = aesUtils.decrypt_aes_cbc(flow.response.content)
                    major_res = MajorLoginResOb53()
                    major_res.ParseFromString(decrypted_resp)
                    if major_res.account_uid:
                        uid_str = str(major_res.account_uid)
                except:
                    pass
                
                if not uid_str:
                    try:
                        decoded = protoUtils.decode_protobuf(flow.response.content, getUID)
                        uid_str = str(decoded.uid)
                    except:
                        pass
                
                if not uid_str or uid_str == "0":
                    print("[WARN] Could not extract UID")
                    return
                
                print(f"\n[UID] {uid_str}")
                
                client_ip = flow.client_conn.address[0]
                country = flow.request.headers.get("CF-IPCountry", "Unknown")
                region = flow.request.headers.get("CF-IPRegion", "Unknown")
                city = flow.request.headers.get("CF-IPCity", "Unknown")
                
                # Check if UID is whitelisted (NO AUTO-WHITELIST)
                if not check_uid_exists(uid_str):
                    inc_stat("blocked")
                    
                    log_login_db(uid_str, client_ip, country, region, city, "BLOCKED ❌")
                    log_access_token("", "", "", uid_str, "DENIED")
                    
                    # CREATE THE EXACT COLORED MESSAGE YOU WANT
                    colored_message = create_colored_error_message(uid_str)
                    
                    # Create a protobuf response with the colored message
                    try:
                        error_res = MajorLoginResOb53()
                        error_res.account_uid = int(uid_str)
                        error_res.result = 1
                        error_res.error_code = "ERR_ACCESS_DENIED"
                        error_res.error_msg = colored_message.decode('utf-8')
                        
                        serialized = error_res.SerializeToString()
                        encrypted_error = aesUtils.encrypt_aes_cbc(serialized)
                        
                        flow.response.content = encrypted_error
                        flow.response.status_code = 200
                        flow.response.headers["Content-Length"] = str(len(encrypted_error))
                        flow.response.headers["Content-Type"] = "application/octet-stream"
                        print(f"[ACCESS DENIED] Colored message sent to UID {uid_str}")
                    except Exception as e:
                        # Fallback to plain text
                        flow.response.content = colored_message
                        flow.response.status_code = 403
                        flow.response.headers["Content-Length"] = str(len(colored_message))
                        flow.response.headers["Content-Type"] = "text/plain"
                        print(f"[ACCESS DENIED] Text fallback sent to UID {uid_str}")
                    
                    return
                
                # ================= ALLOWED =================
                inc_stat("allowed")
                log_login_db(uid_str, client_ip, country, region, city, "ALLOWED ✅")
                log_access_token("", "", "", uid_str, "GRANTED")
                print(f"[ACCESS GRANTED] UID {uid_str}")
                
                # NO AUTO-WHITELIST - UID must be manually added to uid.txt
            
            # ===== GetAccountBriefInfoBeforeLogin nickname modifier =====
            if flow.request.method.upper() == "POST" and "/GetAccountBriefInfoBeforeLogin" in flow.request.path:
                try:
                    if CSGetAccountBriefInfoBeforeLoginRes_pb2:
                        current_response = CSGetAccountBriefInfoBeforeLoginRes_pb2.CSGetAccountBriefInfoBeforeLoginRes()
                        current_response.ParseFromString(flow.response.content)
                        old_nickname = current_response.nickname
                        # Random color for nickname
                        colors = ["ff0000", "00ff00", "ff9900", "ff00ff", "00ffff", "ffff00"]
                        current_response.nickname = f"[c][{random.choice(colors)}]{old_nickname}"
                        new_content = current_response.SerializeToString()
                        flow.response.content = new_content
                        flow.response.headers["Content-Length"] = str(len(new_content))
                        print(f"[NICKNAME] Modified: {old_nickname}")
                except Exception as e:
                    pass  # Silent fail to avoid detection
                    
        except Exception as e:
            print(f"[ERROR] Response: {e}")

addons = [MajorLoginInterceptor()]
save_mitmproxy_cert()

if __name__ == "__main__":
    print("\n" + "="*60)
    print(" 🔥 AXC BYPASS SYSTEM v5.0 (COLORED MESSAGE) 🔥")
    print("="*60)
    print(f" 📊 Whitelisted UIDs: {len(UID_CACHE)}")
    print(f" 🌍 Regions: IN, US, BR, SG, EU (Auto-detect)")
    print(f" 📱 Device: FULLY RANDOMIZED per request")
    print(f" 📡 Carrier: Region-specific + random")
    print(f" 💾 RAM: Random range (4-16GB)")
    print(f" 🎮 GPU: Random (Adreno/Mali/PowerVR)")
    print(f" 📺 Resolution: Random")
    print(f" 🌐 IP: REAL (No spoofing)")
    print(f" 🔑 OAID: Random per session")
    print(f" ⏱️  Timing: Optimized (0.05-0.15s)")
    print(f" 🔄 Retry: Auto-retry on 500 errors")
    print(f" 🚀 Proxy: http://0.0.0.0:9944")
    print(f" 📝 Log file: {LOG_FILE}")
    print(f" 📋 UID file: {UID_FILE}")
    print(f" 💾 Database: {DB_FILE}")
    print("="*60)
    print("\n ⚠️  HOW TO WHITELIST UIDS:")
    print(" → Add UIDs to uid.txt file (one per line)")
    print(" → Example: 1234567890")
    print(" → Restart proxy after adding UIDs")
    print("="*60)
    print("\n 📺 COLORED ACCESS DENIED MESSAGE WILL SHOW IN GAME!")
    print("="*60)
    print("\n 🟢 Starting proxy...\n")
    print(" ⚠️  IMPORTANT: Install mitmproxy certificate on your device!")
    print(" → Open http://mitm.it on your device browser")
    print(" → Download and install Android certificate")
    print("="*60)
    print("\n")
    
    mitmdump([
        "-s", __file__,
        "-p", "9944",
        "--set", "block_global=false",
        "--set", "ssl_insecure=true",
        "--set", "connection_strategy=lazy",
        "--set", "upstream_cert=false"
    ])