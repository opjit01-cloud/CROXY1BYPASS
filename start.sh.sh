#!/bin/bash
# Make sure required files exist
touch uid.txt
touch whitelist.json

# Run the script and log errors
python axcanmol.py 2>&1 | tee startup.log

# If it fails, keep the container alive to see logs
if [ $? -ne 0 ]; then
    echo "=== Script crashed, keeping container alive for debugging ==="
    cat startup.log
    sleep infinity
fi