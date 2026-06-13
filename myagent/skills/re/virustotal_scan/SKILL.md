---
name: virustotal_scan
description: Calculates the SHA-256 hash of a target binary and queries the VirusTotal API to retrieve malware family, community tags, and behavior indicators.
version: 1.0.0
metadata:
  hermes:
    tags: [reversing, osint, virustotal, malware]
    category: re
---
# VirusTotal OSINT Skill

## When to Use
Use this skill when you want to gather threat intelligence on a binary.
Trigger: user says "check virustotal", "vt scan", or "osint check".

## Prerequisites
- The environment variable `VIRUSTOTAL_API_KEY` must be set.
- The `requests` Python library is available in the execution environment.

## Procedure
1. Use Python to calculate the SHA-256 hash of the target binary.
2. Query the VirusTotal API (v3) using the calculated hash.
3. Extract the `meaningful_name`, `tags`, `popular_threat_classification`, and `last_analysis_stats`.

### Python Implementation Template
Execute the following Python script using your code execution capabilities:
```python
import hashlib
import os
import urllib.request
import json
import sys

binary_path = "<INSERT_BINARY_PATH>"
api_key = os.environ.get("VIRUSTOTAL_API_KEY")

if not api_key:
    print("Error: VIRUSTOTAL_API_KEY environment variable is missing.")
    sys.exit(1)

# Calculate SHA256
sha256_hash = hashlib.sha256()
with open(binary_path, "rb") as f:
    for byte_block in iter(lambda: f.read(4096), b""):
        sha256_hash.update(byte_block)
file_hash = sha256_hash.hexdigest()

# Query VT
url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
req = urllib.request.Request(url, headers={"x-apikey": api_key})

try:
    with urllib.request.urlopen(req) as response:
        if response.status == 200:
            data = json.loads(response.read().decode())['data']['attributes']
            print(f"Hash: {file_hash}")
            print(f"Meaningful Name: {data.get('meaningful_name')}")
            print(f"Type: {data.get('type_description')}")
            print(f"Tags: {', '.join(data.get('tags', []))}")
            stats = data.get('last_analysis_stats', {})
            print(f"Malicious: {stats.get('malicious')} / {sum(stats.values())}")
except urllib.error.HTTPError as e:
    if e.code == 404:
        print(f"Hash {file_hash} not found on VirusTotal.")
    else:
        print(f"Error querying VT: {e.code} - {e.read().decode()}")
except Exception as e:
    print(f"Error: {e}")
```

## Reporting Format
Produce a brief summary of the VirusTotal findings to the user. Do not dump the raw JSON. Highlight if the file is flagged as malicious and list its common tags/labels.
