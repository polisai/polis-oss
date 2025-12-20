import requests
import json
import time

url_sse = "http://localhost:8090/sse"
headers = {"X-Agent-ID": "test-agent"}

print(f"Connecting to {url_sse}...")
r = requests.get(url_sse, headers=headers, stream=True)
print(f"Status: {r.status_code}")

for line in r.iter_lines():
    if line:
        print(line.decode("utf-8"))
