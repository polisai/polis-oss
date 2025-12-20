import requests
import time

url = "http://localhost:8090/sse"
headers = {"X-Agent-ID": "test-agent"}

print(f"Connecting to {url}...")
try:
    r = requests.get(url, headers=headers, stream=True, timeout=10)
    print(f"Status: {r.status_code}")
    print(f"Headers: {r.headers}")

    count = 0
    for chunk in r.iter_content(chunk_size=1):
        if chunk:
            print(chunk.decode("utf-8", errors="ignore"), end="", flush=True)
            count += len(chunk)
        if count > 500:
            break
except Exception as e:
    print(f"\nError: {e}")
