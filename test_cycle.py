import requests
import json
import time
import threading


def test_cycle():
    url_sse = "http://localhost:8090/sse"
    url_msg = "http://localhost:8090/message"
    headers = {"X-Agent-ID": "test-agent"}

    print("Test Cycle: Starting...")

    # 1. Start SSE listener in a thread
    sse_data = []

    def listen():
        try:
            r = requests.get(url_sse, headers=headers, stream=True, timeout=15)
            print(f"SSE Status: {r.status_code}")
            for line in r.iter_lines():
                if line:
                    decoded = line.decode("utf-8")
                    # print(f"DEBUG: {decoded}")
                    if decoded.startswith("data:"):
                        sse_data.append(decoded[5:])
        except Exception as e:
            print(f"SSE Error: {e}")

    listener = threading.Thread(target=listen)
    listener.start()

    time.sleep(2)  # Give it a moment to connect

    # 2. Send Tool List Request
    print("Sending tools/list...")
    payload = {
        "jsonrpc": "2.0",
        "id": "list-req-1",
        "method": "tools/list",
        "params": {},
    }
    r_post = requests.post(url_msg, headers=headers, json=payload)
    print(f"POST Status: {r_post.status_code}")
    print(f"POST Body: {r_post.text}")

    # 3. Wait for response on SSE
    print("Waiting for SSE response...")
    start_wait = time.time()
    found = False
    while time.time() - start_wait < 10:
        for d in sse_data:
            try:
                msg = json.loads(d)
                if msg.get("id") == "list-req-1":
                    print("SUCCESS! Received tool list on SSE.")
                    # print(json.dumps(msg, indent=2))
                    found = True
                    break
            except:
                continue
        if found:
            break
        time.sleep(1)

    if not found:
        print("FAILED: Did not receive response on SSE within timeout.")

    print("Test Cycle: Done.")


if __name__ == "__main__":
    test_cycle()
