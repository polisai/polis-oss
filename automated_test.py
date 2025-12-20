import requests
import sseclient
import threading
import json
import time


def test_bridge():
    url = "http://localhost:8090/sse"
    header = {"X-Agent-ID": "test-agent"}

    print(f"Connecting to {url}...")

    # We'll use a session to maintain connection
    response = requests.get(url, headers=header, stream=True)
    client = sseclient.SSEClient(response)

    results = []

    def post_message():
        time.sleep(2)  # Wait for SSE to be ready
        print("Sending tools/list request...")
        post_url = "http://localhost:8090/message"
        payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        res = requests.post(post_url, headers=header, json=payload)
        print(f"POST result: {res.status_code}")

    thread = threading.Thread(target=post_message)
    thread.start()

    print("Listening for events...")
    for event in client.events():
        print(f"Event: {event.event}")
        print(f"Data: {event.data}")

        if event.data:
            try:
                data = json.loads(event.data)
                if "result" in data and "tools" in data["result"]:
                    print("SUCCESS: Tools listed!")
                    results.append("Phase 2.2: List Tools (tested)")
                    break
            except:
                pass

        # Stop after some time or if we have what we need
        if len(results) > 0:
            break

    print("\nVerified functionality:")
    for r in results:
        print(f"- {r}")


if __name__ == "__main__":
    test_bridge()
