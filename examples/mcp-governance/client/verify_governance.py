# verify_client.py
import requests
import json


POLIS_URL = "http://localhost:8085/sse"  # Polis Proxy URL
TARGET_URL = "http://localhost:8000/sse"

# Since LangChain MCP support works nicely with stdio, but SSE client support is emerging/custom,
# we will implement a direct JSON-RPC verification script first to prove the PROXY works.
# This removes LangChain version dependencies for the core governance verification.


def call_tool(method, params, id=1):
    # For SSE, usually we POST key to an endpoint, but standard MCP over HTTP is often:
    # 1. Connect to SSE stream for events.
    # 2. POST to a separate endpoint (often provided in the SSE init) for requests.
    # FastMCP/Starlette usually exposes /messages for POST.

    # However, Polis is a proxy. It needs to define how it proxies.
    # If Polis proxies the SSE stream at /sse, it should also proxy the message endpoint.
    # Let's assume Polis config `target_url` points to `http://localhost:8000`.
    # FastMCP serves SSE at `/sse` and messages at `/messages`.

    url = "http://localhost:8085/messages"  # Proxied endpoint

    # MCP over SSE Flow:
    # 1. Start SSE stream to get session ID (endpoint).
    # 2. Use that session ID endpoint for POSTs.

    if method == "filesystem_read_file" and id == 1:
        # Only do handshake once for the demo script flow
        print("  -> Performing SSE Handshake to get Session ID...")
        try:
            # We connect to the proxy's SSE endpoint (config says 8085)
            # which proxies to localhost:8000/sse
            # IMPORTANT: The correct endpoint for FastMCP is /sse
            # And config.yaml upstream_url is http://localhost:8000

            # NOTE: We use stream=True to open connection but not block forever
            sse_url = "http://localhost:8085/sse"
            with requests.get(
                sse_url, stream=True, headers={"X-Agent-ID": "demo-agent-001"}
            ) as r:
                # Read a few lines to find 'event: endpoint' and 'data: ...'
                # FastMCP usually sends this immediately.
                session_endpoint = None
                for line in r.iter_lines():
                    if line:
                        msg = line.decode("utf-8")
                        if msg.startswith("data:"):
                            # The data is usually the relative or absolute URL for messages
                            # e.g., /messages?session_id=...
                            session_endpoint = msg[5:].strip()
                            break
                        if "endpoint" in msg:
                            continue

                if session_endpoint:
                    print(f"  -> Got Session Endpoint: {session_endpoint}")
                    # FastMCP returns path relative to server root, e.g. /messages?session_id=...
                    # We need to construct the full proxy URL.
                    # If upstream returns `/messages?session_id=X`, and we act via proxy,
                    # we need to hit `http://localhost:8085/messages?session_id=X`.

                    # Hack for demo: extract the query param "session_id"
                    if "?" in session_endpoint:
                        query_part = session_endpoint.split("?")[1]
                        # Update our POST target
                        url = f"http://localhost:8085/messages?{query_part}"
                        print(f"  -> Updated POST URL: {url}")
                else:
                    print("  -> Failed to get session endpoint from SSE handshake.")
        except Exception as e:
            print(f"  -> Handshake failed: {e}")

    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": method, "arguments": params},
        "id": id,
    }

    print(f"\n[Request] {method} {params}")
    try:
        headers = {"Content-Type": "application/json", "X-Agent-ID": "demo-agent-001"}
        print(f"[DEBUG-GOV] Payload: {json.dumps(payload)}")
        response = requests.post(url, json=payload, headers=headers)

        print(f"[Status] {response.status_code}")

        if response.status_code == 202:
            print("[Success] Request Allowed (Async 202 Accepted)")
            print("  -> Waiting for Async Result to confirm success...")

            # Need to listen to SSE for result
            # We already have session_endpoint. We can reconnect to SSE stream or use existing connection?
            # verify_governance.py opens connection in a block that closes it!
            # "with requests.get(...)". Connection closed.

            print(
                "  -> WARNING: SSE connection was closed. Result cannot be retrieved in this simple script."
            )
            return

        try:
            data = response.json()
            if "error" in data:
                print(
                    f"[Blocked?] JSON-RPC Error: {data['error']['code']} - {data['error']['message']}"
                )
            elif "result" in data:
                print(f"[Success] Result: {json.dumps(data['result'], indent=2)}")
            else:
                print(f"[Response] {data}")
        except Exception:
            print(f"[Raw] {response.text}")

    except Exception as e:
        print(f"[Error] {e}")


def main():
    print("--- 1. Testing Allowed Read Operation ---")
    call_tool("filesystem_read_file", {"path": "/tmp/sandbox/test.txt"}, 1)

    print("\n--- 2. Testing Blocked Write Operation ---")
    call_tool("filesystem_write_file", {"path": "/etc/passwd", "content": "hacked"}, 2)

    print("\n--- 3. Testing DLP Redaction in Search ---")
    call_tool("search", {"query": "fake ssn data"}, 3)


if __name__ == "__main__":
    main()
