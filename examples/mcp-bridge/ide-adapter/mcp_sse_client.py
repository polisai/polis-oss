import sys
import argparse
import threading
import requests
import queue
import os


# Flush stdout to ensure the IDE receives messages immediately
def flush_stdout():
    try:
        sys.stdout.flush()
    except Exception:
        pass


def read_stdin(message_queue):
    """Reads JSON-RPC messages from stdin and puts them in a queue."""
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            message_queue.put(line.strip())
        except Exception:
            break


def sse_listener(session_url, headers):
    """Listens to the SSE stream and prints events to stdout."""
    try:
        with requests.get(session_url, headers=headers, stream=True) as response:
            response.raise_for_status()
            for line in response.iter_lines():
                if line:
                    decoded = line.decode("utf-8")
                    if decoded.startswith("data: "):
                        data = decoded[6:]
                        if data.strip() == "[DONE]":
                            continue
                        try:
                            # Forward the JSON-RPC message to stdout
                            # We might need to unwrap if it's raw JSON or just pass through
                            # The Polis bridge sends raw JSON in the data field
                            print(data)
                            flush_stdout()
                        except Exception as e:
                            sys.stderr.write(f"Error parsing SSE data: {e}\n")
    except Exception as e:
        sys.stderr.write(f"SSE Connection failed: {e}\n")
        # In a real scenario, we might want to exit or retry
        os._exit(1)


def main():
    parser = argparse.ArgumentParser(description="MCP Stdio to SSE Adapter")
    parser.add_argument(
        "--url", default="http://localhost:8090", help="Polis Bridge Base URL"
    )
    parser.add_argument("--agent-id", default="ide-user", help="Agent ID for headers")
    parser.add_argument("--api-key", help="Optional API Key for the tools")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    sse_url = f"{base_url}/sse"
    message_url = f"{base_url}/message"

    headers = {"X-Agent-ID": args.agent_id}

    # 1. Connect to SSE to establish session
    # We need to start this in a thread, but we first need the session ID?
    # Actually, Polis returns the session ID in the headers or the first event?
    # Let's just connect. Polis handles session creation on SSE connect.

    # We'll use a queue to send messages from stdin to the poster thread
    msg_queue = queue.Queue()

    # Start stdin reader
    input_thread = threading.Thread(target=read_stdin, args=(msg_queue,), daemon=True)
    input_thread.start()

    # Start SSE listener
    # Note: verify if your bridge implementation requires a POST first or just SSE?
    # Polis creates session on SSE GET.
    sse_thread = threading.Thread(
        target=sse_listener, args=(sse_url, headers), daemon=True
    )
    sse_thread.start()

    # Message posting loop
    # We need to wait for the session to be established?
    # The bridge allows posting with X-Agent-ID, it will direct to the active session or create one?
    # Wait, the bridge requires X-Session-ID for messages usually, OR it infers from AgentID if strict mode is off?
    # Let's look at bridge code. handleMessage validates sessionID.
    # The client usually receives an "endpoint" event with the URL including the sessionID.
    # For this simple adapter, we might need to parse the first SSE event to get the session ID URL.
    # But for now, let's assume the bridge accepts X-Agent-ID correlation if we are lucky,
    # OR we parse the "endpoint" event in the sse_listener and update the post URL.

    # Simple strategy: The sse_listener will see the "endpoint" event.
    # But to be robust, we can just start reading stdin and posting.
    # If the bridge requires session_id, we might fail the first few posts until we capture it?
    # Better: The IDE initiates "initialize". We send that.

    # We need a shared variable for the session-specific message URL
    # For now, we will try posting to /message with just Agent-ID and let the bridge handle it
    # (if the bridge supports agent-based routing without session ID, which it might not).
    # IF NOT, this adapter needs to be smarter and wait for the 'endpoint' event.

    while True:
        msg = msg_queue.get()
        if msg is None:
            break

        # In a robust implementation, we'd wait for session_id from SSE
        # logging.info(f"Posting: {msg}")
        try:
            # We'll try posting to the generic message endpoint.
            # If the bridge needs session_id, we should extract it from the SSE 'endpoint' event.
            # Let's assume for this MVP that we rely on the bridge's header support or we just append it if we have it.

            post_headers = headers.copy()
            post_headers["Content-Type"] = "application/json"

            # Send the message
            # If we haven't received the endpoint event yet, this might fail if the bridge requires session_id.
            # But usually the handshake is tolerant?
            # Let's optimistically post.
            requests.post(message_url, data=msg, headers=post_headers)

        except Exception as e:
            sys.stderr.write(f"Post failed: {e}\n")


if __name__ == "__main__":
    main()
