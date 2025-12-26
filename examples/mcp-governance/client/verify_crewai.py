import signal
import sys

# Patch signal.SIGHUP on Windows for CrewAI compatibility
if sys.platform == "win32":
    if not hasattr(signal, "SIGHUP"):
        signal.SIGHUP = 1
    if not hasattr(signal, "SIGTSTP"):
        signal.SIGTSTP = 1
    if not hasattr(signal, "SIGCONT"):
        signal.SIGCONT = 1

from crewai import Agent, Task, Crew, Process
from crewai.tools import BaseTool
import requests
import json
import threading
import time

# Configuration
POLIS_PROXY_URL = "http://localhost:8085/messages"


class SSEClient:
    def __init__(self, sse_url, post_url_base):
        self.sse_url = sse_url
        self.post_url_base = post_url_base
        self.session_id = None
        self.post_url = post_url_base
        self.results = {}
        self.lock = threading.Lock()
        self.initialized = False

        # Start listening in a background thread
        self.thread = threading.Thread(target=self._listen, daemon=True)
        self.thread.start()
        # Wait for handshake
        time.sleep(1)

    def _listen(self):
        try:
            with requests.get(
                self.sse_url, stream=True, headers={"X-Agent-ID": "demo-agent-001"}
            ) as r:
                for line in r.iter_lines():
                    if not line:
                        continue
                    msg = line.decode("utf-8")
                    if msg.startswith("data:"):
                        data_str = msg[5:].strip()
                        # Handshake: endpoint
                        if "/messages" in data_str and "session_id=" in data_str:
                            self.session_id = data_str.split("session_id=")[1].strip()
                            self.post_url = (
                                f"{self.post_url_base}?session_id={self.session_id}"
                            )
                            print(f"[SSE] Connected. Session ID: {self.session_id}")
                            continue

                        # Result handling
                        try:
                            data = json.loads(data_str)
                            if "id" in data:
                                with self.lock:
                                    self.results[data["id"]] = data
                        except Exception:
                            pass
        except Exception:
            pass

    def _initialize(self):
        if self.initialized:
            return

        headers = {"Content-Type": "application/json", "X-Agent-ID": "demo-agent-001"}
        init_id = "init"
        init_payload = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "crewai-client", "version": "1.0"},
            },
            "id": init_id,
        }
        requests.post(self.post_url, json=init_payload, headers=headers, timeout=5)

        # Wait for init result
        for _ in range(50):
            with self.lock:
                if init_id in self.results:
                    break
            time.sleep(0.1)

        # Initialized Notification
        notif_payload = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }
        requests.post(self.post_url, json=notif_payload, headers=headers, timeout=5)
        self.initialized = True

    def call(self, method, params, id_val):
        if not self.session_id:
            # Try to wait a bit more if not connected
            time.sleep(1)

        if not self.initialized:
            self._initialize()

        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": method, "arguments": params},
            "id": id_val,
        }

        # Clear previous result for this ID
        with self.lock:
            if id_val in self.results:
                del self.results[id_val]

        headers = {"Content-Type": "application/json", "X-Agent-ID": "demo-agent-001"}

        try:
            resp = requests.post(
                self.post_url, json=payload, headers=headers, timeout=10
            )
        except Exception as e:
            return {"error": {"message": f"POST Failed: {e}"}}

        if resp.status_code == 202:
            # Wait for async result
            for _ in range(30):
                with self.lock:
                    if id_val in self.results:
                        return self.results[id_val]
                time.sleep(0.1)
            return {"error": {"message": "Timeout waiting for SSE result"}}

        # If immediate response (e.g. error)
        try:
            return resp.json()
        except Exception:
            return {"error": {"message": f"Raw response: {resp.text}"}}


from pydantic import BaseModel, Field

# Global client
client = SSEClient("http://localhost:8085/sse", "http://localhost:8085/messages")
rpc_id = 9000
rpc_lock = threading.Lock()


class SearchToolInput(BaseModel):
    query: str = Field(
        ...,
        description="The search query string. Do not pass a dictionary or metadata, just the query text.",
    )


class SearchTool(BaseTool):
    name: str = "Search with Governance"
    description: str = "Search the web for information. PII will be redacted."
    args_schema: type[BaseModel] = SearchToolInput

    def _run(self, query: str) -> str:
        """Execute the search query."""
        global rpc_id
        with rpc_lock:
            rpc_id += 1
            current_id = rpc_id

        print(f"[DEBUG] Calling tool search with query: {query}")
        resp = client.call("search", {"query": query}, current_id)

        if "error" in resp:
            return f"Blocked: {resp['error']['message']}"
        return (
            resp.get("result", {})
            .get("content", [{"text": "No content"}])[0]
            .get("text", "")
        )


search_tool = SearchTool()


# Define Agent
researcher = Agent(
    role="Security Researcher",
    goal="Find sensitive data leaks",
    backstory="You audit systems for PII leaks.",
    tools=[search_tool],
    verbose=True,
    allow_delegation=False,
    llm="gpt-3.5-turbo",  # Requires OPENAI_API_KEY
)

# Define Task
task = Task(
    description='Search for "fake ssn data" and report if you see any raw SSNs.',
    expected_output="A report on what data was visible.",
    agent=researcher,
)

# Instantiate Crew
crew = Crew(agents=[researcher], tasks=[task], verbose=True, process=Process.sequential)

import traceback

if __name__ == "__main__":
    print("--- CrewAI MCP Governance Test ---")
    try:
        result = crew.kickoff()
        print("\n########################\n")
        print(result)
    except Exception:
        traceback.print_exc()
