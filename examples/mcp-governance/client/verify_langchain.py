from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
import requests
import json
import threading
import time
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

try:
    from langchain.agents import AgentExecutor, create_tool_calling_agent
except ImportError:
    from langchain.agents.agent import AgentExecutor
    from langchain.agents import create_tool_calling_agent
from langchain_core.prompts import ChatPromptTemplate

# Configuration
from langchain_core.tools import tool


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
                "clientInfo": {"name": "langchain-client", "version": "1.0"},
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


# Global client
client = SSEClient("http://localhost:8085/sse", "http://localhost:8085/messages")

rpc_id = 1000
rpc_lock = threading.Lock()


def rpc_call(method, params):
    global rpc_id
    with rpc_lock:
        rpc_id += 1
        current_id = rpc_id

    response = client.call(method, params, current_id)
    if "error" in response:
        return f"Error: {response['error']['message']}"
    return (
        response.get("result", {})
        .get("content", [{"text": "Success"}])[0]
        .get("text", "Success")
    )


@tool
def filesystem_read_file(path: str) -> str:
    """Read a file from the filesystem."""
    return rpc_call("filesystem_read_file", {"path": path})


@tool
def filesystem_write_file(path: str, content: str) -> str:
    """Write content to a file."""
    return rpc_call("filesystem_write_file", {"path": path, "content": content})


# Setup Agent
llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)
tools = [filesystem_read_file, filesystem_write_file]
prompt = ChatPromptTemplate.from_messages(
    [
        ("system", "You are a secure assistant. You use tools via a proxy."),
        ("human", "{input}"),
        ("placeholder", "{agent_scratchpad}"),
    ]
)

agent = create_tool_calling_agent(llm, tools, prompt)
agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

if __name__ == "__main__":
    print("--- LangChain MCP Governance Test ---")
    print("User: Read /tmp/sandbox/test.txt")
    try:
        agent_executor.invoke({"input": "Read the file at /tmp/sandbox/test.txt"})
    except Exception as e:
        print(f"Error during read: {e}")

    print("\nUser: Write to /etc/passwd")
    try:
        agent_executor.invoke({"input": "Write 'hacked' to /etc/passwd"})
    except Exception as e:
        print(f"Error during write: {e}")
