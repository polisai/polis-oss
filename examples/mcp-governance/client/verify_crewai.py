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
from langchain.tools import tool
import requests

# Configuration
POLIS_PROXY_URL = "http://localhost:8085/messages"


@tool("Search with Governance")
def search_tool(query: str):
    """Search the web for information. PII will be redacted."""
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": "search", "arguments": {"query": query}},
        "id": 1,
    }
    try:
        headers = {"X-Agent-ID": "demo-agent-001"}
        resp = requests.post(POLIS_PROXY_URL, json=payload, headers=headers).json()
        if "error" in resp:
            return f"Blocked: {resp['error']['message']}"
        return (
            resp.get("result", {})
            .get("content", [{"text": "No content"}])[0]
            .get("text", "")
        )
    except Exception as e:
        return f"Error: {str(e)}"


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

if __name__ == "__main__":
    print("--- CrewAI MCP Governance Test ---")
    result = crew.kickoff()
    print("\n########################\n")
    print(result)
