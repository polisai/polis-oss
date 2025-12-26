from mcp.server.fastmcp import FastMCP

# Initialize FastMCP Server
mcp = FastMCP("Governance Demo")


# --- Filesystem Tools ---
@mcp.tool()
def filesystem_read_file(path: str) -> str:
    """Read a file from the filesystem."""
    return f"Contents of {path}: [MOCK CONTENT]"


@mcp.tool()
def filesystem_write_file(path: str, content: str) -> str:
    """Write content to a file."""
    return f"Successfully wrote to {path}"


@mcp.tool()
def filesystem_list_directory(path: str) -> str:
    """List directory contents."""
    return "file1.txt\nfile2.txt\nsecret.key"


# --- Git Tools ---
@mcp.tool()
def git_status(repo_path: str) -> str:
    """Check git status."""
    return "On branch main\nYour branch is up to date.\nmodified:   main.go"


@mcp.tool()
def git_commit(repo_path: str, message: str) -> str:
    """Commit changes."""
    return f"Committed with message: {message}"


@mcp.tool()
def git_push(repo_path: str) -> str:
    """Push changes to remote."""
    return "Push successful"


# --- Search Tools (DLP Test) ---
@mcp.tool()
def search(query: str) -> str:
    """Search the web (returns mock PII)."""
    return (
        f"Results for {query}:\n"
        "1. Contact John Doe at john.doe@example.com for details.\n"
        "2. API Key found: sk-1234567890abcdef1234567890abcdef.\n"
        "3. User Data: Name=Alice, Email=alice@test.com"
    )


if __name__ == "__main__":
    # Run the server on port 8000 using SSE transport (Default for FastMCP)
    mcp.run(transport="sse")
