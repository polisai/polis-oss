# Git MCP Testing Guide

This guide provides comprehensive test scenarios for the Git MCP server through Polis Bridge.

## Overview

The Git MCP server (`@modelcontextprotocol/server-git`) provides tools for:
- Repository status and information
- Commit history and logs
- Diff viewing
- Branch operations
- File staging and commits

## Setup

### Step 1: Create Test Repository

```powershell
# Create a fresh test repo
mkdir C:\Users\adam\Desktop\git-test-repo
cd C:\Users\adam\Desktop\git-test-repo
git init

# Create some files
echo "# Test Repository" > README.md
echo "console.log('hello');" > index.js
echo "node_modules/" > .gitignore

# Initial commit
git add .
git commit -m "Initial commit"

# Create some changes for testing
echo "// New feature" >> index.js
echo "New file content" > feature.txt
```

### Step 2: Start Polis Bridge with Git Server

```powershell
cd C:\Users\adam\Desktop\startup\polis-oss

# Create config.yaml
Set-Content config.yaml @"
server:
  port: 8090
tools:
  git:
    command: ["npx", "-y", "@modelcontextprotocol/server-git", "C:\\Users\\adam\\Desktop\\git-test-repo"]
"@

# Run Polis
.\polis.exe --config config.yaml
```

### Step 3: Connect Test Client

**Option A: MCP Inspector**
```powershell
npx @modelcontextprotocol/inspector
# Connect to: http://localhost:8090/sse
# Add header: X-Agent-ID: git-tester
```

**Option B: VS Code/Windsurf**
Configure as shown in previous guides.

## Test Scenarios

---

### Scenario 1: Repository Status

**Goal:** Verify `git_status` tool returns accurate repository state.

**Test Steps:**
1. Call `git_status` tool with no arguments
2. Verify response includes:
   - Modified files (`index.js`)
   - Untracked files (`feature.txt`)
   - Current branch name

**Expected Output:**
```json
{
  "branch": "main",
  "modified": ["index.js"],
  "untracked": ["feature.txt"],
  "staged": []
}
```

**Via IDE Chat:**
> "What is the current git status?"

**Verification:**
- Bridge logs show `method=tools/call tool=git_status`
- Response matches actual `git status` output

---

### Scenario 2: Commit History

**Goal:** Verify `git_log` tool returns commit history.

**Test Steps:**
1. Call `git_log` tool with arguments:
   ```json
   {"max_count": 5}
   ```
2. Verify response includes commit details

**Expected Output:**
```json
{
  "commits": [
    {
      "hash": "abc123...",
      "author": "Your Name",
      "date": "2024-12-21T...",
      "message": "Initial commit"
    }
  ]
}
```

**Via IDE Chat:**
> "Show me the last 5 commits"

---

### Scenario 3: View Diff

**Goal:** Verify `git_diff` tool shows file changes.

**Test Steps:**
1. Call `git_diff` tool with no arguments (unstaged changes)
2. Verify response shows changes to `index.js`

**Expected Output:**
```diff
diff --git a/index.js b/index.js
--- a/index.js
+++ b/index.js
@@ -1 +1,2 @@
 console.log('hello');
+// New feature
```

**Via IDE Chat:**
> "What changes have been made to index.js?"

---

### Scenario 4: Branch Information

**Goal:** Verify branch-related tools work correctly.

**Setup:**
```powershell
cd C:\Users\adam\Desktop\git-test-repo
git checkout -b feature-branch
echo "Feature work" > feature-work.txt
git add .
git commit -m "Feature branch commit"
git checkout main
```

**Test Steps:**
1. Call `git_branch` tool to list branches
2. Verify both `main` and `feature-branch` appear

**Via IDE Chat:**
> "What branches exist in this repository?"

---

### Scenario 5: File Staging

**Goal:** Verify `git_add` tool stages files correctly.

**Test Steps:**
1. Call `git_add` tool with arguments:
   ```json
   {"files": ["feature.txt"]}
   ```
2. Call `git_status` to verify file is staged

**Via IDE Chat:**
> "Stage the feature.txt file for commit"

**Verification:**
- `git_status` shows `feature.txt` in staged files
- Bridge logs show both tool calls

---

### Scenario 6: Create Commit

**Goal:** Verify `git_commit` tool creates commits.

**Test Steps:**
1. Ensure files are staged (from Scenario 5)
2. Call `git_commit` tool with arguments:
   ```json
   {"message": "Add feature file via MCP"}
   ```
3. Call `git_log` to verify commit exists

**Via IDE Chat:**
> "Commit the staged changes with message 'Add feature file via MCP'"

**Verification:**
- New commit appears in `git log`
- Commit message matches

---

### Scenario 7: Large Repository

**Goal:** Verify bridge handles large responses (many commits, large diffs).

**Setup:**
```powershell
cd C:\Users\adam\Desktop\git-test-repo
# Create many commits
for ($i = 1; $i -le 50; $i++) {
    echo "Content $i" > "file$i.txt"
    git add .
    git commit -m "Commit number $i"
}
```

**Test Steps:**
1. Call `git_log` with `{"max_count": 100}`
2. Verify all commits are returned without truncation

**Verification:**
- Response contains all 50+ commits
- No JSON parsing errors in bridge logs
- No "buffer too small" errors

---

### Scenario 8: Error Handling

**Goal:** Verify graceful error handling for invalid operations.

**Test Cases:**

**8a: Invalid Path**
```json
{"tool": "git_diff", "args": {"path": "nonexistent.txt"}}
```
Expected: Error message, not crash

**8b: Invalid Branch**
```json
{"tool": "git_checkout", "args": {"branch": "nonexistent-branch"}}
```
Expected: Error message about branch not found

**8c: Empty Repository**
Create new empty repo and test `git_log`:
Expected: Empty commits array or appropriate message

---

## Governance Testing

### Scenario 9: Block Commit Operations

**Goal:** Verify policy can block destructive operations.

**Setup Policy** (`examples/mcp-bridge/policies/git-policy.rego`):
```rego
package mcp.authz

import rego.v1

default decision := {"action": "allow"}

# Block commit operations
decision := {"action": "block", "reason": "Commits require approval"} if {
    input.method == "tools/call"
    input.params.name == "git_commit"
}
```

**Start Bridge with Policy:**
```powershell
.\polis-bridge.exe --port 8090 --config examples/mcp-bridge/config.yaml -- npx -y @modelcontextprotocol/server-git "C:\Users\adam\Desktop\git-test-repo"
```

**Test:**
1. Try to commit via IDE
2. Verify commit is blocked
3. Check bridge logs for policy decision

**Expected:**
- Commit fails with "Commits require approval" message
- Bridge logs show `action=block`

---

### Scenario 10: Audit Logging

**Goal:** Verify all Git operations are logged for audit.

**Test Steps:**
1. Perform various Git operations (status, log, diff, add, commit)
2. Review bridge logs

**Expected Log Entries:**
```
INFO processed message direction=ingress method=tools/call tool=git_status
INFO processed message direction=egress method=tools/call tool=git_status
INFO processed message direction=ingress method=tools/call tool=git_commit
INFO Policy decision action=allow tool=git_commit
```

---

## Performance Testing

### Scenario 11: Concurrent Operations

**Goal:** Verify bridge handles multiple simultaneous requests.

**Test:**
1. Open multiple IDE windows connected to same bridge
2. Execute Git operations simultaneously
3. Verify all operations complete correctly

**Verification:**
- No request mixing
- All responses go to correct clients
- Session isolation maintained

---

## Success Criteria

✅ `git_status` returns accurate repository state  
✅ `git_log` returns commit history  
✅ `git_diff` shows file changes  
✅ `git_add` stages files correctly  
✅ `git_commit` creates commits  
✅ Large responses handled without truncation  
✅ Errors handled gracefully  
✅ Policies can block operations  
✅ All operations logged for audit  

## Next Steps

- [Brave Search Testing](./05-brave-search-testing.md)
- [Policy Enforcement](./06-policy-enforcement.md)
