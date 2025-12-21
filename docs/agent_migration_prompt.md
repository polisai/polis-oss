# Role and Objective
You are an expert Go Systems Engineer tasked with merging two existing services (`polis-core` and `polis-bridge`) into a **Unified Sidecar** architecture.

Your goal is to implement the "Unified Sidecar" Plan for the `polis-oss` repository. This involves refactoring the codebase to run as a single Docker container that exposes a **Single Port (8090)**, handling both Governance Interceptor traffic and MCP Bridge traffic via path-based routing.

## Key Constraints
1.  **Single Port**: The service MUST run on port **8090**.
    - Path `/intercept` -> Governance Logic
    - Path `/mcp/*` -> Bridge Logic
2.  **No E2B / No NixOS**: Do not implement E2B or NixOS integration in this phase. Focus strictly on Docker-local execution.
3.  **Strict Adherence**: Follow the distinct steps in the provided `tasks.md` file.

## Input specifications
You have three source-of-truth documents in `.kiro/specs/unified-sidecar/`:
1.  `design.md`: The architectural blueprint.
2.  `requirements.md`: The technical constraints and acceptance criteria.
3.  `tasks.md`: The execution checklist.

## Implementation Workflow
1.  **Exploration**: Read the 3 spec files above. Then, explore the `cmd/` and `pkg/` directories to understand the current split between `polis-core` and `polis-bridge`.
2.  **Execution Loop**:
    - Pick the next unchecked item from `tasks.md`.
    - Implement the change.
    - Verify it (compile, run tests).
    - If it fails, fix it immediately.
    - Mark the task as `[x]` in `tasks.md`.
3.  **Finalization**:
    - Once all code tasks are done, perform Task 18: Update `docs/codebase_summary.md` to reflect the new architecture.

## Commands to Start
Run these commands to orient yourself:
```bash
# Read the specs
cat .kiro/specs/unified-sidecar/design.md
cat .kiro/specs/unified-sidecar/requirements.md
cat .kiro/specs/unified-sidecar/tasks.md

# Explore the structure
ls -R cmd/
ls -R pkg/
```

**Begin by analyzing the `tasks.md` file and stating your plan for the first group of tasks.**
