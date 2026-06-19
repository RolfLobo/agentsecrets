# Agent Operation & Reporting Rules

These rules govern how the AI assistant (Antigravity) must conduct research, make decisions, and report outcomes to the user (the Orchestrator).

---

## 1. Research phase (Findings Report)
Whenever the user asks to research a solution, investigate a bug, or design a feature, the agent must produce a **Research Findings Report** (usually as an artifact or within the response) detailing:
1. **Findings Summary**: The exact root cause, discovery, or research outcome.
2. **Obvious Ways to Solve**: The direct/standard ways to address the problem.
3. **Already Existing Solutions & Mechanics**: How other libraries, systems, or platforms solve this, and their exact inner workings.
4. **Adaptation to Our Problem**: How these existing solutions can be mapped to our codebase/architecture.
5. **Enhancements & Alternative Designs**: Obvious better solutions or optimizations that are not typically explored by standard approaches.
6. **Comparison Matrix**:
   - Limitations
   - Performance impact
   - Simplicity and code maintainability
   - Security implications

---

## 2. Post-Implementation Phase (Session Report)
At the end of every implementation session, task completion, or milestone, the agent must output a **Detailed Session Report** (as part of the Walkthrough/Verification artifact or directly to the user) documenting:
1. **Summary of Work Done**: Precise details of all modified files, added commands, and code logic.
2. **Key Decisions Made**: Architectural choices, why certain functions/APIs were structured the way they were.
3. **Alternatives Explored & Considered**: Other approaches that were analyzed, why they were rejected (e.g., CGO constraints, OS compatibility, performance overhead).
4. **Verification & Testing Results**: Output/logs from unit tests, manual tests, and cross-compilation checks.
5. **Open Tasks/Next Steps**: What is remaining or recommended for future sessions.

---

## 3. Code Modification Guardrails (Impact Evaluation)

Before proposing or making **any** code changes, the agent must systematically evaluate their effect on existing functionality:

1. **System Integrity**: Would this change break any existing system behaviour or test suites?
2. **Feature Preservation**: Would this change remove or bypass any necessary functionality (e.g., security middlewares, verification steps, core validations, auth services)? **Do not replace — extend.**
3. **Broad Implications**: What are the wider effects across OS platforms (Windows, WSL/Linux) and execution contexts? Do not make speculative deletions.
4. **Additive-first**: Always prefer adding alongside existing code rather than replacing it. If a middleware needs to be applied to a new command, wire it in **addition to** the current middleware stack — never swap one out for another.

---

## 4. Coding Standards (CLAUDE.md equivalent)

These rules govern how the agent writes and modifies code. They apply in every session.

### 4.1 Think Before Coding

- State assumptions explicitly. If uncertain, ask — do not silently pick an interpretation.
- If multiple approaches exist, present them and explain trade-offs before choosing.
- If something is unclear, stop, name the confusion, and ask.

### 4.2 Simplicity First

- Minimum code that solves the problem. Nothing speculative or "future-proof".
- No extra abstractions for single-use code.
- No "configurability" added unless asked.
- No premature optimisations.

### 4.3 Preserve Existing Behaviour

- Read the code before changing it. Understand what every changed line does.
- Do not remove comments, error handlers, middlewares, or guard clauses unless explicitly asked to.
- When adding a new code path, verify the old code path still works unchanged.

### 4.4 No Invisible Side Effects

- Do not rename, reorder, or restructure things that weren't asked about.
- Do not change function signatures unless that is the task.
- Do not move code between files as a "clean-up" unless explicitly asked.

### 4.5 Correctness Over Cleverness

- Prefer explicit over implicit.
- Prefer obvious over clever.
- If an approach is non-obvious, add a comment explaining why.

### 4.6 Error Handling

- Every error must be handled or explicitly documented as intentionally ignored.
- Never swallow errors silently.
- Propagate with enough context to diagnose from logs alone.

### 4.7 Security Rules (specific to this project)

- Never log credential values — not to stdout, stderr, files, or audit log.
- Never pass credential values as function arguments where avoidable — pass key names and resolve at the last moment via keyring.
- Never write credential values to any file — keychain only (StorageMode 1).
- The audit log struct must never gain a `value` field.
- All cloud sync operations must use the existing `pkg/crypto` package — no plaintext uploads.
- keychain-auth middleware must never be removed from commands that require keychain access; it can only be extended.
