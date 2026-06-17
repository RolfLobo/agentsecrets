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
