# Mind the Gap: Time of Check to Time of Use Vulnerabilities in LLM-Enabled Agents

## At a Glance
- TOCTOU in LLM agents: attackers exploit the gap between validate and execute.
- 66-task benchmark; 56 tasks show TOCTOU exposure.
- Defenses span pre-plan, planning-time, and execution-time.

## Problem
- LLM agents plan and call tools; state can change between a check and a later use.
- An attacker swaps or mutates the target during the gap, so the agent acts on the wrong (malicious) object.

## The Attack Flow
1. Check: read/validate external state (e.g., "Does file X exist?").
2. Gap: attacker changes state (swap X with malicious Y).
3. Use: agent proceeds, trusting stale state, and hits Y.

## Defenses Across the Pipeline
| Stage | Mechanism | What it does | Goal |
| --- | --- | --- | --- |
| Pre-planning | Prompt Rewriting | Nudge safer, single-step plans | Reduce multi-step race windows |
| Planning | State Integrity Monitoring (SIM) | Flag risky "check then use" sequences before execution | Catch TOCTOU patterns early |
| Execution | Tool Fuser | Combine check+use into one atomic call | Remove the gap entirely |

## Results
- Tool Fuser cuts the attack window by ~95%: from ~1.7 s to ~0.07 s.
- Vulnerable executed plans drop from ~12% to ~8% with prompt rewriting plus other defenses.

## Significance
- First systematic look at TOCTOU for LLM agents, linking AI planning with classic race-condition risk.
- Provides a benchmark and layered mitigations to harden agent tool use.