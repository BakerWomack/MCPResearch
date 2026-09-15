# Atomicity for Agents: Exposing, Exploiting, and Mitigating TOCTOU Vulnerabilities in Browser-Use Agents

arXiv:2603.00476v1 | Submitted 28 February 2026
Linxi Jiang, Zhijie Liu, Haotian Luo, Zhiqiang Lin
https://arxiv.org/abs/2603.00476

## At a Glance
- TOCTOU in browser-use agents: the page changes between the observation the agent plans against and the action it finally executes.
- 10 open-source agents evaluated on DynWeb: 9 synthesized cases + 5 real-world sites = 14 cases.
- Trigger ratio 100% without mitigation; 0% with pre-execution validation.
- Residual window ~0.13 s; overhead below 0.05 s per loop.

## Formal Definition
- t_c = check time, when the agent captures its observation of the page.
- t_u = use time, when the derived action is applied to the page.
- The vulnerable interval is [t_c, t_u).
- Violation condition: s_c != s_u AND Bind(a, s_c) != Bind(a, s_u).
  The page state differs between check and use, AND the action's target binding
  resolves differently under the two states.

## Why the Window Exists
The authors attribute the interval to "the latency between observation and action
selection." Their wording: "After capturing an observation, the agent must run LLM
inference to interpret the page and decide the next action. This computation is not
instantaneous ... so the delay can span seconds and sometimes longer."

Planning is reported at 5-15 s per LLM reasoning step, with total planning delays
"ranging from several seconds to tens of seconds."

## Vulnerability Types
- Type I: UI changes (element moves, is replaced, or is overlaid).
- Type II: data changes (the underlying values the action depends on mutate).
- Type III: expiring state (the observed state is valid only briefly).

## Agents Evaluated (10)
Agent-E, computer-use-demo, openai-cua-sample-app, Cua, UI-TARS-desktop,
Bytebot, Agent-S, WebVoyager, Browser-Use, Midscene.

## Mitigation: Pre-Execution Validation
Monitors DOM and layout changes during the planning phase and re-validates page state
immediately before the action is executed; aborts if the observation the plan was
built on no longer holds.

## Measurement Methodology (important caveat)
Each of the 14 cases is executed 10 times. "If a TOCTOU vulnerability is triggered in
any run, the case is counted as a trigger." Trigger ratio is therefore the fraction of
CASES that triggered at least once, not a per-trial success rate over 140 attempts.
The 100% -> 0% result is a coarse binary over 14 cases. No delay is swept, and no
per-attempt success rate as a function of mutation timing is reported anywhere in the
paper.

## Results (verbatim)
- "Without mitigation, the trigger ratio is 100% for all three types of manipulation."
- "With pre-execution validation enabled, the trigger ratio drops to 0% across all
  tested cases, indicating that the mechanism blocks all evaluated manipulations."
- "In our implementation, the residual vulnerability window is measured to be about 0.13 s."
- "Assuming agent planning time of around 10 s, this represents a reduction by a factor
  of roughly 10/0.13 = 77."
- "Across all sites, the per-loop overhead remains small and stable. In particular, the
  additional latency is below 0.05 s."

Note: the 77x figure rests on an ASSUMED 10 s planning time, not a measured baseline.
Their measured planning range is "5-15 seconds typically required for a single LLM
reasoning step" and total delays "ranging from several seconds to tens of seconds."
Cite the 77x as "roughly 77-fold against an assumed 10-second planning baseline."

They also concede their own mitigation is not atomic: it executes "validation and
interaction as back to back commands rather than a single atomic operation, which
leaves a small residual window between the final check and the action." The 0.13 s is
that residual, by their own account an engineering artifact rather than a floor.

## Relevance to This Thesis
Closest antecedent to this work. Two structural properties limit how far it generalizes:

1. Self-race, not inherited trust. The check and the use are performed by the same
   component in one process. Re-validation is local: the agent compares what it sees
   now against what it saw a moment ago. In the MCP architecture studied here the check
   is performed by a separate scanning service and the verdict is persisted to a
   database; the consuming agent never held the artifact at check time and cannot
   perform the comparison the paper's mitigation depends on.

2. Ephemeral vs. persisted state. Their observation is in-memory, never shared, never
   consulted by another component. The safe flag here is durable shared state, so the
   interval is bounded by transport, queuing, and state propagation across service
   boundaries rather than by one agent's reasoning time alone.

Also note: their mitigation shortens the interval AND re-binds the verdict to current
content at the same time, so the contribution of each mechanism cannot be separated from
their reported numbers. Same limitation applies to Mind the Gap's Tool Fuser, which
achieves atomicity by merging check and use into a single call. Neither evaluates an
architecture that shortens the interval while leaving the verdict bound to an
identifier rather than to content - which is what the Tight configuration isolates.

## Cross-Reference: Mind the Gap
- Tool Fuser: window ~1.7 s -> ~0.07 s (~95% reduction).
- Atomicity: window ~10 s (assumed) -> ~0.13 s (~77x), trigger ratio 100% -> 0%.
Both operate inside a single agent process. Atomicity cites Mind the Gap as [21]
(Lilienthal & Hong) but does not build on its taxonomy.

## Coverage Check
The paper never mentions the Model Context Protocol, multi-service deployments,
persisted validation verdicts, or any check performed by a component other than the
agent itself. The only occurrence of "MCP" in the bibliography is an unrelated
reference to WebMCP. The decoupled case is untouched.
