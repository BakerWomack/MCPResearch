# ATAG: AI-Agent Application Threat Assessment with Attack Graphs

[cite_start]This paper, published in June 2025 by researchers at Ben-Gurion University, introduces **ATAG**, a framework for systematically analyzing security risks in **Multi-Agent AI Systems (MAAS)**[cite: 567, 568, 575]. [cite_start]It addresses the complexity of inter-agent interactions by extending traditional attack graphs to model specific LLM vulnerabilities[cite: 573, 576].

---

## ## Core Framework: ATAG
[cite_start]ATAG extends the **MulVAL** logic-based attack graph generator with custom rules and facts tailored for AI agents[cite: 576, 580]. It consists of four primary modules:

* [cite_start]**Agent Modeler:** Builds the application topology, identifying agent roles (input/output), tool integrations, and communication channels[cite: 687, 710, 712].
* [cite_start]**Vulnerability Mapper:** Maps agents to known risks using the newly created **LLM Vulnerability Database (LVD)**[cite: 688, 732, 739].
* [cite_start]**Attack Graph Generator:** Uses Datalog-based interaction rules to simulate multi-step attack scenarios[cite: 689, 782].
* [cite_start]**Attack Graph Analyzer:** Calculates risk scores for agents and identifies the most critical attack paths based on attack success rates (ASR)[cite: 690, 798, 805].


---

## ## The LLM Vulnerability Database (LVD)
[cite_start]Because a standardized database like CVE did not exist for LLMs, the researchers initiated the **LVD**[cite: 577, 739]. It maps:
* [cite_start]**OWASP Top 10 for LLM** vulnerability categories[cite: 745].
* [cite_start]**MITRE ATLAS** tactics and techniques[cite: 746].
* [cite_start]**Specific LLM versions** and their associated attack success rates (ASR)[cite: 744, 750].

---

## ## Key Research Insights
[cite_start]The framework was validated through two real-world case studies: a **Trip Planner** and an **Automated Email Responder**[cite: 604, 857].

| Insight | Description |
| :--- | :--- |
| **Vulnerability Chaining** | [cite_start]Minor issues, like a single missing input sanitization guardrail, can be chained to achieve total system compromise (e.g., a misinformation attack)[cite: 1054, 1055]. |
| **Architectural Risks** | [cite_start]Sequential architectures allow linear attack propagation, while hierarchical ones create multiple alternative attack paths for an adversary[cite: 1056]. |
| **Communication Weaknesses** | [cite_start]Inter-agent communication channels are critical failure points where malicious payloads propagate seamlessly if not validated[cite: 1058]. |
| **External Tool Access** | [cite_start]Agents with tools (like email search) significantly broaden the attack surface, as legitimate permissions can be subverted for data exfiltration[cite: 1059]. |

---

## ## Attack Scenarios Modeled
* [cite_start]**Trip Planner:** An attacker injects a malicious blog link into a travel request[cite: 877]. [cite_start]The City Selection Agent fails to sanitize it, causing the Research Agent to crawl a site with hidden jailbreak directives that ultimately misdirect the user to dangerous locations[cite: 888, 890, 894].
* [cite_start]**Email Responder:** An indirect prompt injection (IPI) attack uses a coercive "termination threat" in an email to stress the Categorizer Agent[cite: 917, 972, 975]. [cite_start]This induces the agent to exfiltrate its own system prompt and sensitive user data via the Drafter Agent[cite: 975, 976, 984].


---

## ## Conclusion
[cite_start]ATAG provides a **semi-automated methodology** for proactive security analysis[cite: 1075, 1079]. [cite_start]It enables organizations to visualize complex attack paths and prioritize defenses in environments where agents operate with high autonomy[cite: 580, 581, 1076].