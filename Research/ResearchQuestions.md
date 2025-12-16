# Research Questions

- **Defeating Tool Fusing to Re-open the Attack Window**
    - **Question:** What is the maximal achievable temporal window (time gap) that can be deliberately introduced to defeat the **Tool Fusing** defense, and can a novel race condition exploit reliably abuse this sub-millisecond gap to execute a malicious tool call?
    - **Branching Whitepaper:** *Mind the Gap: Time-of-Check to Time-of-Use Vulnerabilities in LLM-Enabled Agents*
- **Bypassing Multi-Layered Defenses with Semantic Injection**
    - **Question:** What advanced, level-3 **semantic attack patterns** (semantic injections) are required to successfully bypass a complete multi-layered defense stack, evading both **Embedding-Based Anomaly Detection** and **Multi-Stage Response Verification**?
    - **Branching Whitepaper:** *Securing AI Agents Against Prompt Injection Attacks*
- **Evading the Safety Auditor via Concealed Protocol Commands (Self-Destructing Attack)**
    - **Question:** Can a malicious MCP Server be designed to **self-destruct upon auditing**? What is the most effective payload delivery and subsequent termination strategy that prevents the **McpSafetyScanner** audit tool from detecting or tracing the exploit source during an active scan?
    - **Branching Whitepaper:** *MCP Safety Audit: LLMs with the Model Context Protocol Allow Major Security Exploits*
- **Defeating Malfunction Detection via Malfunction-Induced Noise**
    - **Question:** What is the optimal ratio and structure of an **Infinite Loop Prompt Injection** that successfully triggers a non-harmful system malfunction while simultaneously forcing the exfiltration of sensitive data, rendering **LLM Self-Examination Defense** ineffective due to a high signal-to-noise ratio?
    - **Branching Whitepaper:** *Breaking Agents: Compromising Autonomous LLM Agents Through Malfunction Amplification*
- **Transferable Prompts against Custom Guardrails**
    - **Question:** By leveraging the **AGENTVIGIL** fuzzing principles, how can a researcher create a **highly transferable adversarial prompt** that maintains a significantly high attack success rate against **unseen target models** protected by custom, prompt-engineering-based guardrails (like `delimit` or `repeat`)?
    - **Branching Whitepaper:** *AGENTVIGIL: Generic Black-Box Red-teaming for Indirect Prompt Injection against LLM Agents*

- **Question**: How can the **URI Template** and resource-request structure of the **Model Context Protocol (MCP)** be abused to "launder" a high-privilege system command within a semantically benign resource request, effectively bypassing intent-based safety auditors by creating a discrepancy between the LLM’s natural language reasoning and the protocol's execution-layer parameters?
- **Branching Whitepaper:** *AGENTVIGIL: Generic Black-Box Red-teaming for Indirect Prompt Injection against LLM Agents*