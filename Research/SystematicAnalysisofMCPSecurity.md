# Systematic Analysis of MCP Security: Comprehensive Research Notes

[cite_start]This paper (August 2025) analyzes the security vulnerabilities of the **Model Context Protocol (MCP)**, a standard for connecting AI agents to external tools[cite: 5, 20]. [cite_start]It introduces **MCPLIB**, a toolkit containing 31 distinct attack types[cite: 12].

---

## 1. Core Architecture & Primary Vulnerability
[cite_start]MCP uses a client-server model consisting of a **Host** (the AI app), a **Client**, and a **Server** (providing Tools, Resources, and Prompts)[cite: 21, 22].
* [cite_start]**The Main Threat:** **Tool Poisoning Attacks (TPA)**[cite: 10]. [cite_start]Attackers embed malicious instructions in tool descriptions or code comments[cite: 28].
* [cite_start]**Root Cause:** **LLM Sycophancy.** AI models often treat tool descriptions as user instructions, leading to "blind obedience" where the model follows the description over actual safe functionality[cite: 33, 84].



---

## 2. The Four-Dimensional Attack Taxonomy (31 Types)
[cite_start]The paper categorizes threats based on the "attack entrance"[cite: 131, 143]:

| Category | Definition | Key Examples |
| :--- | :--- | :--- |
| **Direct Tool Injection** | [cite_start]Payloads injected directly into tool descriptions or `_doc_` attributes[cite: 132]. | [cite_start]**Rug Pull:** Legitimate tools updated post-install with malicious logic[cite: 165, 166]. [cite_start]<br> **RCE:** Executable code hidden in comments[cite: 175]. |
| **Indirect Tool Injection** | [cite_start]Exploits third-party data or tool outputs to trigger the LLM[cite: 134, 201]. | [cite_start]**Webpage Poisoning:** Malicious commands hidden in HTML comments[cite: 202, 219]. [cite_start]<br> **Tool Return Attack:** A tool returns a string that tricks the LLM into calling a different malicious tool[cite: 204, 205]. |
| **Malicious User Attack** | [cite_start]Attacks launched by the user to compromise the server or other users[cite: 135, 207]. | [cite_start]**Privilege Escalation:** Exploiting API access to steal tokens or modify `mcp.json`[cite: 210, 211]. [cite_start]<br> **Installer Spoofing:** Embedding malware in auto-installers like MCP-Get[cite: 229]. |
| **LLM Inherent Attack** | [cite_start]Traditional LLM flaws amplified by the ability to call tools[cite: 136, 236]. | [cite_start]**Prompt Leakage:** Using tools to infer the model's system prompts[cite: 242]. [cite_start]<br> **Goal Hijacking:** Replacing "recommended products" with malicious links via tool results[cite: 253, 254]. |

---

## 3. Critical Research Insights
Through empirical testing, four systemic weaknesses were identified:

* [cite_start]**Insight 1: Operation Sensitivity.** MCP agents are highly sensitive to file operations[cite: 80]. [cite_start]**Add, Retrieve, and Read** operations are executed without user confirmation, whereas **Delete** and **Code Execution** require approval[cite: 302]. [cite_start]This makes file-based exfiltration highly stealthy[cite: 311].
* [cite_start]**Insight 2: Blind Obedience.** Agents prioritize textual descriptions over actual code[cite: 84]. [cite_start]Attackers can use "Best Practice" or "Recommended" tags in descriptions to ensure their malicious tool is chosen over a benign one[cite: 184, 416].
* [cite_start]**Insight 3: Shared Context Infection.** All MCP info is stored in a shared context[cite: 88]. [cite_start]An **Infectious Attack** occurs when an agent generates a new tool (e.g., subtraction) by mimicking the structure of an existing malicious tool (e.g., addition), thereby inheriting its vulnerabilities[cite: 198, 438].
* [cite_start]**Insight 4: Instruction/Data Confusion.** LLMs cannot distinguish between external data and executable commands[cite: 92]. [cite_start]Even illogical data returned by a tool might be blindly executed as a command due to sycophancy[cite: 95, 476].

---

## 4. Quantitative Attack Efficacy (Top Threats)
[cite_start]The efficacy is measured by Success Rate (S), Risk Level (L), Impact (I), and Difficulty (D)[cite: 263].

* [cite_start]**Most Dangerous (Score 10.00):** **SQL Injection & API Theft.** Has a 100% success rate in stealing local API tokens or dropping database tables[cite: 273].
* [cite_start]**Most Reliable (Score 8.38):** **File-Based Injection (Addition/Modification)** and **Malicious Tool Coverage.** These allow persistent system control with nearly zero implementation difficulty[cite: 273].
* [cite_start]**Stealthiest:** **Shadowing Attack (Score 7.79).** Influences the behavior of benign tools even if the malicious tool is never explicitly called[cite: 180, 273].

---

## 5. Defense Mechanisms
[cite_start]Current defenses focus on two paths[cite: 487]:
1.  [cite_start]**Server Scanning:** Tools like **MCP-Scan** detect TPA features[cite: 488].
2.  [cite_start]**Interaction Monitoring:** Middlewares like **MCP Guardian** or **Invariant Guardrails** act as gateways to monitor logs and rate limits between the LLM and the Server[cite: 488, 489].