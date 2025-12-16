# MCP Safety Audit
## LLMs with the Model Context Protocol Allow Major Security Exploits

### Core Problem

The **Model Context Protocol (MCP)**, which standardizes API calls between LLMs, data sources, and tools for agentic workflows, introduces wide-ranging security risks. LLMs can be coerced to use MCP tools to compromise an AI developer's system.

### Impact of Compromise

The LLM agent's access to external tools allows for severe damage compared to a standalone LLM.

---

## Demonstrated Attacks

Three main types of attacks exploiting MCP-enabled tools (e.g., Filesystem, Slack, Everything):

1. **Malicious Code Execution (MCE)**: Attacker inserts malicious code/backdoors into system files (e.g., grants remote access upon opening a new terminal).
2. **Remote Access Control (RAC)**: Attacker gains immediate remote access to the victim’s system.
3. **Credential Theft (CT)**: Attacker extracts sensitive information (e.g., API keys, environment variables).

---

## LLM Susceptibility & Guardrail Reliability (Direct Prompt Attacks - DPA)

| LLM | MCE | RAC | CT | Guardrail Effectiveness |
| --- | --- | --- | --- | --- |
| **Claude 3.7** | Completed (even for direct plaintext) | Completed (sometimes without security note) | Susceptible | **Unreliable** - Easily circumvented by simple prompt changes (produces false sense of security). |
| **Llama-3.3-70B-Instruct** | Completed | Completed | Completed | **Very Low** - Only refuses requests with explicit harmful/unsafe keywords ("hack", "steal", "backdoor"). |

**Conclusion**: Guardrails are insufficient. Remediation must occur at the **MCP server design level** and the **LLM level**.

---

## New, High-Threat Attack (Multi-MCP Server)

### Retrieval-Agent Deception (RADE) Attack

- **Mechanism**: Attacker corrupts publicly available data with MCP-leveraging attack commands (themed around a specific topic, e.g., "MCP").
- **Execution**: Victim adds corrupted data to a vector database (via Chroma MCP server). When the victim queries the database for the theme, the malicious commands are retrieved and executed by the LLM agent.
- **Threat Level**: Significantly **higher** than DPA, as the attacker requires **no direct access** to the victim's system.
- **Demonstrated Results**: Successful RADE attacks for **RAC** and **CT** using Claude Desktop + Chroma/Everything/Filesystem MCP servers.

---

## Proposed Mitigation Tool

### McpSafetyScanner

**Agentic tool, open-source**

**Goal**: Proactively audit the safety of arbitrary MCP servers and provide remediations **prior to deployment**.

### McpSafetyScanner Workflow (3 Stages)

1. **Vulnerability Detection (Hacker Agent)**: Automatically determines adversarial samples based on the MCP server's tools, resources, and prompts.
2. **Vulnerability Search & Remediation (Security Auditor Agent)**: Searches knowledge bases (Web, ArXiv, Hacker News) for related vulnerabilities and determines remediation steps/best practices.
3. **Report Generation (Supervisor Agent)**: Consolidates all findings into a detailed security report.

### McpSafetyScanner Findings Example

| Attack | Description (Exploit) | Remediation |
| --- | --- | --- |
| **MCE** | Use `edit file` / `write file` to inject malicious code. | Implement strict access controls; **Restrict directories** where functions can operate. |
| **RAC** | Add attacker's public SSH keys to `~/.ssh/authorized_keys`. | Use strict permissions on `authorized_keys`. |
| **CT** | `printEnv` to capture environment variables (API keys). | **Avoid storing sensitive info in environment variables**; Enforce least privilege. |
| **CT** | Exploit Slack API to exfiltrate data/unauthorized posts. | Audit/restrict API access; Regularly review channel permissions. |

**Result**: Tool accurately identified vulnerabilities and provided actionable remediations for both developers (server guardrails) and end-users (system defenses).