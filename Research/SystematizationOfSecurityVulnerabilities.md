# CUA-SEC: Systematization of Security Vulnerabilities in Computer Use Agents

[cite_start]This paper, published in 2025 by researchers at Microsoft, conducts a systematic threat analysis of **Computer Use Agents (CUAs)**—autonomous systems that interact with software interfaces like browsers or virtual machines[cite: 1, 3, 5, 6]. [cite_start]It identifies seven unique risk classes and demonstrates how architectural flaws in perception and delegation enable high-impact exploits[cite: 10, 11, 24].

---

## ## Core Framework: CUA Interaction Model
[cite_start]CUAs operate through a perception-reasoning-action feedback loop that differs from traditional chat-based LLMs[cite: 46, 48]. The process involves:

* [cite_start]**Perception:** Capturing screenshots, DOM state, or environment metadata[cite: 49].
* [cite_start]**Context Integration:** Fusing observations with task instructions, memory, and history[cite: 50].
* [cite_start]**Reasoning:** Generating **Chain-of-Thought (CoT)** steps to decompose tasks or adapt to UI changes[cite: 51].
* [cite_start]**Action & Feedback:** Emitting system-level commands (clicks, typing) and observing the results[cite: 52, 53].

---

## ## The Seven Classes of CUA Risk
[cite_start]The researchers categorize risks emerging from the agent's interaction model and delegated authority[cite: 21, 137]:

| Risk Category | Description |
| :--- | :--- |
| **UI Deception (Risk 1)** | [cite_start]Exploiting perceptual mismatches and TOCTOU (time-of-check to time-of-use) vulnerabilities via visual overlays[cite: 25, 26, 149]. |
| **RCE via Composition (Risk 2)** | [cite_start]Synthesizing malicious behavior (e.g., shell access) from sequences of seemingly benign UI-level operations[cite: 27, 167, 168]. |
| **CoT Exposure (Risk 3)** | [cite_start]Leakage of internal reasoning artifacts that reveal sensitive plans, user intent, or hidden assumptions[cite: 28, 29, 192]. |
| **HiTL Bypass (Risk 4)** | [cite_start]Using adversarial prompting or framing to induce agents to skip or suppress human-in-the-loop confirmation steps[cite: 30, 31, 225]. |
| **Indirect Prompt Injection (Risk 5)** | [cite_start]Adversarial instructions embedded in web content, PDFs, or UI elements that a CUA perceives and acts on[cite: 32, 246, 248]. |
| **Identity Ambiguity (Risk 6)** | [cite_start]Conflating agent and user actions, leading to over-delegation and lack of auditability for high-privilege tasks[cite: 33, 34, 271, 274]. |
| **Content Harms (Risk 7)** | [cite_start]Autonomous generation or amplification of misinformation and unauthorized privacy profiling from ambient data[cite: 35, 302, 312]. |

---

## ## Key Research Insights
[cite_start]Evaluations across various CUA deployments, including OpenAI's Operator, reveal that these vulnerabilities are systemic rather than model-specific[cite: 37, 40, 480].

* [cite_start]**Visual Prompt Injection:** Unlike text attacks, these operate "through the pixels" (e.g., malicious tooltips), bypassing standard text-based input sanitization[cite: 64, 66].
* [cite_start]**Chain-of-Thought as an Attack Surface:** CoT traces act like memory dumps; if an adversary can predict or observe them, they can perform front-running attacks[cite: 74, 200, 201].
* [cite_start]**Probabilistic Safeguards:** Existing HiTL triggers are often model-defined heuristics rather than hard-coded constraints, making them fragile under adversarial pressure[cite: 30, 218, 220].

---

## ## Attack Scenarios Modeled
* **Clickjacking via Visual Overlay:** A CUA is prompted to "enter a blog," but a visually benign button is overlaid on a hidden form. [cite_start]The agent clicks based on static cues, triggering a high-privilege payment action without semantic verification[cite: 337, 342, 343].
* **End-to-End RCE:** An indirect prompt injection in a forum post guides the agent to install a PWA. [cite_start]The agent then uses permissive browser APIs to write malicious configuration files and MIME handlers, resulting in shell execution[cite: 370, 375, 378, 379].
* **CoT Leakage via Interface Framing:** An environment is seeded with a file labeled "admin_only.txt." [cite_start]The agent, believing this is a secure developer log, externalizes its internal plans and reasoning steps directly to the user-accessible file[cite: 403, 405, 411, 421].

---

## ## Conclusion
[cite_start]The paper argues that CUAs must be treated as autonomous systems embedded in adversarial environments[cite: 41]. [cite_start]Future secure design requires moving toward agent-native primitives, including cryptographically tied delegation, ephemeral execution sessions, and strict separation between internal reasoning and external output channels[cite: 42, 500, 501, 566].