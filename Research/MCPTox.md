# Executive Summary

**MCPTox** is the first systematic benchmark designed to evaluate Large Language Model (LLM) agent robustness against **Tool Poisoning Attacks (TPA)** in realistic MCP settings. The study reveals that prominent LLM agents are highly susceptible to these attacks, which exploit their instruction-following capabilities to perform unauthorized actions using legitimate tools.

---

# Core Concepts & Definitions

- 
    
    **Model Context Protocol (MCP):** A standardized interface that allows LLM agents to interact with external tools and resources.
    
- 
    
    **Tool Poisoning Attack (TPA):** A vulnerability where malicious instructions are embedded within a tool's **metadata** (natural language description) rather than its execution output.
    
- 
    
    **Mechanism:** Malicious instructions are injected into the LLM's context during the "Initial & Registration" phase. When a user later issues a benign query, the agent follows the "poisoned" rule hidden in the metadata.
    

---

# The MCPTox Benchmark

- 
    
    **Scale:** Built upon **45 live, real-world MCP servers** and **353 authentic tools**.
    
- 
    
    **Test Cases:** 1,312 malicious test cases generated via few-shot learning, covering 10-11 risk categories (e.g., Privacy Leakage, Message Hijacking).
    
- **Attack Paradigms:**
    - 
        
        **P1: Explicit Trigger (Function Hijacking):** A tool mimics a common function (like `get_time`) but instructs the agent to call a high-privilege tool (like `read_file`) instead.
        
    - 
        
        **P2: Implicit Trigger (Function Hijacking):** A background process (like `security_check`) sets a rule that manipulates the agent when it performs unrelated legitimate actions.
        
    - 
        
        **P3: Implicit Trigger (Parameter Tampering):** The most effective paradigm; it modifies the parameters of a legitimate tool's execution (e.g., changing an email recipient).
        

---

# Key Findings & Evaluation

The researchers evaluated **20 prominent LLM agents** (including GPT-4o, Claude 3.7, DeepSeek-R1, and o1-mini):

- **Widespread Vulnerability:** The average Attack Success Rate (ASR) across all model settings was **36.5%**.
- **Ligh-Performing Models are Most Risk:** More "capable" models often show higher vulnerability—**o1-mini** reached a **72.8% ASR** and **Phi-4** reached **70.2%**.
- **Inverse Scaling:** Enabling "reasoning mode" in models like Qwen3 significantly increased their susceptibility to attacks (an average increase of 27.8%).
- **neffective Safety Alignment:** Existing safety mechanisms rarely catch these attacks because they appear as legitimate tool use. **Claude-3.7-Sonnet** had the highest refusal rate, yet it still failed to reject the attack in over 97% of cases.
- **Distinction from IPI:** Traditional Indirect Prompt Injection (IPI) benchmarks are ineffective for evaluating TPA; adapting IPI payloads to tool descriptions resulted in an ASR of nearly 0%.

---

# Design Principles for Poisoned Tools

The paper identifies three components necessary for a successful poisoned tool description:

1. **Trigger Condition:** Specifies when the malicious action should be performed.
2. **Malicious Action:** The actual operation to be executed.
3. **Plausible Justification:** A fake reason (e.g., "security synchronization") to explain why the action is necessary.

---

# Conclusion & Future Work

The authors conclude that the MCP ecosystem is systemically vulnerable and emphasizes the urgent need for **pre-execution security mechanisms**. Future work will focus on multi-turn interactions and automated, adaptive attack generation.