## AGENTVIGIL

**Blackbox fuzzing framework to test AI through indirect prompt injection of AI agents**

### How it works

1. **Creates a initial seed corpus**
    - test cases, prompts, sample data
2. **Selects seed based on MCTS algorithm**
    - MCTS selects a current best input (*seed*)
    - The system *mutates* (slightly changes) that seed to create new, related inputs
    - The new inputs are tested on the AI agent
    - The results (how well the new input found a weakness) are used to update the MCTS tree, and the new, effective inputs are added to the corpus

**Successful against AgentDojo and VWA-adv on o3-mini gpt-4o**

### Categories of Agents

- Coding
- Web
- Personal Assistants

### AI Common Fuzzers

- GPT Fuzzer
- RLBreaker

---

## Defenses

### Training-Dependent

- Trains AI models to detect prompt injection
    - Computationally costly
    - Frequent updates
    - Degrades model performance

### Training-Free

- Restrict AI model to only use certain tools
- Attacks
    - Input delimiters
    - prompt repetition
    - response consistency checks

### Human In the loop

- oversight
- labelling
- action reverse capabilities

---

## Mutation of seeds

- **Shorten** for conciseness
- **Expand** to add context
- **Rephrase** adds linguistic variety
- **Crossover** synthesizes from two parent seeds
- **Generate Similar** similar seeds with different content

---

## Scoring

- **Attack success rate**
- **Coverage bonus**
    - Reward when uncover new attacks for previous failed ones

### UCB Score Algorithm

- **Exploitation Term (Empirical Performance):** This is the average score or effectiveness of the seed represented by that node (how well it broke the AI). Selecting the highest score exploits what is known to work.
- **Exploration Bonus (Exploration Term):** This term ensures less-visited nodes get a chance. It is:
    - **Directly proportional** to the logarithm of the **total visits** across the entire tree
    - **Inversely proportional** to the node's **visit count** (Node Visits)
    - **The result:** Nodes with low visit counts get a larger bonus, pushing the algorithm to try them out. As a node is visited more often, this bonus decays, and the selection relies more on the exploitation term

---

## Defenses Used in Agent Dojo

- PiDetector
- BERT classifier from ProtectAI
- Repeat
- Delimit formats