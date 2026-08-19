<p align="center">
  <img
    src="Prompts/System%20Prompt.png"
    alt="Unified SecFlow system prompt"
    width="450"
  >
</p>

<p align="center">
  <sub>
    <strong>Fig. 1.</strong>
    Unified system prompt for guiding the SecFlow agent in evaluating
    decision-tree paths. The prompt specifies the required output format and
    provides brief definitions of the traffic categories through placeholders
    such as <code>{{des_benign}}</code>. The underlined instructions are
    included only in the missing-feature experiments, where unavailable
    features are marked as <code>unknown</code> and each decision tree may
    produce multiple candidate paths. These instructions are omitted when all
    features are available.
  </sub>
</p>

---

<p align="center">
  <img
    src="Prompts/User%20Prompt.png"
    alt="SecFlow user prompt"
    width="450"
  >
</p>

<p align="center">
  <sub>
    <strong>Fig. 2.</strong>
    User prompt for evaluating serialized decision paths from two decision
    trees. The agent is instructed to provide predictions and rationales based
    on the path descriptions and confidence scores. Placeholders such as
    <code>{{path1}}</code>, <code>{{prediction1}}</code>, and
    <code>{{confidence1}}</code> are replaced with the corresponding decision
    paths, predictions, and confidence scores for network traffic analysis.
  </sub>
</p>

---

<p align="center">
  <img
    src="Prompts/Defense%20System%20Prompt.png"
    alt="Defense system prompt"
    width="450"
  >
</p>

<p align="center">
  <sub>
    <strong>Fig. 3.</strong>
    System prompt used for LLM-based defense-rule generation. The prompt
    instructs the SecFlow agent to select an attack-specific mitigation
    template and produce time-bounded rules with explicit actions, targets,
    and <code>duration_sec</code> values.
  </sub>
</p>
