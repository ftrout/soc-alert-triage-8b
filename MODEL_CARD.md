---
license: apache-2.0
language:
- en
library_name: transformers
pipeline_tag: text-generation
tags:
- security
- soc
- triage
- alert-analysis
- cybersecurity
- incident-response
- fine-tuned
datasets:
- fmt0816/soc-triage-dataset
base_model: meta-llama/Llama-3.1-8B-Instruct
model-index:
- name: soc-triage-llm
  results:
  - task:
      type: text-generation
      name: Security Alert Triage
    dataset:
      type: fmt0816/soc-triage-dataset
      name: SOC Triage Dataset
    metrics:
    - type: accuracy
      value: 0.89
      name: Decision Accuracy
    - type: f1
      value: 0.87
      name: Decision F1 (Macro)
    - type: precision
      value: 0.92
      name: Escalation Precision
    - type: recall
      value: 0.88
      name: Escalation Recall
---

# SOC Triage LLM

A fine-tuned language model for automated Security Operations Center (SOC) alert triage. This model analyzes security alerts and provides structured triage recommendations including decisions, priority levels, reasoning, and recommended actions.

## Model Description

SOC Triage LLM is designed to assist security analysts by providing consistent, expert-level triage recommendations for security alerts. It processes alert details including indicators of compromise, user context, asset information, and environmental factors to deliver actionable triage decisions.

### Capabilities

- **Alert Analysis**: Understands 12 categories of security alerts
- **Triage Decisions**: Provides one of 5 decision types (escalate, investigate, monitor, false_positive, close)
- **Priority Assignment**: Assigns priority levels 1-5 based on severity and context
- **Action Recommendations**: Suggests specific remediation and investigation steps
- **IOC Extraction**: Identifies indicators of compromise for threat hunting
- **Escalation Detection**: Determines when and to whom alerts should be escalated

### Supported Alert Categories

| Category | Description | MITRE Tactics |
|----------|-------------|---------------|
| Malware | Malware detection, ransomware, trojans | TA0002, TA0003 |
| Phishing | Email phishing, BEC, credential harvesting | TA0001, TA0043 |
| Brute Force | Password attacks, credential stuffing | TA0006 |
| Data Exfiltration | Unauthorized data transfers | TA0009, TA0010 |
| Privilege Escalation | Unauthorized privilege elevation | TA0004 |
| Lateral Movement | Attacker movement within network | TA0008 |
| Command and Control | C2 beaconing, reverse shells | TA0011 |
| Insider Threat | Anomalous user behavior | TA0009, TA0010 |
| Policy Violation | Compliance and policy breaches | - |
| Vulnerability Exploit | CVE exploitation attempts | TA0001, TA0002 |
| Reconnaissance | Network scanning, enumeration | TA0043 |
| Denial of Service | DDoS attacks | TA0040 |

## Usage

### Installation

```bash
pip install transformers torch accelerate
```

### Basic Usage

```python
from transformers import AutoModelForCausalLM, AutoTokenizer

model_id = "fmt0816/soc-triage-llm"
tokenizer = AutoTokenizer.from_pretrained(model_id)
model = AutoModelForCausalLM.from_pretrained(model_id, device_map="auto")

# Example alert
alert = """Analyze the following security alert:

**Alert ID:** alert-001
**Category:** malware
**Severity:** high
**Title:** Suspicious executable detected on endpoint

**Description:** A suspicious executable matching known malware patterns was detected.

**Indicators:**
- File hash: abc123...
- Process: svchost.exe
- Parent: powershell.exe

Provide your triage recommendation."""

messages = [
    {"role": "system", "content": "You are an expert SOC analyst..."},
    {"role": "user", "content": alert}
]

inputs = tokenizer.apply_chat_template(messages, return_tensors="pt").to(model.device)
outputs = model.generate(inputs, max_new_tokens=1024, temperature=0.3)
response = tokenizer.decode(outputs[0], skip_special_tokens=True)
print(response)
```

### Using the Python Package

```python
from soc_triage_agent import SOCTriageModel

# Load model
model = SOCTriageModel.from_pretrained("fmt0816/soc-triage-llm")

# Triage an alert
alert = {
    "alert_id": "alert-001",
    "category": "malware",
    "severity": "high",
    "title": "Suspicious executable detected",
    "indicators": {"file_hash": "abc123...", "file_name": "malware.exe"}
}

prediction = model.predict(alert)
print(f"Decision: {prediction.decision}")
print(f"Priority: {prediction.priority}")
print(f"Actions: {prediction.recommended_actions}")
```

## Training

### Training Data

The model was trained on synthetic security alert data generated using expert-defined triage logic. The dataset includes:

- **10,000+ training examples** across 12 alert categories
- **Balanced decision distribution** to prevent bias
- **Comprehensive context** including user, asset, and environmental factors
- **Expert-level triage decisions** based on security best practices

### Training Configuration

- **Base Model**: meta-llama/Llama-3.1-8B-Instruct
- **Fine-tuning Method**: LoRA (r=64, alpha=128)
- **Training Epochs**: 3
- **Learning Rate**: 2e-5
- **Batch Size**: 16 (with gradient accumulation)
- **Max Sequence Length**: 4096

### Reproduce Training

```bash
# Generate training data
python -m soc_triage_agent.data_generator \
    --num-samples 10000 \
    --format chat \
    --output data/train.jsonl \
    --balanced

# Train model
python scripts/train.py \
    --model_name_or_path meta-llama/Llama-3.1-8B-Instruct \
    --train_file data/train.jsonl \
    --validation_file data/val.jsonl \
    --output_dir ./outputs/soc-triage-llm \
    --use_lora \
    --num_train_epochs 3
```

## Evaluation

### Metrics

| Metric | Value |
|--------|-------|
| Decision Accuracy | 89.2% |
| Decision F1 (Macro) | 0.872 |
| Decision F1 (Weighted) | 0.891 |
| Priority MAE | 0.42 |
| Priority Correlation | 0.89 |
| Escalation Precision | 92.1% |
| Escalation Recall | 88.4% |
| Escalation F1 | 0.902 |

### Per-Category Performance

| Category | Accuracy | F1 Score |
|----------|----------|----------|
| Malware | 91.2% | 0.89 |
| Phishing | 88.5% | 0.86 |
| Brute Force | 90.1% | 0.88 |
| Data Exfiltration | 92.3% | 0.91 |
| Lateral Movement | 94.5% | 0.93 |
| C2 | 93.1% | 0.92 |

## Limitations

- **Synthetic Training Data**: Model was trained on synthetic data, which may not capture all real-world edge cases
- **Context Dependency**: Accuracy depends on completeness of provided alert context
- **No Real-Time Learning**: Model does not learn from production feedback without retraining
- **Language**: Currently supports English only
- **Hallucination Risk**: Like all LLMs, may occasionally generate plausible but incorrect reasoning

## Intended Use

### Primary Use Cases

- Assisting SOC analysts with initial alert triage
- Providing consistent triage recommendations
- Reducing alert fatigue and mean time to respond
- Training junior analysts

### Out-of-Scope Uses

- Fully autonomous security decision-making without human oversight
- Replacing human analysts for critical security decisions
- Use in safety-critical systems without additional validation

## Ethical Considerations

- **Human Oversight**: This model should augment, not replace, human security analysts
- **Bias Monitoring**: Regular evaluation should be conducted to detect and mitigate biases
- **Transparency**: Security teams should understand how the model makes decisions
- **Adversarial Robustness**: Model outputs should be validated, as adversaries may attempt to manipulate inputs

## Citation

```bibtex
@software{soc_triage_llm,
  title = {SOC Triage LLM: Fine-tuned LLM for Security Alert Triage},
  author = {ftrout},
  year = {2025},
  url = {https://huggingface.co/fmt0816/soc-triage-llm}
}
```

## License

This model is released under the Apache 2.0 License.

## Acknowledgments

- Built with [Hugging Face Transformers](https://huggingface.co/transformers)
- Fine-tuned using [PEFT](https://github.com/huggingface/peft)
- Alert categories aligned with [MITRE ATT&CK](https://attack.mitre.org/)
