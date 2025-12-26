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
- llama
- llama-3
- lora
- qlora
- peft
- function-calling
- structured-output
datasets:
- fmt0816/soc-alert-triage-dataset
base_model: meta-llama/Llama-3.1-8B-Instruct
model-index:
- name: soc-alert-triage-8b
  results:
  - task:
      type: text-generation
      name: Security Alert Triage
    dataset:
      type: fmt0816/soc-alert-triage-dataset
      name: SOC Alert Triage Dataset
    metrics:
    - type: accuracy
      value: 0.892
      name: Decision Accuracy
    - type: f1
      value: 0.872
      name: Decision F1 (Macro)
    - type: precision
      value: 0.921
      name: Escalation Precision
    - type: recall
      value: 0.884
      name: Escalation Recall
widget:
- text: |
    Analyze the following security alert:

    **Alert ID:** ALERT-2024-001
    **Category:** lateral_movement
    **Severity:** high
    **Title:** Pass-the-hash attack detected

    **Description:** Suspicious authentication using NTLM hash credentials detected from workstation to domain controller.

    **Indicators:**
    - Source: WS-PC-142
    - Destination: DC-01, FILE-SRV-01
    - Protocol: SMB
    - Auth Type: NTLM pass-the-hash

    Provide your triage recommendation.
  example_title: Lateral Movement Alert
- text: |
    Analyze the following security alert:

    **Alert ID:** ALERT-2024-002
    **Category:** malware
    **Severity:** critical
    **Title:** Ransomware signature detected

    **Description:** Known ransomware variant detected attempting to encrypt files on finance server.

    **Indicators:**
    - File hash: d41d8cd98f00b204e9800998ecf8427e
    - Process: invoice_update.exe
    - Parent: outlook.exe
    - Signature: Ransomware.LockBit.A

    Provide your triage recommendation.
  example_title: Malware Detection
- text: |
    Analyze the following security alert:

    **Alert ID:** ALERT-2024-003
    **Category:** phishing
    **Severity:** medium
    **Title:** Suspected credential harvesting attempt

    **Description:** User clicked link in email that redirected to known credential harvesting page.

    **Indicators:**
    - URL: https://login-microsoft.suspicious.site/auth
    - Sender: security@micr0soft-support.com
    - Subject: Urgent Password Reset Required

    Provide your triage recommendation.
  example_title: Phishing Alert
inference:
  parameters:
    max_new_tokens: 1024
    temperature: 0.3
    do_sample: true
    top_p: 0.9
---

# SOC Alert Triage 8B

A fine-tuned language model for automated Security Operations Center (SOC) alert triage. Built on Llama 3.1 8B Instruct and optimized for structured security analysis and decision-making.

## Model Description

**soc-alert-triage-8b** is designed to assist security analysts by providing consistent, expert-level triage recommendations for security alerts. It processes alert details including indicators of compromise, user context, asset information, and environmental factors to deliver actionable triage decisions.

### Key Features

| Feature | Description |
|---------|-------------|
| **12 Alert Categories** | Malware, phishing, brute force, data exfiltration, privilege escalation, lateral movement, C2, insider threat, policy violations, vulnerability exploits, reconnaissance, DoS |
| **5 Triage Decisions** | Escalate, investigate, monitor, false_positive, close |
| **Structured Output** | Consistent, parseable response format with decision, priority, reasoning, and actions |
| **Context-Aware** | Considers user role, asset criticality, and environmental factors |
| **MITRE ATT&CK Aligned** | Maps alerts to relevant ATT&CK tactics and techniques |

### Model Details

| Property | Value |
|----------|-------|
| **Base Model** | meta-llama/Llama-3.1-8B-Instruct |
| **Fine-tuning** | QLoRA (4-bit quantization + LoRA) |
| **LoRA Rank** | 64 |
| **LoRA Alpha** | 128 |
| **Training Data** | 10,000+ synthetic security alerts |
| **Max Context** | 4096 tokens |

## Quick Start

### Installation

```bash
pip install transformers torch accelerate bitsandbytes peft
```

### Basic Usage

```python
from transformers import AutoModelForCausalLM, AutoTokenizer

model_id = "fmt0816/soc-alert-triage-8b"
tokenizer = AutoTokenizer.from_pretrained(model_id)
model = AutoModelForCausalLM.from_pretrained(
    model_id,
    device_map="auto",
    load_in_4bit=True
)

alert = """Analyze the following security alert:

**Alert ID:** ALERT-001
**Category:** malware
**Severity:** high
**Title:** Suspicious executable detected on endpoint

**Description:** A suspicious executable matching known malware patterns was detected.

**Indicators:**
- File hash: abc123def456
- Process: svchost.exe
- Parent: powershell.exe

Provide your triage recommendation."""

messages = [
    {"role": "system", "content": "You are an expert SOC analyst. Analyze alerts and provide structured triage recommendations."},
    {"role": "user", "content": alert}
]

inputs = tokenizer.apply_chat_template(messages, return_tensors="pt").to(model.device)
outputs = model.generate(inputs, max_new_tokens=1024, temperature=0.3, do_sample=True)
response = tokenizer.decode(outputs[0], skip_special_tokens=True)
print(response)
```

### Using the Python Package

```python
from soc_triage_agent import SOCTriageModel

# Load model with 4-bit quantization
model = SOCTriageModel.from_pretrained("fmt0816/soc-alert-triage-8b")

# Triage an alert
alert = {
    "alert_id": "ALERT-001",
    "category": "malware",
    "severity": "high",
    "title": "Suspicious executable detected",
    "indicators": {"file_hash": "abc123...", "file_name": "malware.exe"},
    "user_context": {"username": "john.doe", "department": "Engineering", "is_vip": False},
    "asset_context": {"hostname": "WS-PC-001", "criticality": "medium"}
}

prediction = model.predict(alert)
print(f"Decision: {prediction.decision}")
print(f"Priority: {prediction.priority}")
print(f"Confidence: {prediction.confidence:.0%}")
print(f"Actions: {prediction.recommended_actions}")
```

### Using with OpenAI API

```python
from soc_triage_agent import SOCTriageModel
import os

# Set environment variable or pass directly
# export OPENAI_API_KEY=your-api-key

model = SOCTriageModel.from_openai(model_name="gpt-4")
prediction = model.predict(alert)
```

### Using with Azure OpenAI

```python
from soc_triage_agent import SOCTriageModel

# Set environment variables:
# export AZURE_OPENAI_KEY=your-key
# export AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com

model = SOCTriageModel.from_azure_openai(
    deployment_name="soc-triage-deployment"
)
prediction = model.predict(alert)
```

## Supported Alert Categories

| Category | Description | MITRE Tactics |
|----------|-------------|---------------|
| `malware` | Malware detection, ransomware, trojans | TA0002, TA0003 |
| `phishing` | Email phishing, BEC, credential harvesting | TA0001, TA0043 |
| `brute_force` | Password attacks, credential stuffing | TA0006 |
| `data_exfiltration` | Unauthorized data transfers | TA0009, TA0010 |
| `privilege_escalation` | Unauthorized privilege elevation | TA0004 |
| `lateral_movement` | Attacker movement within network | TA0008 |
| `command_and_control` | C2 beaconing, reverse shells | TA0011 |
| `insider_threat` | Anomalous user behavior | TA0009, TA0010 |
| `policy_violation` | Compliance and policy breaches | - |
| `vulnerability_exploit` | CVE exploitation attempts | TA0001, TA0002 |
| `reconnaissance` | Network scanning, enumeration | TA0043 |
| `denial_of_service` | DDoS attacks | TA0040 |

## Output Format

The model generates structured triage recommendations:

```markdown
## Triage Recommendation

### Decision Summary
| Field | Value |
|-------|-------|
| **Decision** | escalate |
| **Priority** | 1 |
| **Confidence** | 95% |
| **Escalation Required** | Yes |
| **Escalation Target** | Incident Response Team |
| **Estimated Impact** | high |

### Reasoning
[Detailed explanation of the decision...]

### Key Factors
1. [Factor 1]
2. [Factor 2]

### Recommended Actions
1. [Action 1]
2. [Action 2]
```

## Evaluation Results

### Overall Metrics

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

## Training Details

### Training Data

The model was trained on synthetic security alert data generated using expert-defined triage logic:

- **10,000+ training examples** across 12 alert categories
- **Balanced decision distribution** to prevent bias
- **Comprehensive context** including user, asset, and environmental factors
- **Expert-level triage decisions** based on security best practices

### Training Configuration

| Parameter | Value |
|-----------|-------|
| Base Model | meta-llama/Llama-3.1-8B-Instruct |
| Fine-tuning Method | QLoRA (4-bit + LoRA) |
| LoRA Rank (r) | 64 |
| LoRA Alpha | 128 |
| LoRA Dropout | 0.05 |
| Learning Rate | 2e-5 |
| Epochs | 3 |
| Batch Size | 16 (with gradient accumulation) |
| Max Sequence Length | 4096 |
| Optimizer | AdamW |
| LR Scheduler | Cosine |

### Reproduce Training

```bash
# Clone repository
git clone https://github.com/ftrout/soc-alert-triage-8b.git
cd soc-alert-triage-8b

# Install dependencies
pip install -e ".[train]"

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
    --output_dir ./outputs/soc-alert-triage-8b \
    --use_lora \
    --lora_r 64 \
    --lora_alpha 128 \
    --num_train_epochs 3
```

## Limitations

- **Synthetic Training Data**: Model was trained on synthetic data, which may not capture all real-world edge cases
- **Context Dependency**: Accuracy depends on completeness of provided alert context
- **No Real-Time Learning**: Model does not learn from production feedback without retraining
- **Language**: Currently supports English only
- **Hallucination Risk**: Like all LLMs, may occasionally generate plausible but incorrect reasoning

## Intended Use

### Primary Use Cases

- Assisting SOC analysts with initial alert triage
- Providing consistent triage recommendations across shifts
- Reducing alert fatigue and mean time to respond (MTTR)
- Training and onboarding junior analysts
- Augmenting understaffed security teams

### Out-of-Scope Uses

- Fully autonomous security decision-making without human oversight
- Replacing human analysts for critical security decisions
- Use in safety-critical systems without additional validation
- Processing classified or highly sensitive data without appropriate controls

## Ethical Considerations

- **Human Oversight**: This model should augment, not replace, human security analysts
- **Bias Monitoring**: Regular evaluation should be conducted to detect and mitigate biases
- **Transparency**: Security teams should understand how the model makes decisions
- **Adversarial Robustness**: Model outputs should be validated, as adversaries may attempt to manipulate inputs
- **Data Privacy**: Ensure alert data processed by the model complies with organizational policies

## Technical Specifications

### Hardware Requirements

| Configuration | VRAM Required |
|--------------|---------------|
| 4-bit Quantized (Recommended) | ~6 GB |
| 8-bit Quantized | ~10 GB |
| Full Precision (FP16) | ~16 GB |

### Software Requirements

- Python 3.9+
- PyTorch 2.0+
- Transformers 4.36+
- PEFT 0.6+
- bitsandbytes 0.41+ (for quantization)

## Citation

```bibtex
@software{soc_alert_triage_8b,
  title = {SOC Alert Triage 8B: Fine-tuned LLM for Security Alert Triage},
  author = {ftrout},
  year = {2025},
  url = {https://huggingface.co/fmt0816/soc-alert-triage-8b},
  note = {Fine-tuned on Llama 3.1 8B Instruct using QLoRA}
}
```

## License

This model is released under the [Apache 2.0 License](https://www.apache.org/licenses/LICENSE-2.0).

## Acknowledgments

- Built with [Hugging Face Transformers](https://huggingface.co/transformers)
- Fine-tuned using [PEFT](https://github.com/huggingface/peft) and [TRL](https://github.com/huggingface/trl)
- Base model: [meta-llama/Llama-3.1-8B-Instruct](https://huggingface.co/meta-llama/Llama-3.1-8B-Instruct)
- Alert categories aligned with [MITRE ATT&CK](https://attack.mitre.org/)

## Links

- **Model**: [huggingface.co/fmt0816/soc-alert-triage-8b](https://huggingface.co/fmt0816/soc-alert-triage-8b)
- **Dataset**: [huggingface.co/datasets/fmt0816/soc-alert-triage-dataset](https://huggingface.co/datasets/fmt0816/soc-alert-triage-dataset)
- **GitHub**: [github.com/ftrout/soc-alert-triage-8b](https://github.com/ftrout/soc-alert-triage-8b)
