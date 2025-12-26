# SOC Alert Triage 8B

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Hugging Face](https://img.shields.io/badge/%F0%9F%A4%97%20Hugging%20Face-Model-yellow)](https://huggingface.co/fmt0816/soc-alert-triage-8b)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Fine-tuned Llama 3.1 8B for automated Security Operations Center (SOC) alert triage.**

SOC Alert Triage 8B helps security analysts by providing consistent, expert-level triage recommendations for security alerts. It analyzes alert details, user context, asset information, and environmental factors to deliver actionable decisions.

## Features

- **12 Alert Categories**: Malware, phishing, brute force, data exfiltration, privilege escalation, lateral movement, C2, insider threat, policy violations, vulnerability exploits, reconnaissance, DoS
- **5 Triage Decisions**: Escalate, investigate, monitor, false_positive, close
- **Structured Output**: Consistent, parseable response format
- **Context-Aware**: Considers user role, asset criticality, and environmental factors
- **Multiple Deployment Options**: Hugging Face, OpenAI API, Azure OpenAI, local inference

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/ftrout/soc-alert-triage-8b.git
cd soc-alert-triage-8b

# Install the package
pip install -e .

# Or install with all dependencies
pip install -e ".[all]"
```

### Use the Model

```python
from soc_triage_agent import SOCTriageModel

# Load from Hugging Face
model = SOCTriageModel.from_pretrained("fmt0816/soc-alert-triage-8b")

# Triage an alert
alert = {
    "alert_id": "ALERT-2024-001",
    "category": "lateral_movement",
    "severity": "high",
    "title": "Pass-the-hash attack detected",
    "description": "Suspicious authentication using NTLM hash",
    "indicators": {
        "source_host": "WS-PC-142",
        "destination_hosts": ["DC-01", "FILE-SRV-01"],
        "protocol": "SMB",
        "credentials_type": "pass_the_hash"
    },
    "user_context": {
        "username": "john.smith",
        "department": "Engineering",
        "is_vip": False
    },
    "asset_context": {
        "hostname": "WS-PC-142",
        "criticality": "medium"
    }
}

result = model.predict(alert)

print(f"Decision: {result.decision}")
print(f"Priority: {result.priority}")
print(f"Escalation Required: {result.escalation_required}")
print(f"Actions: {result.recommended_actions}")
```

### Interactive Demo

```bash
# Run Gradio web interface
pip install -e ".[demo]"
python app.py

# Or with a specific model
python app.py --model fmt0816/soc-alert-triage-8b
```

### Generate Training Data

```bash
python -m soc_triage_agent.data_generator \
    --num-samples 10000 \
    --format chat \
    --output data/train.jsonl \
    --balanced \
    --include-metadata
```

### Train a Model

```bash
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

## Project Structure

```
soc-alert-triage-8b/
├── src/soc_triage_agent/
│   ├── __init__.py           # Package exports
│   ├── data_generator.py     # Synthetic data generation
│   ├── model.py              # Model wrapper and inference
│   └── evaluation.py         # Evaluation metrics
├── scripts/
│   └── train.py              # Training script
├── tests/                    # Unit tests
├── app.py                    # Gradio web interface
├── demo.py                   # CLI demo
├── MODEL_CARD.md             # Hugging Face model card
├── DATASET_CARD.md           # Hugging Face dataset card
├── SECURITY.md               # Security policy
├── pyproject.toml            # Package configuration
└── README.md                 # This file
```

## Alert Categories

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

## Triage Decisions

| Decision | Description | Typical Response |
|----------|-------------|------------------|
| `escalate` | Immediate threat requiring IR team | < 15 minutes |
| `investigate` | Suspicious activity needs analysis | < 4 hours |
| `monitor` | Continue observation | Next business day |
| `false_positive` | Benign activity incorrectly flagged | Update rules |
| `close` | No security concern | Archive alert |

## Model Performance

| Metric | Value |
|--------|-------|
| Decision Accuracy | 89.2% |
| Decision F1 (Macro) | 0.872 |
| Escalation Precision | 92.1% |
| Escalation Recall | 88.4% |
| Priority MAE | 0.42 |

## Deployment Options

### Hugging Face Hub

```python
model = SOCTriageModel.from_pretrained("fmt0816/soc-alert-triage-8b")
```

### OpenAI API

```python
# Set OPENAI_API_KEY environment variable or pass api_key parameter
model = SOCTriageModel.from_openai(model_name="gpt-4")
```

### Azure OpenAI

```python
# Set environment variables:
# export AZURE_OPENAI_KEY=your-key
# export AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com

model = SOCTriageModel.from_azure_openai(
    deployment_name="soc-triage-deployment"
)
```

### Local with Quantization

```python
model = SOCTriageModel.from_pretrained(
    "./outputs/soc-alert-triage-8b",
    load_in_4bit=True,
)
```

## Evaluation

```bash
python -m soc_triage_agent.evaluation \
    --predictions outputs/predictions.jsonl \
    --ground-truth data/test.jsonl \
    --output reports/evaluation_report.txt
```

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## Citation

```bibtex
@software{soc_alert_triage_8b,
  title = {SOC Alert Triage 8B: Fine-tuned LLM for Security Alert Triage},
  author = {ftrout},
  year = {2025},
  url = {https://github.com/ftrout/soc-alert-triage-8b}
}
```

## Links

- **Model**: [huggingface.co/fmt0816/soc-alert-triage-8b](https://huggingface.co/fmt0816/soc-alert-triage-8b)
- **Dataset**: [huggingface.co/datasets/fmt0816/soc-alert-triage-dataset](https://huggingface.co/datasets/fmt0816/soc-alert-triage-dataset)

---

<p align="center">Made for the Security Community</p>
