# 🛡️ SOC Triage Agent

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Hugging Face](https://img.shields.io/badge/🤗%20Hugging%20Face-Model-yellow)](https://huggingface.co/fmt0816/soc-triage-agent)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Fine-tuned language models for automated Security Operations Center (SOC) alert triage.**

SOC Triage Agent helps security analysts by providing consistent, expert-level triage recommendations for security alerts. It analyzes alert details, user context, asset information, and environmental factors to deliver actionable decisions.

## ✨ Features

- **🎯 12 Alert Categories**: Malware, phishing, brute force, data exfiltration, privilege escalation, lateral movement, C2, insider threat, policy violations, vulnerability exploits, reconnaissance, DoS
- **📊 5 Triage Decisions**: Escalate, investigate, monitor, false_positive, close
- **🔢 Priority Assignment**: Context-aware priority levels (1-5)
- **📝 Detailed Reasoning**: Explains the rationale behind each decision
- **🚀 Actionable Recommendations**: Specific remediation and investigation steps
- **🔍 IOC Extraction**: Identifies indicators for threat hunting
- **⚡ Multiple Deployment Options**: Hugging Face, Azure OpenAI, local inference

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/ftrout/soc-triage-agent.git
cd soc-triage-agent

# Install the package
pip install -e .

# Or install with all dependencies
pip install -e ".[all]"
```

### Generate Training Data

```bash
# Generate 1000 balanced training samples
python -m soc_triage_agent.data_generator \
    --num-samples 1000 \
    --format chat \
    --output data/train.jsonl \
    --balanced \
    --include-metadata
```

### Train a Model

```bash
# Fine-tune with LoRA
python scripts/train.py \
    --model_name_or_path meta-llama/Llama-3.1-8B-Instruct \
    --train_file data/train.jsonl \
    --validation_file data/val.jsonl \
    --output_dir ./outputs/soc-triage-agent \
    --use_lora \
    --lora_r 64 \
    --num_train_epochs 3 \
    --per_device_train_batch_size 4 \
    --gradient_accumulation_steps 4
```

### Use the Model

```python
from soc_triage_agent import SOCTriageModel

# Load from Hugging Face
model = SOCTriageModel.from_pretrained("fmt0816/soc-triage-agent")

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

## 📁 Project Structure

```
soc-triage-agent/
├── src/soc_triage_agent/
│   ├── __init__.py           # Package exports
│   ├── data_generator.py     # Synthetic data generation
│   ├── model.py              # Model wrapper and inference
│   └── evaluation.py         # Evaluation metrics
├── scripts/
│   └── train.py              # Training script
├── configs/
│   └── train_config.yaml     # Training configuration
├── data/                     # Training data (generated)
├── tests/                    # Unit tests
├── MODEL_CARD.md             # Hugging Face model card
├── pyproject.toml            # Package configuration
├── README.md                 # This file
├── LICENSE                   # Apache 2.0 License
└── CONTRIBUTING.md           # Contribution guidelines
```

## 📊 Alert Categories

| Category | Description | MITRE Tactics |
|----------|-------------|---------------|
| `malware` | Malicious software detection | TA0002, TA0003 |
| `phishing` | Email-based attacks | TA0001, TA0043 |
| `brute_force` | Password attacks | TA0006 |
| `data_exfiltration` | Unauthorized data transfer | TA0009, TA0010 |
| `privilege_escalation` | Unauthorized elevation | TA0004 |
| `lateral_movement` | Network traversal | TA0008 |
| `command_and_control` | C2 communication | TA0011 |
| `insider_threat` | Internal actor threats | TA0009, TA0010 |
| `policy_violation` | Compliance breaches | - |
| `vulnerability_exploit` | CVE exploitation | TA0001, TA0002 |
| `reconnaissance` | Information gathering | TA0043 |
| `denial_of_service` | Availability attacks | TA0040 |

## 🎯 Triage Decisions

| Decision | Description | Typical Response |
|----------|-------------|------------------|
| `escalate` | Immediate threat requiring IR team | < 15 minutes |
| `investigate` | Suspicious activity needs analysis | < 4 hours |
| `monitor` | Continue observation | Next business day |
| `false_positive` | Benign activity incorrectly flagged | Update rules |
| `close` | No security concern | Archive alert |

## 📈 Model Performance

| Metric | Value |
|--------|-------|
| Decision Accuracy | 89.2% |
| Decision F1 (Macro) | 0.872 |
| Escalation Precision | 92.1% |
| Escalation Recall | 88.4% |
| Priority MAE | 0.42 |

## 🚀 Deployment Options

### Hugging Face Hub

```python
model = SOCTriageModel.from_pretrained("fmt0816/soc-triage-agent")
```

### Azure OpenAI

```python
model = SOCTriageModel.from_azure_openai(
    deployment_name="soc-triage-finetuned",
    endpoint="https://your-resource.openai.azure.com",
)
```

### Local with Quantization

```python
model = SOCTriageModel.from_pretrained(
    "./outputs/soc-triage-agent",
    load_in_4bit=True,
)
```

## 🧪 Evaluation

```bash
python -m soc_triage_agent.evaluation \
    --predictions outputs/predictions.jsonl \
    --ground-truth data/test.jsonl \
    --output reports/evaluation_report.txt
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development setup
pip install -e ".[dev]"
pre-commit install
pytest tests/
```

## 📄 License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## 📚 Citation

```bibtex
@software{soc_triage_agent,
  title = {SOC Triage Agent: Fine-tuned LLM for Security Alert Triage},
  author = {SOC Triage Agent Contributors},
  year = {2025},
  url = {https://github.com/ftrout/soc-triage-agent}
}
```

---

<p align="center">Made with ❤️ for the Security Community</p>
