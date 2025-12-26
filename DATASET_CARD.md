---
annotations_creators:
- machine-generated
language:
- en
license: apache-2.0
multilinguality:
- monolingual
pretty_name: SOC Alert Triage Dataset
size_categories:
- "10K<n<100K"
source_datasets:
- original
tags:
- security
- cybersecurity
- soc
- triage
- alert-analysis
- incident-response
task_categories:
- text-generation
- text-classification
task_ids:
- multi-class-classification
---

# SOC Alert Triage Dataset

A synthetic dataset of security alerts with expert-level triage decisions for training the SOC Alert Triage 8B model and other security operations models.

## Dataset Description

### Summary

This dataset contains synthetic security alerts and corresponding triage recommendations, designed for training and evaluating machine learning models for Security Operations Center (SOC) automation.

Each sample includes:
- Detailed security alert with indicators of compromise
- User context (department, role, VIP status)
- Asset context (criticality, data classification)
- Environmental context (business hours, threat level)
- Expert triage decision with reasoning

### Supported Tasks

- **Security Alert Classification**: Classify alerts into triage decisions
- **Priority Prediction**: Predict appropriate priority levels
- **Text Generation**: Generate detailed triage recommendations

### Languages

English (en)

## Dataset Structure

### Data Instances

Each instance contains a conversation in chat format:

```json
{
  "messages": [
    {
      "role": "system",
      "content": "You are an expert Security Operations Center (SOC) analyst..."
    },
    {
      "role": "user", 
      "content": "Analyze the following security alert...\n\n## Alert Details\n..."
    },
    {
      "role": "assistant",
      "content": "## Triage Recommendation\n\n### Decision Summary\n| Field | Value |\n..."
    }
  ]
}
```

With metadata (when `include_metadata=True`):

```json
{
  "messages": [...],
  "_metadata": {
    "alert": {
      "alert_id": "550e8400-e29b-41d4-a716-446655440000",
      "timestamp": "2024-01-15T14:32:00",
      "source_system": "CrowdStrike Falcon",
      "category": "malware",
      "severity": "high",
      "title": "Suspicious executable detected on endpoint",
      "description": "...",
      "indicators": {...},
      "user_context": {...},
      "asset_context": {...},
      "environment_context": {...}
    },
    "triage": {
      "decision": "escalate",
      "priority": 2,
      "confidence_score": 0.92,
      "reasoning": "...",
      "recommended_actions": [...],
      "escalation_required": true,
      "escalation_target": "Incident Response Team"
    }
  }
}
```

### Data Fields

#### Alert Fields

| Field | Type | Description |
|-------|------|-------------|
| alert_id | string | Unique identifier |
| timestamp | string | ISO 8601 timestamp |
| source_system | string | Detection system name |
| category | string | Alert category (12 types) |
| severity | string | critical/high/medium/low/informational |
| title | string | Alert title |
| description | string | Detailed description |
| affected_assets | list[string] | Affected hostnames |
| indicators | dict | Category-specific IOCs |
| user_context | dict | User information |
| asset_context | dict | Asset information |
| environment_context | dict | Environmental factors |
| raw_log | string | Simulated raw log entry |
| mitre_techniques | list[string] | MITRE ATT&CK IDs |

#### Triage Fields

| Field | Type | Description |
|-------|------|-------------|
| decision | string | escalate/investigate/monitor/false_positive/close |
| priority | int | 1 (highest) to 5 (lowest) |
| confidence_score | float | 0.0 to 1.0 |
| reasoning | string | Explanation of decision |
| key_factors | list[string] | Key decision factors |
| recommended_actions | list[string] | Remediation steps |
| escalation_required | bool | Whether to escalate |
| escalation_target | string | Escalation destination |
| estimated_impact | string | none/low/moderate/high/severe |
| estimated_urgency | string | immediate/hours/day/week |
| additional_investigation | list[string] | Further investigation steps |
| ioc_extraction | list[string] | Extracted IOCs |

### Alert Categories

| Category | Description | Examples |
|----------|-------------|----------|
| malware | Malware detection | Ransomware, trojans, cryptominers |
| phishing | Email threats | Credential harvesting, BEC |
| brute_force | Auth attacks | Password spraying, credential stuffing |
| data_exfiltration | Data theft | Unauthorized transfers, USB copying |
| privilege_escalation | Privilege abuse | Token manipulation, UAC bypass |
| lateral_movement | Network spread | Pass-the-hash, WMI execution |
| command_and_control | C2 activity | Beaconing, DNS tunneling |
| insider_threat | User risk | Anomalous behavior, data hoarding |
| policy_violation | Compliance | Unauthorized software, config drift |
| vulnerability_exploit | CVE attacks | SQL injection, RCE attempts |
| reconnaissance | Scanning | Port scans, enumeration |
| denial_of_service | DDoS | Volumetric attacks, slowloris |

### Data Splits

| Split | Samples | Purpose |
|-------|---------|---------|
| train | 8,000 | Model training |
| validation | 1,000 | Hyperparameter tuning |
| test | 1,000 | Final evaluation |

## Dataset Creation

### Generation Process

1. **Template-Based Generation**: Realistic alert titles and descriptions from security expert templates
2. **Indicator Generation**: Category-specific IOCs (hashes, IPs, CVEs, etc.)
3. **Context Generation**: Randomized but coherent user/asset/environment contexts
4. **Triage Logic**: Rule-based expert decisions following security best practices

### Triage Decision Logic

Decisions are determined by:

- **Escalate**: Critical severity, successful attacks, lateral movement, threat intel matches
- **Investigate**: High severity, suspicious indicators, context anomalies
- **Monitor**: Low severity, partial indicators, uncertain outcomes
- **False Positive**: Change window activity, known authorized tools
- **Close**: Informational alerts, no action needed

Priority is influenced by:
- Severity weight (critical=1 to info=5)
- VIP user involvement (-1 priority)
- Critical asset involvement (-1 priority)
- Elevated threat level (-1 priority)

### Source Data

All data is synthetically generated. No real security incidents or personal data.

## Considerations

### Biases

- Balanced across alert categories by default
- Real-world distributions may differ significantly
- Some categories have more varied templates than others

### Limitations

- Synthetic data may not capture all real-world edge cases
- Triage logic is rule-based, not from actual analyst decisions
- Context combinations may occasionally be unrealistic
- English language only

### Recommendations

- Supplement with real (anonymized) alert data if available
- Adjust decision thresholds based on organizational risk tolerance
- Use for initial training, then fine-tune with production feedback
- Always maintain human oversight for critical decisions

## Usage

### Load Dataset

```python
from datasets import load_dataset

# From Hugging Face Hub
dataset = load_dataset("fmt0816/soc-triage-dataset")

# Access splits
train_data = dataset["train"]
val_data = dataset["validation"]
test_data = dataset["test"]
```

### Generate Custom Dataset

```python
from soc_triage_agent import SecurityAlertGenerator

generator = SecurityAlertGenerator(seed=42)
dataset = generator.generate_dataset(
    num_samples=10000,
    format_type="chat",
    balanced=True,
    include_metadata=True
)
```

### Format Variants

```python
# OpenAI chat format (default)
generator.generate_dataset(format_type="chat")

# ShareGPT format
generator.generate_dataset(format_type="sharegpt")

# Instruction format
generator.generate_dataset(format_type="instruction")

# Hugging Face format
generator.generate_dataset(format_type="huggingface")
```

## Citation

```bibtex
@dataset{soc_triage_dataset,
  title = {SOC Triage Dataset: Synthetic Security Alerts for ML Training},
  author = {ftrout},
  year = {2025},
  url = {https://huggingface.co/datasets/fmt0816/soc-triage-dataset},
  license = {Apache-2.0}
}
```

## License

Apache License 2.0
