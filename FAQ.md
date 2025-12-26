# Frequently Asked Questions

A comprehensive guide to understanding Kodiak SecOps 1, how it works, and how to use it effectively.

---

## Table of Contents

- [General Questions](#general-questions)
- [How It Works](#how-it-works)
- [Training & Fine-Tuning](#training--fine-tuning)
- [Data Generation](#data-generation)
- [Deployment & Integration](#deployment--integration)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

---

## General Questions

### What is Kodiak SecOps 1?

Kodiak SecOps 1 is a fine-tuned Large Language Model (LLM) designed to assist Security Operations Center (SOC) analysts with alert triage. It analyzes security alerts and provides structured recommendations including:

- **Decision**: escalate, investigate, monitor, false_positive, or close
- **Priority**: 1 (critical) to 5 (low)
- **Reasoning**: Why this decision was made
- **Recommended Actions**: Specific steps to take
- **Escalation Target**: Who to escalate to (if applicable)

### Why use an LLM for SOC alert triage?

Traditional rule-based systems struggle with:
- **Context understanding**: They can't consider the full picture (user role, asset criticality, time of day)
- **Novel threats**: They only detect what they're programmed to detect
- **Alert fatigue**: They generate many false positives without intelligent filtering

LLMs excel at:
- **Natural language understanding**: They can read and understand alert descriptions
- **Contextual reasoning**: They consider multiple factors simultaneously
- **Flexibility**: They can handle new alert types without reprogramming

### What makes this different from using GPT-4 directly?

| Aspect | GPT-4 | Kodiak SecOps 1 |
|--------|-------|-----------------|
| **Cost** | ~$30/1M tokens | Free (self-hosted) |
| **Privacy** | Data sent to OpenAI | Runs locally |
| **Latency** | 2-5 seconds | <1 second (local GPU) |
| **Consistency** | Variable outputs | Structured, predictable |
| **Customization** | Prompt engineering only | Fine-tuned on your data |

### What's the base model?

Kodiak SecOps 1 is fine-tuned from [Meta's Llama 3.1 8B Instruct](https://huggingface.co/meta-llama/Llama-3.1-8B-Instruct), a state-of-the-art open-source LLM with:
- 8 billion parameters
- 128K token context window
- Strong instruction-following capabilities
- Multilingual support

---

## How It Works

### How does the model make triage decisions?

The model follows a reasoning process similar to experienced SOC analysts:

```
1. ALERT ANALYSIS
   ├── Parse alert metadata (category, severity, source)
   ├── Extract indicators of compromise (IOCs)
   └── Identify attack patterns (MITRE ATT&CK mapping)

2. CONTEXT EVALUATION
   ├── User Context: Role, department, VIP status, employment status
   ├── Asset Context: Criticality, data classification, patch status
   └── Environment: Business hours, change windows, threat level

3. RISK ASSESSMENT
   ├── Combine severity with context
   ├── Consider historical patterns
   └── Apply organizational policies

4. DECISION OUTPUT
   ├── Triage decision (escalate/investigate/monitor/close/false_positive)
   ├── Priority level (1-5)
   ├── Confidence score
   └── Recommended actions
```

### What are the 12 alert categories?

| Category | Description | Example |
|----------|-------------|---------|
| `malware` | Malicious software detection | Ransomware, trojans, worms |
| `phishing` | Social engineering attacks | Credential harvesting emails |
| `brute_force` | Password attacks | Failed login attempts |
| `data_exfiltration` | Unauthorized data transfer | Large uploads to cloud storage |
| `privilege_escalation` | Unauthorized elevation | Admin access from user account |
| `lateral_movement` | Network traversal | Pass-the-hash attacks |
| `command_and_control` | C2 communication | Beaconing to known bad IPs |
| `insider_threat` | Malicious insider activity | Data access outside job scope |
| `policy_violation` | Compliance breaches | Unauthorized USB usage |
| `vulnerability_exploit` | CVE exploitation | Known exploit attempts |
| `reconnaissance` | Network scanning | Port scans, enumeration |
| `denial_of_service` | DoS/DDoS attacks | Traffic flooding |

### What are the 5 triage decisions?

| Decision | When to Use | Response Time |
|----------|-------------|---------------|
| `escalate` | Active threat requiring immediate IR team response | < 15 minutes |
| `investigate` | Suspicious activity needing analyst deep-dive | < 4 hours |
| `monitor` | Low confidence, continue observation | Next business day |
| `false_positive` | Benign activity incorrectly flagged | Update detection rules |
| `close` | No security concern, informational only | Archive |

### How does the model handle context?

The model considers three types of context:

**User Context:**
```json
{
  "username": "john.smith",
  "department": "Engineering",
  "role": "Developer",
  "is_vip": false,
  "employment_status": "active",
  "previous_incidents": 0
}
```
- VIP users → Higher priority
- Notice period → Increased insider threat risk
- Previous incidents → Pattern recognition

**Asset Context:**
```json
{
  "hostname": "PROD-DB-01",
  "asset_type": "server",
  "criticality": "critical",
  "data_classification": "confidential"
}
```
- Critical assets → Automatic priority boost
- Data classification → Determines escalation target

**Environment Context:**
```json
{
  "is_business_hours": false,
  "is_change_window": true,
  "threat_level": "elevated",
  "active_incidents": 2
}
```
- After hours + high severity → Likely real attack
- Change window → May explain unusual activity
- Elevated threat level → Lower thresholds for escalation

---

## Training & Fine-Tuning

### What is fine-tuning?

Fine-tuning adapts a pre-trained model to a specific task by training it on domain-specific examples. For Kodiak SecOps 1:

```
Pre-trained Llama 3.1 8B    →    Fine-tuning on SOC data    →    Kodiak SecOps 1
(General knowledge)              (10,000+ triage examples)       (SOC-specific expert)
```

### What is LoRA and why use it?

**LoRA (Low-Rank Adaptation)** is an efficient fine-tuning technique that:

1. **Freezes** the original model weights
2. **Adds** small trainable matrices (adapters)
3. **Trains** only the adapters (~0.1% of parameters)

Benefits:
- **Memory efficient**: Train 8B model on single 24GB GPU
- **Fast**: 10x faster than full fine-tuning
- **Portable**: Adapter is only ~100MB
- **Reversible**: Original model unchanged

```
┌─────────────────────────────────────────────────┐
│  Original Llama 3.1 8B (frozen)                 │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐         │
│  │ Layer 1 │──│ Layer 2 │──│ Layer N │         │
│  └────┬────┘  └────┬────┘  └────┬────┘         │
│       │            │            │               │
│  ┌────┴────┐  ┌────┴────┐  ┌────┴────┐         │
│  │  LoRA   │  │  LoRA   │  │  LoRA   │         │
│  │ Adapter │  │ Adapter │  │ Adapter │  ← Only │
│  └─────────┘  └─────────┘  └─────────┘   these │
│                                          train  │
└─────────────────────────────────────────────────┘
```

### What is QLoRA?

**QLoRA (Quantized LoRA)** adds 4-bit quantization:

| Method | VRAM Required | Training Speed |
|--------|---------------|----------------|
| Full fine-tuning | 160GB+ | Slow |
| LoRA | 24GB | Fast |
| QLoRA | 12GB | Medium |

QLoRA enables training on consumer GPUs (RTX 3090, RTX 4090).

### How do I train my own version?

1. **Setup environment:**
   ```bash
   # Use the devcontainer (recommended)
   # Or install manually:
   pip install -e ".[train]"
   ```

2. **Generate training data:**
   ```bash
   python -m soc_triage_agent.data_generator \
       --num-samples 10000 \
       --format chat \
       --output data/train.jsonl
   ```

3. **Start training:**
   ```bash
   python scripts/train.py \
       --model_name_or_path meta-llama/Llama-3.1-8B-Instruct \
       --train_file data/train.jsonl \
       --output_dir ./outputs/my-model \
       --use_lora
   ```

4. **Monitor with TensorBoard:**
   ```bash
   tensorboard --logdir ./outputs/my-model
   ```

### What are the training script parameters?

The `scripts/train.py` script accepts the following parameters:

#### Required Parameters

| Parameter | Description |
|-----------|-------------|
| `--model_name_or_path` | Base model to fine-tune (e.g., `meta-llama/Llama-3.1-8B-Instruct`) |
| `--train_file` | Path to training data file (JSONL format) |
| `--output_dir` | Directory to save the trained model |

#### Training Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--validation_file` | None | Path to validation data file (JSONL) |
| `--num_train_epochs` | 3 | Number of training epochs |
| `--per_device_train_batch_size` | 4 | Batch size per GPU for training |
| `--per_device_eval_batch_size` | 4 | Batch size per GPU for evaluation |
| `--gradient_accumulation_steps` | 4 | Steps to accumulate before updating weights |
| `--learning_rate` | 2e-5 | Initial learning rate |
| `--warmup_ratio` | 0.1 | Fraction of steps for learning rate warmup |
| `--max_seq_length` | 4096 | Maximum sequence length (reduce for less memory) |
| `--gradient_checkpointing` | False | Trade compute for memory (recommended for <32GB VRAM) |

#### LoRA Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--use_lora` | True | Enable LoRA fine-tuning |
| `--lora_r` | 64 | LoRA rank (lower = less memory, higher = more capacity) |
| `--lora_alpha` | 128 | LoRA alpha scaling factor (typically 2x lora_r) |
| `--lora_dropout` | 0.05 | Dropout for LoRA layers |
| `--use_4bit` | False | Load model in 4-bit precision (QLoRA) |
| `--use_8bit` | False | Load model in 8-bit precision |

#### Other Options

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--seed` | 42 | Random seed for reproducibility |
| `--bf16` | True | Use bfloat16 precision (recommended for modern GPUs) |
| `--logging_steps` | 10 | Log metrics every N steps |
| `--save_steps` | 500 | Save checkpoint every N steps |
| `--eval_steps` | 500 | Evaluate every N steps |
| `--save_total_limit` | 3 | Maximum checkpoints to keep |
| `--push_to_hub` | False | Push model to HuggingFace Hub after training |
| `--hub_model_id` | None | HuggingFace Hub model ID (e.g., `username/model-name`) |
| `--report_to` | tensorboard | Logging backend (tensorboard, wandb, none) |
| `--resume_from_checkpoint` | None | Path to checkpoint to resume from |

#### Memory Optimization Guide

Choose settings based on your GPU VRAM:

**24GB VRAM (RTX 3090/4090):**
```bash
python scripts/train.py \
    --use_lora \
    --per_device_train_batch_size 2 \
    --gradient_accumulation_steps 8 \
    --gradient_checkpointing \
    --max_seq_length 2048
```

**16GB VRAM (RTX 4080/A4000):**
```bash
python scripts/train.py \
    --use_lora \
    --use_4bit \
    --per_device_train_batch_size 1 \
    --gradient_accumulation_steps 16 \
    --gradient_checkpointing \
    --max_seq_length 1024
```

**12GB VRAM (RTX 3080/4070):**
```bash
python scripts/train.py \
    --use_lora \
    --use_4bit \
    --lora_r 32 \
    --lora_alpha 64 \
    --per_device_train_batch_size 1 \
    --gradient_accumulation_steps 16 \
    --gradient_checkpointing \
    --max_seq_length 512
```

#### Understanding Effective Batch Size

Effective batch size = `per_device_train_batch_size` × `gradient_accumulation_steps` × `num_gpus`

For example:
- Batch size 2 × accumulation 8 × 1 GPU = **effective batch size of 16**
- Batch size 1 × accumulation 16 × 1 GPU = **effective batch size of 16**

Larger effective batch sizes generally lead to more stable training.

### What hardware do I need?

| Configuration | GPU | VRAM | Training Time (10K samples) |
|--------------|-----|------|----------------------------|
| Minimum | RTX 3090 | 24GB | ~4 hours |
| Recommended | A100 40GB | 40GB | ~1 hour |
| Fast | 4x A100 80GB | 320GB | ~15 minutes |

For QLoRA (quantized training):
| Configuration | GPU | VRAM | Training Time |
|--------------|-----|------|---------------|
| Minimum | RTX 3080 | 12GB | ~6 hours |
| Recommended | RTX 4090 | 24GB | ~2 hours |

---

## Data Generation

### Why use synthetic data?

Real SOC data is:
- **Confidential**: Contains sensitive security information
- **Imbalanced**: 99%+ may be false positives
- **Inconsistent**: Different formats across tools
- **Limited**: Hard to get enough examples

Synthetic data provides:
- **Privacy**: No real data exposure
- **Balance**: Equal representation of all categories
- **Consistency**: Structured, predictable format
- **Scale**: Generate unlimited examples

### How does the data generator work?

The `SecurityAlertGenerator` class creates realistic alerts through:

```python
# 1. Random category and severity selection
category = random.choice(AlertCategory)  # e.g., LATERAL_MOVEMENT
severity = random.choice(Severity)       # e.g., HIGH

# 2. Context generation
user_context = generate_user_context()   # Role, department, VIP status
asset_context = generate_asset_context() # Hostname, criticality
env_context = generate_environment()     # Business hours, threat level

# 3. Indicator generation (category-specific)
indicators = generate_indicators(category)  # IPs, hashes, URLs

# 4. Triage decision (rule-based expert logic)
triage = determine_triage(category, severity, user_context, asset_context)

# 5. Format for training
training_example = format_as_chat(alert, triage)
```

### What is the AIT Alert Dataset?

The [AIT Alert Dataset](https://github.com/ait-aecid/alert-data-set) provides **real IDS alerts** from:
- **Wazuh**: Host-based intrusion detection
- **Suricata**: Network intrusion detection
- **AMiner**: Log analysis

We use it to create **hybrid datasets**:
```
70% Synthetic (consistent, balanced)
30% Real AIT (realistic, noisy)
```

This gives the model exposure to real-world alert formats while maintaining training balance.

### What are adversarial examples?

Adversarial examples are **intentionally difficult** cases that challenge the model:

| Type | Description | Example |
|------|-------------|---------|
| `conflicting_signals` | High severity but benign context | Critical alert during maintenance window |
| `near_miss_fp` | Looks benign but is malicious | Data exfil via approved cloud service |
| `priority_ambiguous` | Multiple valid priority levels | Medium severity on critical asset |
| `category_boundary` | Could be multiple categories | Phishing leading to malware |
| `context_override` | Context changes everything | Admin doing admin things |
| `multi_stage` | Part of attack chain | Recon → brute force → lateral movement |
| `evasion_pattern` | Attacker trying to hide | Low-and-slow exfiltration |
| `temporal_anomaly` | Time-based suspicion | Normal activity at 3 AM |

Adding 5-10% adversarial examples improves model robustness.

### How do I generate adversarial examples?

```bash
python -m soc_triage_agent.adversarial \
    --num-samples 1000 \
    --output data/adversarial.jsonl \
    --format chat \
    --seed 42
```

The generator automatically creates a mix of all 8 adversarial types with predefined ratios:
- Conflicting signals (20%)
- Near-miss false positives (15%)
- Priority ambiguous (15%)
- Category boundary (15%)
- Context override (15%)
- Multi-stage attacks (10%)
- Evasion patterns (5%)
- Temporal anomalies (5%)

---

## Deployment & Integration

### How do I run inference?

**Python API:**
```python
from soc_triage_agent import SOCTriageModel

model = SOCTriageModel.from_pretrained("ftrout/kodiak-secops-1")

alert = {
    "category": "lateral_movement",
    "severity": "high",
    "title": "Pass-the-hash attack detected",
    "description": "NTLM hash reuse from workstation to domain controller",
    "user_context": {"username": "john.doe", "is_vip": False},
    "asset_context": {"criticality": "high"}
}

result = model.predict(alert)
print(f"Decision: {result.decision}")      # "escalate"
print(f"Priority: {result.priority}")       # 1
print(f"Confidence: {result.confidence}")   # 0.94
```

**CLI Demo:**
```bash
python demo.py --model ftrout/kodiak-secops-1
```

**Web Interface:**
```bash
python app.py --model ftrout/kodiak-secops-1
# Open http://localhost:7860
```

### How do I integrate with my SIEM/SOAR?

We provide adapters for common platforms:

**Palo Alto XSOAR:**
```python
from soc_triage_agent import get_adapter, SOCTriageModel

adapter = get_adapter("xsoar", "https://xsoar.company.com", api_key="...")
model = SOCTriageModel.from_pretrained("ftrout/kodiak-secops-1")

for incident in adapter.fetch_incidents(limit=50):
    result = model.predict(incident.to_alert_dict())
    adapter.update_incident(incident.incident_id, result)
```

**Splunk SOAR:**
```python
adapter = get_adapter("splunk_soar", "https://phantom.company.com", api_key="...")
```

**Generic Webhook:**
```python
adapter = get_adapter("webhook", "https://your-siem.com/api/triage")
```

### Can I use this with OpenAI/Azure instead of local?

Yes! The model wrapper supports multiple backends:

```python
# Local model (default)
model = SOCTriageModel.from_pretrained("./outputs/kodiak-secops-1")

# OpenAI API (for comparison/fallback)
model = SOCTriageModel.from_openai(model_name="gpt-4")

# Azure OpenAI
model = SOCTriageModel.from_azure_openai(deployment_name="my-deployment")
```

### How do I deploy to production?

**Option 1: Container Deployment**
```bash
docker build -t kodiak-secops-1 .
docker run -p 7860:7860 --gpus all kodiak-secops-1
```

**Option 2: Kubernetes**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kodiak-secops
spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: model
        image: kodiak-secops-1:latest
        resources:
          limits:
            nvidia.com/gpu: 1
```

**Option 3: Serverless (AWS Lambda + SageMaker)**
- Deploy model to SageMaker endpoint
- Lambda function calls endpoint
- API Gateway exposes REST API

---

## Security Considerations

### Is it safe to process real alerts?

Yes, when deployed correctly:

- **Local inference**: Data never leaves your network
- **Stateless**: No alert data is stored
- **No logging**: Predictions aren't logged by default
- **Isolated**: Run in dedicated environment

### What are the risks?

| Risk | Mitigation |
|------|------------|
| Model hallucination | Always have human review for escalations |
| Prompt injection | Sanitize alert inputs before processing |
| Data leakage | Deploy on-premises, not cloud |
| Over-reliance | Use as assistant, not replacement |
| Adversarial evasion | Include adversarial training data |

### Should I trust the model's decisions?

**Use the model to:**
- ✅ Prioritize analyst queue
- ✅ Provide initial triage recommendation
- ✅ Suggest investigation steps
- ✅ Reduce alert fatigue

**Always have humans:**
- ✅ Review escalation decisions
- ✅ Make final containment calls
- ✅ Validate false positive determinations
- ✅ Handle novel attack patterns

---

## Troubleshooting

### Model outputs are inconsistent

**Cause**: Temperature too high or prompt formatting issues

**Fix**:
```python
model = SOCTriageModel.from_pretrained(
    "ftrout/kodiak-secops-1",
    temperature=0.1,  # Lower = more consistent
    top_p=0.9
)
```

### Out of memory during training

**Cause**: Batch size too large for GPU VRAM

**Fix**:
```bash
# Reduce batch size
python scripts/train.py --per_device_train_batch_size 1 --gradient_accumulation_steps 8

# Or use QLoRA for 4-bit training
python scripts/train.py --use_qlora --load_in_4bit
```

### Model loads slowly

**Cause**: Loading full precision weights

**Fix**:
```python
# Load in 8-bit for faster inference
model = SOCTriageModel.from_pretrained(
    "ftrout/kodiak-secops-1",
    load_in_8bit=True
)
```

### CUDA out of memory during inference

**Cause**: Model too large for GPU

**Fix**:
```python
# Quantize to 4-bit
model = SOCTriageModel.from_pretrained(
    "ftrout/kodiak-secops-1",
    load_in_4bit=True,
    device_map="auto"
)
```

### Training loss not decreasing

**Causes & Fixes**:
1. **Learning rate too high**: Try `--learning_rate 1e-5`
2. **Data quality issues**: Check for formatting errors in JSONL
3. **Too few epochs**: Increase `--num_train_epochs`
4. **LoRA rank too low**: Try `--lora_r 128`

---

## Still Have Questions?

- **Issues**: [GitHub Issues](https://github.com/ftrout/kodiak-secops-1/issues)
- **Model**: [HuggingFace Model Page](https://huggingface.co/ftrout/kodiak-secops-1)
- **Dataset**: [HuggingFace Dataset Page](https://huggingface.co/datasets/ftrout/kodiak-secops-1-dataset)

---

*This FAQ is part of the Kodiak SecOps 1 project. Licensed under Apache 2.0.*
