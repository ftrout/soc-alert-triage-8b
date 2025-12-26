# Frequently Asked Questions

A comprehensive guide to understanding Kodiak SecOps 1, how it works, and how to use it effectively.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Glossary](#glossary)
- [General Questions](#general-questions)
- [How It Works](#how-it-works)
- [Training & Fine-Tuning](#training--fine-tuning)
- [Data Generation](#data-generation)
- [Deployment & Integration](#deployment--integration)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
- [Common Mistakes](#common-mistakes)
- [Step-by-Step Example](#step-by-step-example-training-your-first-model)

---

## Quick Start

New to Kodiak SecOps 1? Here's the 5-minute overview:

### What This Project Does

```
┌─────────────────┐      ┌──────────────────┐      ┌─────────────────┐
│  Security Alert │  →   │  Kodiak SecOps 1 │  →   │ Triage Decision │
│  (from SIEM)    │      │  (AI Model)      │      │ + Priority      │
└─────────────────┘      └──────────────────┘      └─────────────────┘
```

**Input**: A security alert (e.g., "Failed login from unusual IP")
**Output**: Triage recommendation (e.g., "Investigate, Priority 2, check user's recent activity")

### The Complete Workflow

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        END-TO-END WORKFLOW                               │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  STEP 1: Generate Training Data                                          │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐                    │
│  │  Synthetic  │ + │ Adversarial │ + │  AIT Real   │ = Training Data    │
│  │   8,000     │   │   1,000     │   │   3,000     │   (12,000 total)   │
│  └─────────────┘   └─────────────┘   └─────────────┘                    │
│                                                                          │
│  STEP 2: Fine-tune the Model                                             │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐              │
│  │ Llama 3.1   │  +   │  Training   │  =   │   Kodiak    │              │
│  │ 8B Base     │      │    Data     │      │  SecOps 1   │              │
│  └─────────────┘      └─────────────┘      └─────────────┘              │
│                                                                          │
│  STEP 3: Deploy & Use                                                    │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐              │
│  │    SIEM     │  →   │   Model     │  →   │  Analyst    │              │
│  │   Alerts    │      │   API       │      │  Dashboard  │              │
│  └─────────────┘      └─────────────┘      └─────────────┘              │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### Quick Commands

```bash
# 1. Setup (use devcontainer or install manually)
pip install -e ".[all]"

# 2. Generate training data
python -m soc_triage_agent.data_generator --num-samples 5000 --output data/train.jsonl

# 3. Train the model (adjust for your GPU)
python scripts/train.py \
    --model_name_or_path meta-llama/Llama-3.1-8B-Instruct \
    --train_file data/train.jsonl \
    --output_dir ./outputs/kodiak-secops-1 \
    --use_lora --use_4bit --gradient_checkpointing

# 4. Run the demo
python app.py
```

---

## Project Structure

Understanding where everything is:

```
kodiak-secops-1/
├── src/soc_triage_agent/          # 📦 Main Python package
│   ├── __init__.py                #    Package initialization
│   ├── data_generator.py          #    Creates synthetic training data
│   ├── adversarial.py             #    Generates challenging edge cases
│   ├── ait_dataset.py             #    Integrates real IDS alerts
│   ├── prompts.py                 #    Prompt templates and variants
│   ├── soar_adapters.py           #    SIEM/SOAR platform integrations
│   ├── feedback.py                #    Analyst feedback collection
│   └── evaluation.py              #    Model evaluation metrics
│
├── scripts/                       # 🔧 Utility scripts
│   ├── train.py                   #    Main training script
│   └── upload_to_hub.py           #    Upload to HuggingFace Hub
│
├── configs/                       # ⚙️ Configuration files
│   ├── train_lora.yaml            #    LoRA training config
│   └── train_qlora.yaml           #    QLoRA (4-bit) training config
│
├── data/                          # 📊 Training data (generated)
│   ├── train.jsonl                #    Training examples
│   ├── val.jsonl                  #    Validation examples
│   └── adversarial.jsonl          #    Adversarial examples
│
├── outputs/                       # 📤 Trained models (generated)
│   └── kodiak-secops-1/           #    Your trained model
│
├── app.py                         # 🌐 Gradio web interface
├── demo.py                        # 💻 CLI demo
├── pyproject.toml                 # 📋 Project dependencies
├── Dockerfile                     # 🐳 Container definition
└── .devcontainer/                 # 🛠️ VS Code dev container
```

### Key Files Explained

| File | What It Does | When You Use It |
|------|--------------|-----------------|
| `data_generator.py` | Creates synthetic security alerts with expert triage decisions | Before training to create your dataset |
| `adversarial.py` | Generates tricky edge cases to improve model robustness | After basic data generation |
| `train.py` | Runs the fine-tuning process on your GPU | When you're ready to train |
| `app.py` | Web UI to test the model interactively | After training to demo/test |
| `soar_adapters.py` | Connects to XSOAR, Splunk SOAR, etc. | For production integration |

---

## Glossary

Key terms explained for beginners:

### Machine Learning Terms

| Term | Simple Explanation | Analogy |
|------|-------------------|---------|
| **LLM** | Large Language Model - AI that understands and generates text | A very well-read assistant |
| **Fine-tuning** | Teaching a general AI to be an expert in a specific domain | Training a generalist doctor to be a cardiologist |
| **LoRA** | Efficient fine-tuning that only trains small adapter layers | Adding a specialty module instead of rebuilding the whole brain |
| **QLoRA** | LoRA with 4-bit compression for less memory usage | Same specialty module, but compressed to fit smaller devices |
| **Epoch** | One complete pass through all training data | Reading the entire textbook once |
| **Batch Size** | How many examples to process at once | Studying 4 flashcards at a time vs 16 |
| **Learning Rate** | How much to adjust the model from each example | Small = careful learning, Large = aggressive learning |
| **Gradient Checkpointing** | Trade speed for memory by recomputing instead of storing | Recalculating instead of taking notes |
| **VRAM** | GPU memory (Video RAM) | Your GPU's working memory |

### Security Terms

| Term | Simple Explanation | Example |
|------|-------------------|---------|
| **SOC** | Security Operations Center - team that monitors for threats | 24/7 security monitoring team |
| **SIEM** | Security Information and Event Management - collects logs | Splunk, Microsoft Sentinel, QRadar |
| **SOAR** | Security Orchestration and Automated Response - automates actions | XSOAR, Splunk SOAR, Tines |
| **IDS** | Intrusion Detection System - detects attacks | Suricata, Snort, Wazuh |
| **IOC** | Indicator of Compromise - evidence of attack | Malicious IP, file hash, domain |
| **Triage** | Prioritizing and categorizing security alerts | ER doctors prioritizing patients |
| **False Positive** | Alert that looks bad but isn't actually a threat | Fire alarm triggered by burnt toast |
| **Lateral Movement** | Attacker moving between systems after initial access | Burglar moving room to room |
| **C2/C&C** | Command and Control - attacker's remote control channel | Puppet master pulling strings |

### Training Data Terms

| Term | Simple Explanation |
|------|-------------------|
| **Synthetic Data** | Artificially generated training examples |
| **Adversarial Examples** | Intentionally tricky cases to challenge the model |
| **JSONL** | JSON Lines format - one JSON object per line |
| **Chat Format** | Training data formatted as conversation turns |

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

### How do I choose the right foundation model?

Choosing the right base model is critical. Here's a comprehensive guide:

#### Model Size vs. Hardware Requirements

| Model Size | Parameters | VRAM (LoRA) | VRAM (QLoRA) | Inference Speed | Quality |
|------------|------------|-------------|--------------|-----------------|---------|
| **3B** | 3 billion | 10GB | 6GB | Very Fast | Good |
| **7-8B** | 7-8 billion | 20GB | 10GB | Fast | Very Good |
| **13B** | 13 billion | 32GB | 16GB | Medium | Excellent |
| **70B** | 70 billion | 160GB | 48GB | Slow | Best |

#### Recommended Models by Use Case

**For Production (Best Quality + Reasonable Speed):**
```
meta-llama/Llama-3.1-8B-Instruct  ← Recommended default
```
- Best balance of quality, speed, and memory
- Well-tested, widely supported
- Strong instruction following

**For Limited Hardware (12-16GB VRAM):**
```
meta-llama/Llama-3.2-3B-Instruct
microsoft/Phi-3-mini-4k-instruct
```
- Smaller but still capable
- Fast inference
- Good for edge deployment

**For Maximum Quality (48GB+ VRAM or cloud):**
```
meta-llama/Llama-3.1-70B-Instruct
Qwen/Qwen2.5-72B-Instruct
```
- Best reasoning capabilities
- Requires multi-GPU or cloud
- Slower but most accurate

**For Specific Languages:**
```
Qwen/Qwen2.5-7B-Instruct      # Best for Chinese + English
mistralai/Mistral-7B-Instruct  # Strong European languages
```

#### Decision Flowchart

```
                    ┌─────────────────────────┐
                    │  What's your GPU VRAM?  │
                    └───────────┬─────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        ▼                       ▼                       ▼
   ┌─────────┐            ┌─────────┐            ┌─────────┐
   │  <16GB  │            │ 16-24GB │            │  >48GB  │
   └────┬────┘            └────┬────┘            └────┬────┘
        │                      │                      │
        ▼                      ▼                      ▼
┌───────────────┐      ┌───────────────┐      ┌───────────────┐
│ Llama 3.2 3B  │      │ Llama 3.1 8B  │      │ Llama 3.1 70B │
│    + QLoRA    │      │ + LoRA/QLoRA  │      │   + QLoRA     │
└───────────────┘      └───────────────┘      └───────────────┘
        │                      │                      │
        ▼                      ▼                      ▼
   Good quality          Best balance          Highest quality
   Fast inference        Recommended           Slower inference
```

#### Model Comparison for Security Tasks

| Model | Reasoning | Speed | Context | Security Knowledge | License |
|-------|-----------|-------|---------|-------------------|---------|
| **Llama 3.1 8B** | ★★★★☆ | ★★★★☆ | 128K | ★★★★☆ | Open (commercial OK) |
| **Llama 3.2 3B** | ★★★☆☆ | ★★★★★ | 128K | ★★★☆☆ | Open (commercial OK) |
| **Mistral 7B** | ★★★★☆ | ★★★★☆ | 32K | ★★★☆☆ | Apache 2.0 |
| **Phi-3 Mini** | ★★★☆☆ | ★★★★★ | 4K | ★★☆☆☆ | MIT |
| **Qwen2.5 7B** | ★★★★☆ | ★★★★☆ | 128K | ★★★★☆ | Apache 2.0 |
| **Llama 3.1 70B** | ★★★★★ | ★★☆☆☆ | 128K | ★★★★★ | Open (commercial OK) |

#### Key Factors to Consider

1. **VRAM Availability**
   - Check with `nvidia-smi`
   - Leave 2-4GB headroom for system
   - QLoRA roughly halves requirements

2. **Inference Latency Requirements**
   - Real-time triage: Use 3B-8B models
   - Batch processing: Can use larger models
   - Smaller = faster

3. **Quality Requirements**
   - Critical decisions: Use 8B+ models
   - High-volume triage: 3B may suffice
   - Test with your data!

4. **Context Length**
   - Most alerts: 1-2K tokens sufficient
   - Alert + full context: May need 4K+
   - Long investigation chains: 8K+

5. **Licensing**
   - Commercial use: Check model license
   - Llama: Requires Meta agreement
   - Mistral/Qwen: Apache 2.0 (permissive)

#### Practical Examples

**Example 1: Home Lab / Learning**
```bash
# RTX 3060 12GB - Use 3B with QLoRA
python scripts/train.py \
    --model_name_or_path meta-llama/Llama-3.2-3B-Instruct \
    --use_lora --use_4bit
```

**Example 2: Enterprise Workstation**
```bash
# RTX 4090 24GB - Use 8B with LoRA
python scripts/train.py \
    --model_name_or_path meta-llama/Llama-3.1-8B-Instruct \
    --use_lora --gradient_checkpointing
```

**Example 3: Cloud/Data Center**
```bash
# A100 80GB - Use 70B with QLoRA
python scripts/train.py \
    --model_name_or_path meta-llama/Llama-3.1-70B-Instruct \
    --use_lora --use_4bit
```

#### Where to Find Models

All models available on HuggingFace:
- **Llama models**: [meta-llama](https://huggingface.co/meta-llama) (requires access request)
- **Mistral models**: [mistralai](https://huggingface.co/mistralai)
- **Qwen models**: [Qwen](https://huggingface.co/Qwen)
- **Phi models**: [microsoft](https://huggingface.co/microsoft)

To request Llama access:
1. Go to [meta-llama/Llama-3.1-8B-Instruct](https://huggingface.co/meta-llama/Llama-3.1-8B-Instruct)
2. Click "Request access"
3. Fill out the form (usually approved within hours)
4. Run `huggingface-cli login` with your token

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

model = SOCTriageModel.from_pretrained("fmt0816/kodiak-secops-1")

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
python demo.py --model fmt0816/kodiak-secops-1
```

**Web Interface:**
```bash
python app.py --model fmt0816/kodiak-secops-1
# Open http://localhost:7860
```

### How do I integrate with my SIEM/SOAR?

We provide adapters for common platforms:

**Palo Alto XSOAR:**
```python
from soc_triage_agent import get_adapter, SOCTriageModel

adapter = get_adapter("xsoar", "https://xsoar.company.com", api_key="...")
model = SOCTriageModel.from_pretrained("fmt0816/kodiak-secops-1")

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
    "fmt0816/kodiak-secops-1",
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
    "fmt0816/kodiak-secops-1",
    load_in_8bit=True
)
```

### CUDA out of memory during inference

**Cause**: Model too large for GPU

**Fix**:
```python
# Quantize to 4-bit
model = SOCTriageModel.from_pretrained(
    "fmt0816/kodiak-secops-1",
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

## Common Mistakes

Avoid these pitfalls that trip up first-time users:

### Training Mistakes

| Mistake | Why It's Wrong | How to Fix |
|---------|---------------|------------|
| Using batch size 4+ on consumer GPU | Causes out-of-memory errors | Use `--per_device_train_batch_size 1` with `--gradient_accumulation_steps 16` |
| Forgetting `--gradient_checkpointing` | Uses 2x more memory | Always add this flag on GPUs < 48GB |
| Training without validation data | Can't detect overfitting | Always create a validation set |
| Using max sequence length 4096 | Wastes memory on short examples | Use `--max_seq_length 1024` or 2048 |
| Not using `--use_4bit` on smaller GPUs | Won't fit in memory | Add this for GPUs < 20GB |

### Data Generation Mistakes

| Mistake | Why It's Wrong | How to Fix |
|---------|---------------|------------|
| Generating only 100 examples | Model won't learn patterns | Generate 5,000+ examples minimum |
| Not including adversarial data | Model fails on edge cases | Add 10% adversarial examples |
| Imbalanced categories | Model biased toward common categories | Use `--balanced` flag |
| Not validating JSONL format | Training will crash | Check file with `python -m json.tool --json-lines data/train.jsonl` |

### Deployment Mistakes

| Mistake | Why It's Wrong | How to Fix |
|---------|---------------|------------|
| Trusting model decisions blindly | Models can hallucinate | Always have human review for escalations |
| Not sanitizing inputs | Prompt injection vulnerability | Clean alert text before inference |
| Loading full model for inference | Uses unnecessary memory | Use `load_in_4bit=True` or `load_in_8bit=True` |
| Running on CPU | Extremely slow inference | Use GPU or cloud GPU instance |

### Understanding Training Output

When training, watch for these indicators:

```
✅ GOOD SIGNS:
- Training loss decreasing steadily (e.g., 2.5 → 1.8 → 1.2)
- Validation loss decreasing (not just training loss)
- No NaN or inf in loss values

❌ BAD SIGNS:
- Loss stuck at same value → Learning rate too low or data issue
- Loss exploding (going up) → Learning rate too high
- Training loss decreasing but val loss increasing → Overfitting
- NaN loss → Data formatting issue or learning rate too high
```

### Example Training Run Interpretation

```
Step 100: loss=2.45, lr=1.8e-05  ← Starting to learn
Step 200: loss=1.82, lr=1.9e-05  ← Good progress
Step 300: loss=1.54, lr=2.0e-05  ← Still improving
Step 400: loss=1.31, lr=1.9e-05  ← Great!
Step 500: loss=1.28, lr=1.8e-05  ← Converging (slowing down is normal)
...
Step 1000: loss=0.95  ← Model is well-trained
```

### How to Know If Training Worked

After training, test with known examples:

```python
# Test with obvious cases first
test_cases = [
    # Should escalate (obvious threat)
    {"category": "malware", "severity": "critical",
     "title": "Ransomware encrypting files"},

    # Should be false positive (obvious benign)
    {"category": "policy_violation", "severity": "low",
     "title": "Admin accessed server during maintenance window"},
]

for case in test_cases:
    result = model.predict(case)
    print(f"{case['title']}: {result.decision} (P{result.priority})")
```

If the model gets obvious cases wrong, more training is needed.

---

## Step-by-Step Example: Training Your First Model

Complete walkthrough for absolute beginners:

### Prerequisites Checklist

- [ ] NVIDIA GPU with 12GB+ VRAM
- [ ] CUDA installed (`nvidia-smi` should work)
- [ ] Python 3.10+
- [ ] HuggingFace account (for downloading Llama)
- [ ] ~50GB free disk space

### Step 1: Environment Setup (10 minutes)

```bash
# Clone the repository
git clone https://github.com/fmt0816/kodiak-secops-1.git
cd kodiak-secops-1

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# OR: venv\Scripts\activate  # Windows

# Install dependencies
pip install -e ".[all]"

# Login to HuggingFace (needed for Llama)
huggingface-cli login
# Enter your token from https://huggingface.co/settings/tokens
```

### Step 2: Generate Training Data (5 minutes)

```bash
# Create data directory
mkdir -p data

# Generate synthetic training data
python -m soc_triage_agent.data_generator \
    --num-samples 5000 \
    --format chat \
    --output data/train.jsonl \
    --balanced

# Generate validation data
python -m soc_triage_agent.data_generator \
    --num-samples 500 \
    --format chat \
    --output data/val.jsonl \
    --balanced

# Verify data was created
wc -l data/*.jsonl
# Should show: 5000 train.jsonl, 500 val.jsonl
```

### Step 3: Start Training (2-6 hours depending on GPU)

```bash
# For RTX 3080/3090/4080/4090 (12-24GB VRAM)
python scripts/train.py \
    --model_name_or_path meta-llama/Llama-3.1-8B-Instruct \
    --train_file data/train.jsonl \
    --validation_file data/val.jsonl \
    --output_dir ./outputs/my-first-model \
    --use_lora \
    --use_4bit \
    --lora_r 32 \
    --lora_alpha 64 \
    --per_device_train_batch_size 1 \
    --gradient_accumulation_steps 16 \
    --gradient_checkpointing \
    --max_seq_length 1024 \
    --num_train_epochs 3 \
    --learning_rate 2e-4 \
    --logging_steps 10 \
    --save_steps 500

# Monitor GPU usage in another terminal
watch -n 1 nvidia-smi
```

### Step 4: Test Your Model (5 minutes)

```bash
# Run the web interface
python app.py --model ./outputs/my-first-model

# Open browser to http://localhost:7860
# Try entering a sample alert to test
```

### Step 5: Celebrate! 🎉

You've just fine-tuned a security AI model!

---

## Still Have Questions?

- **Issues**: [GitHub Issues](https://github.com/fmt0816/kodiak-secops-1/issues)
- **Model**: [HuggingFace Model Page](https://huggingface.co/fmt0816/kodiak-secops-1)
- **Dataset**: [HuggingFace Dataset Page](https://huggingface.co/datasets/fmt0816/kodiak-secops-1-dataset)

---

*This FAQ is part of the Kodiak SecOps 1 project. Licensed under Apache 2.0.*
