# =============================================================================
# SOC Triage Agent - Optimized Training Container
# =============================================================================
# Base: NVIDIA PyTorch NGC Container (optimized for A100/H100/RTX GPUs)
# Includes: CUDA 12.x, cuDNN 9, NCCL, PyTorch 2.4+, Flash Attention
# =============================================================================

# -----------------------------------------------------------------------------
# Option 1: NVIDIA NGC PyTorch (Recommended for Training)
# Best performance, includes all NVIDIA optimizations
# Requires: NGC account (free) or use nvcr.io/nvidia/pytorch
# -----------------------------------------------------------------------------
FROM nvcr.io/nvidia/pytorch:24.08-py3

# -----------------------------------------------------------------------------
# Option 2: Hugging Face Training Container (Alternative)
# Uncomment below and comment out Option 1 if you prefer HF's container
# -----------------------------------------------------------------------------
# FROM huggingface/transformers-pytorch-gpu:latest

# -----------------------------------------------------------------------------
# Option 3: Lightweight CUDA base (Smaller image, manual setup)
# Uncomment below for minimal CUDA environment
# -----------------------------------------------------------------------------
# FROM nvidia/cuda:12.4.1-cudnn-devel-ubuntu22.04

LABEL maintainer="SOC Triage Agent Contributors"
LABEL description="Optimized container for fine-tuning LLMs for security alert triage"

# Environment variables for optimal training
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # CUDA optimizations
    CUDA_DEVICE_ORDER=PCI_BUS_ID \
    NCCL_DEBUG=WARN \
    NCCL_IB_DISABLE=0 \
    NCCL_NET_GDR_LEVEL=2 \
    # PyTorch optimizations
    TORCH_CUDA_ARCH_LIST="8.0;8.6;8.9;9.0" \
    PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
    # Transformers/HF settings
    TRANSFORMERS_CACHE=/workspace/.cache/huggingface \
    HF_HOME=/workspace/.cache/huggingface \
    HF_DATASETS_CACHE=/workspace/.cache/huggingface/datasets \
    # Flash Attention
    FLASH_ATTENTION_FORCE_BUILD=FALSE \
    MAX_JOBS=4

WORKDIR /workspace

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    git-lfs \
    curl \
    wget \
    vim \
    htop \
    nvtop \
    tmux \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Initialize git-lfs
RUN git lfs install

# Upgrade pip and install build tools
RUN pip install --upgrade pip setuptools wheel

# -----------------------------------------------------------------------------
# Install core ML dependencies (optimized versions)
# -----------------------------------------------------------------------------
RUN pip install --no-cache-dir \
    # Core ML
    torch>=2.4.0 \
    transformers>=4.44.0 \
    datasets>=2.20.0 \
    accelerate>=0.33.0 \
    # LoRA/QLoRA
    peft>=0.12.0 \
    bitsandbytes>=0.43.0 \
    # Flash Attention 2 (pre-built wheels for faster install)
    flash-attn>=2.6.0 --no-build-isolation \
    # Distributed training
    deepspeed>=0.14.0 \
    # Experiment tracking
    wandb>=0.17.0 \
    tensorboard>=2.17.0 \
    # Serving
    vllm>=0.5.0 \
    # Utilities
    safetensors>=0.4.0 \
    sentencepiece>=0.2.0 \
    protobuf>=4.25.0 \
    scipy \
    ninja \
    packaging

# Install Hugging Face CLI
RUN pip install --no-cache-dir huggingface_hub[cli]>=0.24.0

# -----------------------------------------------------------------------------
# Install development tools
# -----------------------------------------------------------------------------
RUN pip install --no-cache-dir \
    pytest>=8.0.0 \
    pytest-cov>=5.0.0 \
    black>=24.0.0 \
    ruff>=0.5.0 \
    mypy>=1.10.0 \
    ipython \
    jupyter \
    rich

# Create cache directories
RUN mkdir -p /workspace/.cache/huggingface \
    /workspace/.cache/torch \
    /workspace/.cache/wandb \
    /workspace/data \
    /workspace/outputs

# Copy project files (will be overridden by mount in devcontainer)
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install the package in development mode
RUN pip install -e ".[train,dev]" || true

# Default command
CMD ["bash"]
