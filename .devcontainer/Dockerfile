# =============================================================================
# SOC Triage Agent - Training Container
# =============================================================================
# Base: NVIDIA PyTorch NGC Container (optimized for RTX/A100/H100 GPUs)
# Includes: CUDA 12.x, cuDNN 9, NCCL, PyTorch 2.4+
# =============================================================================

FROM nvcr.io/nvidia/pytorch:24.08-py3

LABEL maintainer="SOC Triage Agent Contributors"
LABEL description="Container for fine-tuning LLMs for security alert triage"

# Environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # CUDA optimizations
    CUDA_DEVICE_ORDER=PCI_BUS_ID \
    # PyTorch optimizations
    PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
    # Transformers/HF settings
    TRANSFORMERS_CACHE=/workspace/.cache/huggingface \
    HF_HOME=/workspace/.cache/huggingface \
    HF_DATASETS_CACHE=/workspace/.cache/huggingface/datasets

WORKDIR /workspace

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    git-lfs \
    curl \
    wget \
    vim \
    htop \
    tmux \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && git lfs install

# Upgrade pip
RUN pip install --upgrade pip setuptools wheel

# -----------------------------------------------------------------------------
# Install core dependencies (fast, no compilation required)
# -----------------------------------------------------------------------------
RUN pip install --no-cache-dir \
    transformers>=4.44.0 \
    datasets>=2.20.0 \
    accelerate>=0.33.0 \
    peft>=0.12.0 \
    bitsandbytes>=0.43.0 \
    safetensors>=0.4.0 \
    sentencepiece>=0.2.0 \
    protobuf>=4.25.0 \
    wandb>=0.17.0 \
    tensorboard>=2.17.0 \
    scipy \
    packaging \
    huggingface_hub[cli]>=0.24.0

# Install development tools
RUN pip install --no-cache-dir \
    pytest>=8.0.0 \
    pytest-cov>=5.0.0 \
    black>=24.0.0 \
    ruff>=0.5.0 \
    ipython \
    rich

# Create cache directories
RUN mkdir -p /workspace/.cache/huggingface \
    /workspace/.cache/torch \
    /workspace/data \
    /workspace/outputs

# Default command
CMD ["bash"]
