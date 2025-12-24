#!/bin/bash
# =============================================================================
# Post-create script for SOC Triage Agent devcontainer
# =============================================================================

set -e

echo "=== Installing SOC Triage Agent in development mode ==="
pip install -e ".[dev]"

echo ""
echo "=== Container setup complete! ==="
echo ""
echo "Optional: Install additional training dependencies:"
echo "  pip install deepspeed       # For distributed training"
echo "  pip install flash-attn      # For Flash Attention 2 (requires compilation)"
echo ""
echo "Quick start:"
echo "  python -m soc_triage_agent.data_generator --num-samples 100 --output data/train.jsonl"
echo "  pytest tests/"
echo ""
