#!/usr/bin/env python3
"""Training Script for SOC Triage Agent.
=====================================

Fine-tune language models for security alert triage using
Hugging Face Transformers and PEFT (LoRA).

Supports:
- Full fine-tuning
- LoRA/QLoRA fine-tuning
- DeepSpeed integration
- Weights & Biases logging
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import torch


def validate_data_files(train_file: str, validation_file: Optional[str] = None) -> None:
    """Validate that training data files exist and are valid JSONL.

    Args:
        train_file: Path to training data file
        validation_file: Optional path to validation data file

    Raises:
        FileNotFoundError: If files don't exist
        ValueError: If files are not valid JSONL

    """
    train_path = Path(train_file)
    if not train_path.exists():
        raise FileNotFoundError(f"Training file not found: {train_file}")

    if not train_path.is_file():
        raise ValueError(f"Training path is not a file: {train_file}")

    # Validate JSONL format by reading first line
    try:
        with open(train_path) as f:
            first_line = f.readline().strip()
            if first_line:
                data = json.loads(first_line)
                if "messages" not in data and "text" not in data:
                    raise ValueError(
                        f"Training file must have 'messages' or 'text' field: {train_file}"
                    )
    except json.JSONDecodeError as e:
        raise ValueError(f"Training file is not valid JSONL: {train_file} - {e}") from e

    if validation_file:
        val_path = Path(validation_file)
        if not val_path.exists():
            raise FileNotFoundError(f"Validation file not found: {validation_file}")

        if not val_path.is_file():
            raise ValueError(f"Validation path is not a file: {validation_file}")

        try:
            with open(val_path) as f:
                first_line = f.readline().strip()
                if first_line:
                    json.loads(first_line)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"Validation file is not valid JSONL: {validation_file} - {e}"
            ) from e

    print(f"✓ Training file validated: {train_file}")
    if validation_file:
        print(f"✓ Validation file validated: {validation_file}")
from datasets import Dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    DataCollatorForSeq2Seq,
    Trainer,
    TrainingArguments,
    set_seed,
)
from transformers.trainer_utils import get_last_checkpoint

# Optional imports
try:
    from peft import (
        LoraConfig,
        TaskType,
        get_peft_model,
        prepare_model_for_kbit_training,
    )

    PEFT_AVAILABLE = True
except ImportError:
    PEFT_AVAILABLE = False
    print("PEFT not available. Install with: pip install peft")

import importlib.util

WANDB_AVAILABLE = importlib.util.find_spec("wandb") is not None


@dataclass
class ModelArguments:
    """Arguments for model configuration."""

    model_name_or_path: str = field(
        metadata={"help": "Path to pretrained model or model identifier from huggingface.co/models"}
    )
    tokenizer_name: Optional[str] = field(
        default=None, metadata={"help": "Pretrained tokenizer name or path if different from model"}
    )
    use_flash_attention_2: bool = field(
        default=True, metadata={"help": "Whether to use Flash Attention 2"}
    )
    trust_remote_code: bool = field(default=True, metadata={"help": "Whether to trust remote code"})


@dataclass
class DataArguments:
    """Arguments for data configuration."""

    train_file: str = field(metadata={"help": "Path to training data (JSONL format)"})
    validation_file: Optional[str] = field(
        default=None, metadata={"help": "Path to validation data (JSONL format)"}
    )
    max_seq_length: int = field(default=4096, metadata={"help": "Maximum sequence length"})
    preprocessing_num_workers: int = field(
        default=4, metadata={"help": "Number of workers for data preprocessing"}
    )


@dataclass
class LoraArguments:
    """Arguments for LoRA configuration."""

    use_lora: bool = field(default=True, metadata={"help": "Whether to use LoRA for training"})
    lora_r: int = field(default=64, metadata={"help": "LoRA rank"})
    lora_alpha: int = field(default=128, metadata={"help": "LoRA alpha"})
    lora_dropout: float = field(default=0.05, metadata={"help": "LoRA dropout"})
    lora_target_modules: str = field(
        default="q_proj,k_proj,v_proj,o_proj,gate_proj,up_proj,down_proj",
        metadata={"help": "Comma-separated list of target modules for LoRA"},
    )
    use_4bit: bool = field(
        default=False, metadata={"help": "Whether to use 4-bit quantization (QLoRA)"}
    )
    use_8bit: bool = field(default=False, metadata={"help": "Whether to use 8-bit quantization"})


def load_and_prepare_data(
    tokenizer,
    data_args: DataArguments,
    training_args: TrainingArguments,
) -> tuple:
    """Load and preprocess training data."""

    def load_jsonl(file_path: str) -> Dataset:
        """Load JSONL file into Dataset."""
        data = []
        with open(file_path) as f:
            for line in f:
                data.append(json.loads(line))
        return Dataset.from_list(data)

    # Load datasets
    train_dataset = load_jsonl(data_args.train_file)
    print(f"Loaded {len(train_dataset)} training samples")

    eval_dataset = None
    if data_args.validation_file:
        eval_dataset = load_jsonl(data_args.validation_file)
        print(f"Loaded {len(eval_dataset)} validation samples")

    def preprocess_function(examples):
        """Tokenize and prepare training examples."""
        # Handle chat format
        if "messages" in examples:
            texts = []
            for messages in examples["messages"]:
                # Apply chat template
                if hasattr(tokenizer, "apply_chat_template"):
                    text = tokenizer.apply_chat_template(
                        messages,
                        tokenize=False,
                        add_generation_prompt=False,
                    )
                else:
                    # Fallback for tokenizers without chat template
                    text = ""
                    for msg in messages:
                        role = msg["role"]
                        content = msg["content"]
                        text += f"<|{role}|>\n{content}\n"
                texts.append(text)
        elif "text" in examples:
            texts = examples["text"]
        else:
            raise ValueError("Dataset must have 'messages' or 'text' field")

        # Tokenize
        tokenized = tokenizer(
            texts,
            truncation=True,
            max_length=data_args.max_seq_length,
            padding=False,
            return_tensors=None,
        )

        # Set labels for causal LM
        tokenized["labels"] = tokenized["input_ids"].copy()

        return tokenized

    # Preprocess datasets
    train_dataset = train_dataset.map(
        preprocess_function,
        batched=True,
        num_proc=data_args.preprocessing_num_workers,
        remove_columns=train_dataset.column_names,
        desc="Tokenizing training data",
    )

    if eval_dataset:
        eval_dataset = eval_dataset.map(
            preprocess_function,
            batched=True,
            num_proc=data_args.preprocessing_num_workers,
            remove_columns=eval_dataset.column_names,
            desc="Tokenizing validation data",
        )

    return train_dataset, eval_dataset


def create_model_and_tokenizer(
    model_args: ModelArguments,
    lora_args: LoraArguments,
    training_args: TrainingArguments,
):
    """Load model and tokenizer with optional quantization."""
    # Load tokenizer
    tokenizer = AutoTokenizer.from_pretrained(
        model_args.tokenizer_name or model_args.model_name_or_path,
        trust_remote_code=model_args.trust_remote_code,
        padding_side="right",
    )

    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    # Prepare quantization config
    quantization_config = None
    if lora_args.use_4bit:
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
            bnb_4bit_quant_type="nf4",
        )
    elif lora_args.use_8bit:
        quantization_config = BitsAndBytesConfig(
            load_in_8bit=True,
        )

    # Load model
    model_kwargs = {
        "trust_remote_code": model_args.trust_remote_code,
        "torch_dtype": torch.bfloat16,
    }

    if quantization_config:
        model_kwargs["quantization_config"] = quantization_config
        model_kwargs["device_map"] = "auto"

    if model_args.use_flash_attention_2:
        model_kwargs["attn_implementation"] = "flash_attention_2"

    print(f"Loading model: {model_args.model_name_or_path}")
    model = AutoModelForCausalLM.from_pretrained(
        model_args.model_name_or_path,
        **model_kwargs,
    )

    # Prepare for k-bit training if needed
    if quantization_config and PEFT_AVAILABLE:
        model = prepare_model_for_kbit_training(
            model,
            use_gradient_checkpointing=training_args.gradient_checkpointing,
        )

    # Apply LoRA if requested
    if lora_args.use_lora and PEFT_AVAILABLE:
        print("Applying LoRA configuration...")

        target_modules = lora_args.lora_target_modules.split(",")

        lora_config = LoraConfig(
            r=lora_args.lora_r,
            lora_alpha=lora_args.lora_alpha,
            lora_dropout=lora_args.lora_dropout,
            target_modules=target_modules,
            bias="none",
            task_type=TaskType.CAUSAL_LM,
        )

        model = get_peft_model(model, lora_config)
        model.print_trainable_parameters()

    # Enable gradient checkpointing
    if training_args.gradient_checkpointing:
        model.gradient_checkpointing_enable()
        model.config.use_cache = False

    return model, tokenizer


def main():
    parser = argparse.ArgumentParser(description="Train SOC Triage Model")

    # Add argument groups
    parser.add_argument(
        "--model_name_or_path", type=str, required=True, help="Base model to fine-tune"
    )
    parser.add_argument("--train_file", type=str, required=True, help="Training data file (JSONL)")
    parser.add_argument(
        "--validation_file", type=str, default=None, help="Validation data file (JSONL)"
    )
    parser.add_argument("--output_dir", type=str, required=True, help="Output directory for model")

    # Training parameters
    parser.add_argument("--num_train_epochs", type=int, default=3)
    parser.add_argument("--per_device_train_batch_size", type=int, default=4)
    parser.add_argument("--per_device_eval_batch_size", type=int, default=4)
    parser.add_argument("--gradient_accumulation_steps", type=int, default=4)
    parser.add_argument("--learning_rate", type=float, default=2e-5)
    parser.add_argument("--warmup_ratio", type=float, default=0.1)
    parser.add_argument("--max_seq_length", type=int, default=4096)
    parser.add_argument("--gradient_checkpointing", action="store_true")

    # LoRA parameters
    parser.add_argument("--use_lora", action="store_true", default=True)
    parser.add_argument("--lora_r", type=int, default=64)
    parser.add_argument("--lora_alpha", type=int, default=128)
    parser.add_argument("--lora_dropout", type=float, default=0.05)
    parser.add_argument("--use_4bit", action="store_true")
    parser.add_argument("--use_8bit", action="store_true")

    # Other options
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--bf16", action="store_true", default=True)
    parser.add_argument("--logging_steps", type=int, default=10)
    parser.add_argument("--save_steps", type=int, default=500)
    parser.add_argument("--eval_steps", type=int, default=500)
    parser.add_argument("--save_total_limit", type=int, default=3)
    parser.add_argument("--push_to_hub", action="store_true")
    parser.add_argument("--hub_model_id", type=str, default=None)
    parser.add_argument("--report_to", type=str, default="tensorboard")
    parser.add_argument("--resume_from_checkpoint", type=str, default=None)

    args = parser.parse_args()

    # Validate data files before proceeding
    validate_data_files(args.train_file, args.validation_file)

    # Set seed
    set_seed(args.seed)

    # Create argument objects
    model_args = ModelArguments(
        model_name_or_path=args.model_name_or_path,
    )

    data_args = DataArguments(
        train_file=args.train_file,
        validation_file=args.validation_file,
        max_seq_length=args.max_seq_length,
    )

    lora_args = LoraArguments(
        use_lora=args.use_lora,
        lora_r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        use_4bit=args.use_4bit,
        use_8bit=args.use_8bit,
    )

    # Training arguments
    training_args = TrainingArguments(
        output_dir=args.output_dir,
        num_train_epochs=args.num_train_epochs,
        per_device_train_batch_size=args.per_device_train_batch_size,
        per_device_eval_batch_size=args.per_device_eval_batch_size,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        learning_rate=args.learning_rate,
        warmup_ratio=args.warmup_ratio,
        gradient_checkpointing=args.gradient_checkpointing,
        bf16=args.bf16,
        logging_steps=args.logging_steps,
        save_steps=args.save_steps,
        eval_strategy="steps" if args.validation_file else "no",
        eval_steps=args.eval_steps if args.validation_file else None,
        save_total_limit=args.save_total_limit,
        load_best_model_at_end=bool(args.validation_file),
        report_to=args.report_to,
        push_to_hub=args.push_to_hub,
        hub_model_id=args.hub_model_id,
        seed=args.seed,
        optim="adamw_torch",
        lr_scheduler_type="cosine",
        remove_unused_columns=False,
    )

    # Create model and tokenizer
    model, tokenizer = create_model_and_tokenizer(model_args, lora_args, training_args)

    # Load and prepare data
    train_dataset, eval_dataset = load_and_prepare_data(tokenizer, data_args, training_args)

    # Data collator
    data_collator = DataCollatorForSeq2Seq(
        tokenizer=tokenizer,
        model=model,
        padding=True,
        pad_to_multiple_of=8,
    )

    # Check for checkpoint
    last_checkpoint = None
    if os.path.isdir(args.output_dir) and not args.resume_from_checkpoint:
        last_checkpoint = get_last_checkpoint(args.output_dir)
        if last_checkpoint:
            print(f"Checkpoint detected, resuming from {last_checkpoint}")

    if args.resume_from_checkpoint:
        last_checkpoint = args.resume_from_checkpoint

    # Initialize trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        data_collator=data_collator,
        tokenizer=tokenizer,
    )

    # Train
    print("Starting training...")
    train_result = trainer.train(resume_from_checkpoint=last_checkpoint)

    # Save model
    print("Saving model...")
    trainer.save_model()
    tokenizer.save_pretrained(args.output_dir)

    # Save training metrics
    metrics = train_result.metrics
    trainer.log_metrics("train", metrics)
    trainer.save_metrics("train", metrics)
    trainer.save_state()

    # Evaluate
    if eval_dataset:
        print("Evaluating...")
        eval_metrics = trainer.evaluate()
        trainer.log_metrics("eval", eval_metrics)
        trainer.save_metrics("eval", eval_metrics)

    # Push to hub
    if args.push_to_hub:
        print("Pushing to Hub...")
        trainer.push_to_hub()

    print("Training complete!")
    print(f"Model saved to: {args.output_dir}")


if __name__ == "__main__":
    main()
