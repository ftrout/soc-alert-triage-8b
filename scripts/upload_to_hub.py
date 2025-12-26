#!/usr/bin/env python3
"""Upload Kodiak SecOps 1 model and dataset to HuggingFace Hub.

This script handles uploading trained models and generated datasets to
the HuggingFace Hub with proper configuration and documentation.

Usage:
    # Upload model
    python scripts/upload_to_hub.py model --model-path ./outputs/kodiak-secops-1

    # Upload dataset
    python scripts/upload_to_hub.py dataset --data-path ./data/train.jsonl

    # Upload both
    python scripts/upload_to_hub.py all --model-path ./outputs/kodiak-secops-1 --data-path ./data

    # Dry run (show what would be uploaded)
    python scripts/upload_to_hub.py model --model-path ./outputs/kodiak-secops-1 --dry-run

Requirements:
    pip install huggingface_hub

Authentication:
    Set HF_TOKEN environment variable or run `huggingface-cli login`

"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# Repository configuration
MODEL_REPO_ID = "ftrout/kodiak-secops-1"
DATASET_REPO_ID = "ftrout/kodiak-secops-1-dataset"

# Files to include with model
MODEL_FILES = [
    "*.safetensors",
    "*.bin",
    "*.json",
    "*.txt",
    "*.model",
    "tokenizer*",
    "special_tokens_map.json",
    "vocab.*",
    "merges.txt",
]

# Files to exclude
EXCLUDE_PATTERNS = [
    "*.pyc",
    "__pycache__",
    ".git",
    ".DS_Store",
    "*.log",
    "optimizer.pt",
    "scheduler.pt",
    "trainer_state.json",
    "training_args.bin",
]


def check_auth() -> str:
    """Check HuggingFace authentication and return token."""
    try:
        from huggingface_hub import HfApi

        api = HfApi()
        token = os.environ.get("HF_TOKEN")

        if token:
            # Validate token
            user_info = api.whoami(token=token)
            logger.info(f"Authenticated as: {user_info['name']}")
            return token
        else:
            # Try cached credentials
            user_info = api.whoami()
            logger.info(f"Authenticated as: {user_info['name']} (cached credentials)")
            return None  # Use cached token

    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        logger.error("Please set HF_TOKEN environment variable or run: huggingface-cli login")
        sys.exit(1)


def upload_model(
    model_path: str,
    repo_id: str = MODEL_REPO_ID,
    commit_message: str = "Update model",
    private: bool = False,
    dry_run: bool = False,
) -> None:
    """Upload model to HuggingFace Hub."""
    from huggingface_hub import HfApi, create_repo

    model_dir = Path(model_path)
    if not model_dir.exists():
        logger.error(f"Model path does not exist: {model_path}")
        sys.exit(1)

    token = check_auth()
    api = HfApi()

    # Check what files will be uploaded
    files_to_upload = []
    for pattern in MODEL_FILES:
        files_to_upload.extend(model_dir.glob(pattern))

    # Also include adapter files for LoRA models
    adapter_files = list(model_dir.glob("adapter_*.safetensors")) + list(
        model_dir.glob("adapter_*.bin")
    )
    files_to_upload.extend(adapter_files)

    # Remove duplicates and sort
    files_to_upload = sorted(set(files_to_upload))

    if not files_to_upload:
        logger.error(f"No model files found in {model_path}")
        logger.info("Expected files: " + ", ".join(MODEL_FILES))
        sys.exit(1)

    logger.info(f"Found {len(files_to_upload)} files to upload:")
    for f in files_to_upload:
        size_mb = f.stat().st_size / (1024 * 1024)
        logger.info(f"  - {f.name} ({size_mb:.2f} MB)")

    if dry_run:
        logger.info("[DRY RUN] Would upload to: " + repo_id)
        return

    # Create repo if it doesn't exist
    try:
        create_repo(
            repo_id=repo_id,
            token=token,
            private=private,
            repo_type="model",
            exist_ok=True,
        )
        logger.info(f"Repository ready: {repo_id}")
    except Exception as e:
        logger.warning(f"Could not create/verify repo: {e}")

    # Upload README (MODEL_CARD.md)
    model_card_path = Path(__file__).parent.parent / "MODEL_CARD.md"
    if model_card_path.exists():
        logger.info("Uploading MODEL_CARD.md as README.md...")
        api.upload_file(
            path_or_fileobj=str(model_card_path),
            path_in_repo="README.md",
            repo_id=repo_id,
            repo_type="model",
            token=token,
            commit_message="Update model card",
        )

    # Upload model files
    logger.info(f"Uploading model files to {repo_id}...")
    api.upload_folder(
        folder_path=str(model_dir),
        repo_id=repo_id,
        repo_type="model",
        token=token,
        commit_message=commit_message,
        ignore_patterns=EXCLUDE_PATTERNS,
    )

    logger.info(f"✓ Model uploaded successfully to: https://huggingface.co/{repo_id}")


def upload_dataset(
    data_path: str,
    repo_id: str = DATASET_REPO_ID,
    commit_message: str = "Update dataset",
    private: bool = False,
    dry_run: bool = False,
) -> None:
    """Upload dataset to HuggingFace Hub."""
    from huggingface_hub import HfApi, create_repo

    data_dir = Path(data_path)

    token = check_auth()
    api = HfApi()

    # Find data files
    if data_dir.is_file():
        files_to_upload = [data_dir]
        data_dir = data_dir.parent
    else:
        files_to_upload = (
            list(data_dir.glob("*.jsonl"))
            + list(data_dir.glob("*.json"))
            + list(data_dir.glob("*.parquet"))
            + list(data_dir.glob("*.csv"))
        )

    if not files_to_upload:
        logger.error(f"No data files found in {data_path}")
        sys.exit(1)

    logger.info(f"Found {len(files_to_upload)} data files:")
    total_size = 0
    for f in files_to_upload:
        size_mb = f.stat().st_size / (1024 * 1024)
        total_size += size_mb
        # Count lines for JSONL files
        if f.suffix == ".jsonl":
            with open(f) as fp:
                line_count = sum(1 for _ in fp)
            logger.info(f"  - {f.name} ({size_mb:.2f} MB, {line_count:,} examples)")
        else:
            logger.info(f"  - {f.name} ({size_mb:.2f} MB)")

    logger.info(f"Total size: {total_size:.2f} MB")

    if dry_run:
        logger.info("[DRY RUN] Would upload to: " + repo_id)
        return

    # Create repo if it doesn't exist
    try:
        create_repo(
            repo_id=repo_id,
            token=token,
            private=private,
            repo_type="dataset",
            exist_ok=True,
        )
        logger.info(f"Repository ready: {repo_id}")
    except Exception as e:
        logger.warning(f"Could not create/verify repo: {e}")

    # Upload README (DATASET_CARD.md)
    dataset_card_path = Path(__file__).parent.parent / "DATASET_CARD.md"
    if dataset_card_path.exists():
        logger.info("Uploading DATASET_CARD.md as README.md...")
        api.upload_file(
            path_or_fileobj=str(dataset_card_path),
            path_in_repo="README.md",
            repo_id=repo_id,
            repo_type="dataset",
            token=token,
            commit_message="Update dataset card",
        )

    # Upload data files
    for data_file in files_to_upload:
        logger.info(f"Uploading {data_file.name}...")
        api.upload_file(
            path_or_fileobj=str(data_file),
            path_in_repo=f"data/{data_file.name}",
            repo_id=repo_id,
            repo_type="dataset",
            token=token,
            commit_message=commit_message,
        )

    logger.info(f"✓ Dataset uploaded successfully to: https://huggingface.co/datasets/{repo_id}")


def generate_and_upload_dataset(
    num_samples: int = 10000,
    repo_id: str = DATASET_REPO_ID,
    include_adversarial: bool = True,
    dry_run: bool = False,
) -> None:
    """Generate synthetic dataset and upload to HuggingFace Hub."""
    import tempfile

    from soc_triage_agent import AdversarialGenerator, SecurityAlertGenerator

    logger.info(f"Generating {num_samples} training examples...")

    generator = SecurityAlertGenerator()

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "train.jsonl"

        # Generate main dataset
        samples = []
        for i in range(num_samples):
            alert, triage = generator.generate_alert()
            sample = generator.format_for_training(alert, triage, format_type="chat")
            samples.append(sample)

            if (i + 1) % 1000 == 0:
                logger.info(f"  Generated {i + 1}/{num_samples} examples...")

        # Add adversarial examples
        if include_adversarial:
            logger.info("Generating adversarial examples...")
            adv_generator = AdversarialGenerator()
            adv_examples = adv_generator.generate_hard_cases(num_samples=500)
            adv_samples = adv_generator.to_training_format(adv_examples, format_type="chat")
            samples.extend(adv_samples)
            logger.info(f"  Added {len(adv_samples)} adversarial examples")

        # Write to file
        with open(output_path, "w") as f:
            for sample in samples:
                f.write(json.dumps(sample) + "\n")

        logger.info(f"Generated {len(samples)} total examples")

        # Upload
        upload_dataset(
            data_path=str(output_path),
            repo_id=repo_id,
            commit_message=f"Update dataset ({len(samples)} examples)",
            dry_run=dry_run,
        )


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Upload Kodiak SecOps 1 to HuggingFace Hub",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Upload trained model
    python scripts/upload_to_hub.py model --model-path ./outputs/kodiak-secops-1-lora

    # Upload existing dataset files
    python scripts/upload_to_hub.py dataset --data-path ./data/train.jsonl

    # Generate and upload fresh dataset
    python scripts/upload_to_hub.py generate --num-samples 10000

    # Upload everything
    python scripts/upload_to_hub.py all --model-path ./outputs/kodiak-secops-1 --data-path ./data

    # Dry run to see what would be uploaded
    python scripts/upload_to_hub.py model --model-path ./outputs/kodiak-secops-1 --dry-run
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Model upload
    model_parser = subparsers.add_parser("model", help="Upload model to HuggingFace Hub")
    model_parser.add_argument(
        "--model-path",
        type=str,
        required=True,
        help="Path to model directory",
    )
    model_parser.add_argument(
        "--repo-id",
        type=str,
        default=MODEL_REPO_ID,
        help=f"HuggingFace repo ID (default: {MODEL_REPO_ID})",
    )
    model_parser.add_argument(
        "--message",
        type=str,
        default="Update model",
        help="Commit message",
    )
    model_parser.add_argument("--private", action="store_true", help="Make repo private")
    model_parser.add_argument("--dry-run", action="store_true", help="Show what would be uploaded")

    # Dataset upload
    dataset_parser = subparsers.add_parser("dataset", help="Upload dataset to HuggingFace Hub")
    dataset_parser.add_argument(
        "--data-path",
        type=str,
        required=True,
        help="Path to data file or directory",
    )
    dataset_parser.add_argument(
        "--repo-id",
        type=str,
        default=DATASET_REPO_ID,
        help=f"HuggingFace repo ID (default: {DATASET_REPO_ID})",
    )
    dataset_parser.add_argument(
        "--message",
        type=str,
        default="Update dataset",
        help="Commit message",
    )
    dataset_parser.add_argument("--private", action="store_true", help="Make repo private")
    dataset_parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be uploaded"
    )

    # Generate and upload dataset
    generate_parser = subparsers.add_parser("generate", help="Generate and upload dataset")
    generate_parser.add_argument(
        "--num-samples",
        type=int,
        default=10000,
        help="Number of samples to generate (default: 10000)",
    )
    generate_parser.add_argument(
        "--repo-id",
        type=str,
        default=DATASET_REPO_ID,
        help=f"HuggingFace repo ID (default: {DATASET_REPO_ID})",
    )
    generate_parser.add_argument(
        "--no-adversarial",
        action="store_true",
        help="Skip adversarial examples",
    )
    generate_parser.add_argument(
        "--dry-run", action="store_true", help="Show what would be uploaded"
    )

    # Upload all
    all_parser = subparsers.add_parser("all", help="Upload both model and dataset")
    all_parser.add_argument(
        "--model-path",
        type=str,
        required=True,
        help="Path to model directory",
    )
    all_parser.add_argument(
        "--data-path",
        type=str,
        required=True,
        help="Path to data file or directory",
    )
    all_parser.add_argument("--private", action="store_true", help="Make repos private")
    all_parser.add_argument("--dry-run", action="store_true", help="Show what would be uploaded")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Check for huggingface_hub
    try:
        import huggingface_hub  # noqa: F401
    except ImportError:
        logger.error("huggingface_hub not installed. Run: pip install huggingface_hub")
        sys.exit(1)

    if args.command == "model":
        upload_model(
            model_path=args.model_path,
            repo_id=args.repo_id,
            commit_message=args.message,
            private=args.private,
            dry_run=args.dry_run,
        )
    elif args.command == "dataset":
        upload_dataset(
            data_path=args.data_path,
            repo_id=args.repo_id,
            commit_message=args.message,
            private=args.private,
            dry_run=args.dry_run,
        )
    elif args.command == "generate":
        generate_and_upload_dataset(
            num_samples=args.num_samples,
            repo_id=args.repo_id,
            include_adversarial=not args.no_adversarial,
            dry_run=args.dry_run,
        )
    elif args.command == "all":
        upload_model(
            model_path=args.model_path,
            private=args.private,
            dry_run=args.dry_run,
        )
        upload_dataset(
            data_path=args.data_path,
            private=args.private,
            dry_run=args.dry_run,
        )


if __name__ == "__main__":
    main()
