"""AIT Alert Dataset Integration.
===================================

Downloads, parses, and integrates the Austrian Institute of Technology (AIT)
Alert Dataset for training with real-world IDS alerts.

The AIT Alert Dataset contains 2.6M+ alerts from three intrusion detection
systems (Wazuh, Suricata, AMiner) with labeled attack scenarios.

Dataset source: https://github.com/ait-aecid/alert-data-set
Zenodo: https://zenodo.org/records/8263181

Example:
    >>> from soc_triage_agent.ait_dataset import AITDatasetLoader
    >>> loader = AITDatasetLoader()
    >>> loader.download()
    >>> alerts = loader.load_alerts(max_alerts=10000)
    >>> training_data = loader.convert_to_training_format(alerts)

"""

import hashlib
import json
import logging
import random
import shutil
import uuid
import zipfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.request import urlretrieve

from .data_generator import (
    AlertCategory,
    SecurityAlertGenerator,
    Severity,
    TriageDecision,
)

logger = logging.getLogger(__name__)


# AIT Dataset URLs and metadata
AIT_ZENODO_URL = "https://zenodo.org/records/8263181/files/ait-alert-dataset.zip"
AIT_GITHUB_URL = "https://github.com/ait-aecid/alert-data-set"

# Scenarios available in the AIT dataset
AIT_SCENARIOS = [
    "fox",
    "harrison",
    "russellmitchell",
    "santos",
    "shaw",
    "wardbeck",
    "wheeler",
    "wilson",
]

# Mapping from AIT detector signatures to our alert categories
DETECTOR_TO_CATEGORY = {
    # Wazuh signatures
    "wazuh_authentication_failed": AlertCategory.BRUTE_FORCE,
    "wazuh_authentication_success": AlertCategory.BRUTE_FORCE,
    "wazuh_multiple_authentication_failures": AlertCategory.BRUTE_FORCE,
    "wazuh_ssh_bruteforce": AlertCategory.BRUTE_FORCE,
    "wazuh_web_attack": AlertCategory.VULNERABILITY_EXPLOIT,
    "wazuh_sql_injection": AlertCategory.VULNERABILITY_EXPLOIT,
    "wazuh_xss_attempt": AlertCategory.VULNERABILITY_EXPLOIT,
    "wazuh_malware_detected": AlertCategory.MALWARE,
    "wazuh_rootkit_detected": AlertCategory.MALWARE,
    "wazuh_file_integrity": AlertCategory.INSIDER_THREAT,
    "wazuh_policy_violation": AlertCategory.POLICY_VIOLATION,
    "wazuh_privilege_escalation": AlertCategory.PRIVILEGE_ESCALATION,
    "wazuh_lateral_movement": AlertCategory.LATERAL_MOVEMENT,
    # Suricata signatures
    "suricata_et_scan": AlertCategory.RECONNAISSANCE,
    "suricata_et_exploit": AlertCategory.VULNERABILITY_EXPLOIT,
    "suricata_et_malware": AlertCategory.MALWARE,
    "suricata_et_trojan": AlertCategory.MALWARE,
    "suricata_et_c2": AlertCategory.COMMAND_AND_CONTROL,
    "suricata_et_exfiltration": AlertCategory.DATA_EXFILTRATION,
    "suricata_dos": AlertCategory.DENIAL_OF_SERVICE,
    "suricata_shellcode": AlertCategory.VULNERABILITY_EXPLOIT,
    # AMiner signatures
    "aminer_anomaly": AlertCategory.INSIDER_THREAT,
    "aminer_new_program": AlertCategory.POLICY_VIOLATION,
    "aminer_value_range": AlertCategory.INSIDER_THREAT,
}

# Attack labels from AIT dataset to our categories
ATTACK_LABEL_TO_CATEGORY = {
    # Multi-step attack phases
    "reconnaissance": AlertCategory.RECONNAISSANCE,
    "initial_access": AlertCategory.VULNERABILITY_EXPLOIT,
    "execution": AlertCategory.MALWARE,
    "persistence": AlertCategory.MALWARE,
    "privilege_escalation": AlertCategory.PRIVILEGE_ESCALATION,
    "defense_evasion": AlertCategory.MALWARE,
    "credential_access": AlertCategory.BRUTE_FORCE,
    "discovery": AlertCategory.RECONNAISSANCE,
    "lateral_movement": AlertCategory.LATERAL_MOVEMENT,
    "collection": AlertCategory.DATA_EXFILTRATION,
    "command_and_control": AlertCategory.COMMAND_AND_CONTROL,
    "exfiltration": AlertCategory.DATA_EXFILTRATION,
    "impact": AlertCategory.DENIAL_OF_SERVICE,
    # Specific attack types
    "brute_force": AlertCategory.BRUTE_FORCE,
    "ssh_brute_force": AlertCategory.BRUTE_FORCE,
    "web_attack": AlertCategory.VULNERABILITY_EXPLOIT,
    "sql_injection": AlertCategory.VULNERABILITY_EXPLOIT,
    "phishing": AlertCategory.PHISHING,
    "malware": AlertCategory.MALWARE,
    "ransomware": AlertCategory.MALWARE,
    "data_theft": AlertCategory.DATA_EXFILTRATION,
    "insider": AlertCategory.INSIDER_THREAT,
    # False positive label
    "false_positive": None,
    "benign": None,
    "normal": None,
}


@dataclass
class AITAlert:
    """Parsed alert from the AIT dataset."""

    timestamp: str
    detector: str  # aminer, wazuh, suricata
    signature: str
    host: str
    event_label: str  # attack type or false_positive
    time_label: str  # attack scenario or normal
    raw_data: dict[str, Any]

    @property
    def is_attack(self) -> bool:
        """Check if this alert is attack-related."""
        return self.event_label not in ["false_positive", "benign", "normal", ""]

    @property
    def is_false_positive(self) -> bool:
        """Check if this alert is a known false positive."""
        return self.event_label in ["false_positive", "benign", "normal"]


class AITDatasetLoader:
    """Loader for the AIT Alert Dataset.

    Downloads, parses, and converts AIT alerts to the training format
    used by Kodiak SecOps 1.

    Attributes:
        data_dir: Directory to store downloaded data
        seed: Random seed for reproducibility

    """

    def __init__(
        self,
        data_dir: str = "data/ait-dataset",
        seed: Optional[int] = None,
    ):
        """Initialize the loader.

        Args:
            data_dir: Directory to store downloaded dataset
            seed: Random seed for reproducibility

        """
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.seed = seed
        self._rng = random.Random(seed)
        self._synthetic_generator = SecurityAlertGenerator(seed=seed)

    def download(
        self,
        url: Optional[str] = None,
        force: bool = False,
    ) -> Path:
        """Download the AIT Alert Dataset.

        Args:
            url: Custom URL to download from (uses Zenodo by default)
            force: Force re-download even if files exist

        Returns:
            Path to the downloaded/extracted data directory

        """
        url = url or AIT_ZENODO_URL
        zip_path = self.data_dir / "ait-alert-dataset.zip"
        extracted_dir = self.data_dir / "alerts"

        if extracted_dir.exists() and not force:
            logger.info(f"Dataset already exists at {extracted_dir}")
            return extracted_dir

        # Download
        logger.info(f"Downloading AIT Alert Dataset from {url}")
        try:

            def progress_hook(block_num: int, block_size: int, total_size: int) -> None:
                if total_size > 0:
                    percent = min(100, block_num * block_size * 100 // total_size)
                    if block_num % 100 == 0:
                        logger.info(f"Download progress: {percent}%")

            urlretrieve(url, zip_path, reporthook=progress_hook)
            logger.info(f"Downloaded to {zip_path}")
        except Exception as e:
            logger.error(f"Failed to download dataset: {e}")
            logger.info("You can manually download from:")
            logger.info(f"  - Zenodo: {AIT_ZENODO_URL}")
            logger.info(f"  - GitHub: {AIT_GITHUB_URL}")
            raise

        # Extract
        logger.info("Extracting dataset...")
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(self.data_dir)

        # Clean up zip
        zip_path.unlink()

        logger.info(f"Dataset extracted to {extracted_dir}")
        return extracted_dir

    def download_from_github(self, force: bool = False) -> Path:
        """Download dataset directly from GitHub repository.

        This is an alternative to Zenodo for smaller downloads.

        Args:
            force: Force re-download

        Returns:
            Path to data directory

        """
        import subprocess

        repo_dir = self.data_dir / "alert-data-set"

        if repo_dir.exists() and not force:
            logger.info(f"Repository already exists at {repo_dir}")
            return repo_dir / "data"

        if repo_dir.exists():
            shutil.rmtree(repo_dir)

        logger.info("Cloning AIT Alert Dataset from GitHub...")
        subprocess.run(
            ["git", "clone", "--depth", "1", f"{AIT_GITHUB_URL}.git", str(repo_dir)],
            check=True,
        )

        return repo_dir / "data"

    def load_alerts(
        self,
        scenarios: Optional[list[str]] = None,
        detectors: Optional[list[str]] = None,
        max_alerts: Optional[int] = None,
        include_false_positives: bool = True,
        attack_only: bool = False,
    ) -> list[AITAlert]:
        """Load alerts from the downloaded dataset.

        Args:
            scenarios: Specific scenarios to load (default: all)
            detectors: Specific detectors to load (default: all)
            max_alerts: Maximum number of alerts to load
            include_false_positives: Include known false positives
            attack_only: Only load attack-related alerts

        Returns:
            List of parsed AITAlert objects

        """
        scenarios = scenarios or AIT_SCENARIOS
        detectors = detectors or ["wazuh", "suricata", "aminer"]

        alerts = []
        alerts_dir = self.data_dir / "alerts"

        if not alerts_dir.exists():
            # Try alternative paths
            for alt_path in [
                self.data_dir / "alert-data-set" / "data",
                self.data_dir / "data",
                self.data_dir,
            ]:
                if (alt_path / "fox").exists() or list(alt_path.glob("*.json")):
                    alerts_dir = alt_path
                    break
            else:
                raise FileNotFoundError(
                    f"Dataset not found. Run download() first or check {self.data_dir}"
                )

        # Load from each scenario
        for scenario in scenarios:
            scenario_dir = alerts_dir / scenario

            if not scenario_dir.exists():
                # Try loading from flat structure
                json_files = list(alerts_dir.glob(f"{scenario}*.json"))
                if not json_files:
                    logger.warning(f"Scenario {scenario} not found, skipping")
                    continue

                for json_file in json_files:
                    alerts.extend(self._load_json_file(json_file, detectors))
            else:
                # Load from scenario directory
                for detector in detectors:
                    detector_file = scenario_dir / f"{detector}_alerts.json"
                    if detector_file.exists():
                        alerts.extend(self._load_json_file(detector_file, [detector]))

            if max_alerts and len(alerts) >= max_alerts:
                break

        # Filter
        if attack_only:
            alerts = [a for a in alerts if a.is_attack]
        elif not include_false_positives:
            alerts = [a for a in alerts if not a.is_false_positive]

        # Limit
        if max_alerts and len(alerts) > max_alerts:
            self._rng.shuffle(alerts)
            alerts = alerts[:max_alerts]

        logger.info(f"Loaded {len(alerts)} alerts")
        return alerts

    def _load_json_file(
        self,
        filepath: Path,
        detectors: list[str],
    ) -> list[AITAlert]:
        """Load alerts from a single JSON file."""
        alerts = []

        try:
            with open(filepath) as f:
                data = json.load(f)

            # Handle both list and dict formats
            if isinstance(data, list):
                raw_alerts = data
            elif isinstance(data, dict):
                raw_alerts = data.get("alerts", [data])
            else:
                return alerts

            for raw in raw_alerts:
                # Parse based on format
                alert = self._parse_raw_alert(raw, detectors)
                if alert:
                    alerts.append(alert)

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse {filepath}: {e}")
        except Exception as e:
            logger.warning(f"Error loading {filepath}: {e}")

        return alerts

    def _parse_raw_alert(
        self,
        raw: dict[str, Any],
        detectors: list[str],
    ) -> Optional[AITAlert]:
        """Parse a raw alert dictionary into AITAlert."""
        # Extract detector
        detector = raw.get("detector", "")
        if not detector:
            # Try to infer from signature name
            name = raw.get("name", "").lower()
            if "wazuh" in name:
                detector = "wazuh"
            elif "suricata" in name:
                detector = "suricata"
            elif "aminer" in name:
                detector = "aminer"
            else:
                detector = "unknown"

        if detector not in detectors and "all" not in detectors:
            return None

        # Extract fields
        timestamp = raw.get("timestamp", raw.get("@timestamp", ""))
        if not timestamp:
            timestamp = datetime.now().isoformat()

        signature = raw.get("name", raw.get("signature", raw.get("rule_name", "")))
        host = raw.get("host", raw.get("hostname", raw.get("src_ip", "unknown")))
        event_label = raw.get("event_label", raw.get("attack_type", ""))
        time_label = raw.get("time_label", raw.get("scenario", ""))

        return AITAlert(
            timestamp=timestamp,
            detector=detector,
            signature=signature,
            host=host,
            event_label=event_label,
            time_label=time_label,
            raw_data=raw,
        )

    def map_to_category(self, alert: AITAlert) -> Optional[AlertCategory]:
        """Map an AIT alert to our AlertCategory.

        Args:
            alert: The AIT alert to map

        Returns:
            Corresponding AlertCategory or None for false positives

        """
        # First try event label
        if alert.event_label:
            label_lower = alert.event_label.lower().replace(" ", "_").replace("-", "_")
            if label_lower in ATTACK_LABEL_TO_CATEGORY:
                return ATTACK_LABEL_TO_CATEGORY[label_lower]

        # Try signature-based mapping
        sig_lower = alert.signature.lower().replace(" ", "_").replace("-", "_")
        for pattern, category in DETECTOR_TO_CATEGORY.items():
            if pattern in sig_lower:
                return category

        # Default based on detector
        detector_defaults = {
            "wazuh": AlertCategory.POLICY_VIOLATION,
            "suricata": AlertCategory.RECONNAISSANCE,
            "aminer": AlertCategory.INSIDER_THREAT,
        }

        return detector_defaults.get(alert.detector, AlertCategory.POLICY_VIOLATION)

    def determine_severity(self, alert: AITAlert) -> Severity:
        """Determine severity for an AIT alert.

        Args:
            alert: The AIT alert

        Returns:
            Appropriate Severity level

        """
        # Check raw data for severity hints
        raw = alert.raw_data
        raw_severity = str(
            raw.get("severity", raw.get("priority", raw.get("level", "")))
        ).lower()

        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFORMATIONAL,
            "informational": Severity.INFORMATIONAL,
            "1": Severity.CRITICAL,
            "2": Severity.HIGH,
            "3": Severity.MEDIUM,
            "4": Severity.LOW,
            "5": Severity.INFORMATIONAL,
        }

        if raw_severity in severity_map:
            return severity_map[raw_severity]

        # Infer from category
        category = self.map_to_category(alert)
        if category in [
            AlertCategory.LATERAL_MOVEMENT,
            AlertCategory.COMMAND_AND_CONTROL,
            AlertCategory.DATA_EXFILTRATION,
        ]:
            return Severity.HIGH if alert.is_attack else Severity.MEDIUM
        elif category in [
            AlertCategory.MALWARE,
            AlertCategory.PRIVILEGE_ESCALATION,
            AlertCategory.VULNERABILITY_EXPLOIT,
        ]:
            return Severity.HIGH if alert.is_attack else Severity.MEDIUM
        elif category in [AlertCategory.BRUTE_FORCE, AlertCategory.PHISHING]:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def determine_triage(
        self,
        alert: AITAlert,
        category: Optional[AlertCategory] = None,
        severity: Optional[Severity] = None,
    ) -> TriageDecision:
        """Determine triage decision for an AIT alert.

        Uses the attack labels and context from the AIT dataset to
        make informed triage decisions.

        Args:
            alert: The AIT alert
            category: Pre-mapped category (optional)
            severity: Pre-determined severity (optional)

        Returns:
            Appropriate TriageDecision

        """
        if alert.is_false_positive:
            return TriageDecision.FALSE_POSITIVE

        category = category or self.map_to_category(alert)
        severity = severity or self.determine_severity(alert)

        # High severity attacks should escalate
        if severity == Severity.CRITICAL:
            return TriageDecision.ESCALATE

        if severity == Severity.HIGH and alert.is_attack:
            return TriageDecision.ESCALATE

        # Category-specific decisions
        escalate_categories = [
            AlertCategory.LATERAL_MOVEMENT,
            AlertCategory.COMMAND_AND_CONTROL,
            AlertCategory.DATA_EXFILTRATION,
        ]

        investigate_categories = [
            AlertCategory.MALWARE,
            AlertCategory.PRIVILEGE_ESCALATION,
            AlertCategory.VULNERABILITY_EXPLOIT,
            AlertCategory.BRUTE_FORCE,
            AlertCategory.PHISHING,
            AlertCategory.INSIDER_THREAT,
        ]

        if category in escalate_categories and alert.is_attack:
            return TriageDecision.ESCALATE
        elif category in investigate_categories:
            return TriageDecision.INVESTIGATE
        elif category == AlertCategory.RECONNAISSANCE:
            return TriageDecision.MONITOR
        elif category == AlertCategory.POLICY_VIOLATION:
            return TriageDecision.MONITOR
        else:
            return TriageDecision.INVESTIGATE

    def convert_to_training_format(
        self,
        alerts: list[AITAlert],
        format_type: str = "chat",
    ) -> list[dict[str, Any]]:
        """Convert AIT alerts to training format.

        Uses the synthetic generator's formatting but with real alert data.

        Args:
            alerts: List of AIT alerts to convert
            format_type: Output format (chat, instruction, etc.)

        Returns:
            List of training examples

        """
        training_data = []

        for alert in alerts:
            category = self.map_to_category(alert)
            if category is None:  # False positive
                category = self._rng.choice(list(AlertCategory))

            severity = self.determine_severity(alert)
            decision = self.determine_triage(alert, category, severity)

            # Generate synthetic context to enrich real alerts
            synthetic_alert, synthetic_triage = self._synthetic_generator.generate_alert(
                category=category,
                severity=severity,
            )

            # Override with real alert data
            synthetic_alert.alert_id = str(uuid.uuid4())
            synthetic_alert.timestamp = alert.timestamp
            synthetic_alert.source_system = f"{alert.detector.title()} IDS"
            synthetic_alert.title = alert.signature or synthetic_alert.title
            synthetic_alert.category = category.value
            synthetic_alert.severity = severity.value

            # Add real data to description
            real_context = f"Real alert from {alert.detector} IDS. "
            if alert.event_label:
                real_context += f"Attack type: {alert.event_label}. "
            if alert.time_label:
                real_context += f"Scenario: {alert.time_label}. "

            synthetic_alert.description = real_context + synthetic_alert.description

            # Merge real IOCs if available
            raw = alert.raw_data
            if "src_ip" in raw:
                synthetic_alert.indicators["source_ip"] = raw["src_ip"]
            if "dst_ip" in raw:
                synthetic_alert.indicators["destination_ip"] = raw["dst_ip"]
            if "src_port" in raw:
                synthetic_alert.indicators["source_port"] = raw["src_port"]
            if "dst_port" in raw:
                synthetic_alert.indicators["destination_port"] = raw["dst_port"]

            # Update triage based on real labels
            synthetic_triage.decision = decision.value
            if alert.is_attack:
                synthetic_triage.confidence_score = min(
                    0.95, synthetic_triage.confidence_score + 0.1
                )
                if "multi-step" in alert.time_label.lower():
                    synthetic_triage.key_factors.insert(
                        0, "Part of multi-step attack campaign"
                    )
            elif alert.is_false_positive:
                synthetic_triage.decision = TriageDecision.FALSE_POSITIVE.value
                synthetic_triage.key_factors = [
                    "Verified false positive from labeled dataset"
                ]
                synthetic_triage.recommended_actions = [
                    "Update detection rules to reduce false positives"
                ]

            # Format for training
            formatted = self._synthetic_generator.format_for_training(
                synthetic_alert,
                synthetic_triage,
                format_type,
            )

            # Add metadata
            formatted["_metadata"] = {
                "source": "ait_dataset",
                "detector": alert.detector,
                "is_attack": alert.is_attack,
                "event_label": alert.event_label,
                "time_label": alert.time_label,
            }

            training_data.append(formatted)

        return training_data

    def generate_hybrid_dataset(
        self,
        num_samples: int = 10000,
        real_ratio: float = 0.3,
        format_type: str = "chat",
        balanced: bool = True,
    ) -> list[dict[str, Any]]:
        """Generate a hybrid dataset mixing real and synthetic alerts.

        Args:
            num_samples: Total number of samples
            real_ratio: Ratio of real alerts (0.0-1.0)
            format_type: Output format
            balanced: Balance across categories

        Returns:
            Combined training dataset

        """
        num_real = int(num_samples * real_ratio)
        num_synthetic = num_samples - num_real

        logger.info(f"Generating hybrid dataset: {num_real} real + {num_synthetic} synthetic")

        # Load real alerts
        try:
            real_alerts = self.load_alerts(max_alerts=num_real * 2)  # Load extra for filtering
            if len(real_alerts) < num_real:
                logger.warning(
                    f"Only {len(real_alerts)} real alerts available, adjusting ratio"
                )
                num_real = len(real_alerts)
                num_synthetic = num_samples - num_real

            # Sample real alerts
            self._rng.shuffle(real_alerts)
            real_alerts = real_alerts[:num_real]

            real_training = self.convert_to_training_format(real_alerts, format_type)
            logger.info(f"Converted {len(real_training)} real alerts")

        except FileNotFoundError:
            logger.warning("AIT dataset not found, using 100% synthetic data")
            real_training = []
            num_synthetic = num_samples

        # Generate synthetic
        synthetic_training = self._synthetic_generator.generate_dataset(
            num_samples=num_synthetic,
            format_type=format_type,
            include_metadata=True,
            balanced=balanced,
        )

        # Add source metadata
        for sample in synthetic_training:
            if "_metadata" not in sample:
                sample["_metadata"] = {}
            sample["_metadata"]["source"] = "synthetic"

        logger.info(f"Generated {len(synthetic_training)} synthetic samples")

        # Combine and shuffle
        combined = real_training + synthetic_training
        self._rng.shuffle(combined)

        logger.info(f"Total hybrid dataset size: {len(combined)}")
        return combined

    def get_statistics(self, alerts: list[AITAlert]) -> dict[str, Any]:
        """Calculate statistics for loaded alerts.

        Args:
            alerts: List of alerts to analyze

        Returns:
            Statistics dictionary

        """
        stats: dict[str, Any] = {
            "total_alerts": len(alerts),
            "detectors": {},
            "categories": {},
            "attack_alerts": 0,
            "false_positives": 0,
            "scenarios": {},
        }

        for alert in alerts:
            # Detector counts
            stats["detectors"][alert.detector] = (
                stats["detectors"].get(alert.detector, 0) + 1
            )

            # Category counts
            category = self.map_to_category(alert)
            if category:
                cat_name = category.value
                stats["categories"][cat_name] = stats["categories"].get(cat_name, 0) + 1

            # Attack vs false positive
            if alert.is_attack:
                stats["attack_alerts"] += 1
            if alert.is_false_positive:
                stats["false_positives"] += 1

            # Scenario counts
            if alert.time_label:
                stats["scenarios"][alert.time_label] = (
                    stats["scenarios"].get(alert.time_label, 0) + 1
                )

        return stats


def main():
    """CLI for AIT dataset operations."""
    import argparse

    parser = argparse.ArgumentParser(
        description="AIT Alert Dataset Integration for Kodiak SecOps 1"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Download command
    download_parser = subparsers.add_parser("download", help="Download the AIT dataset")
    download_parser.add_argument(
        "--data-dir",
        type=str,
        default="data/ait-dataset",
        help="Directory to store dataset",
    )
    download_parser.add_argument(
        "--github",
        action="store_true",
        help="Download from GitHub instead of Zenodo",
    )
    download_parser.add_argument(
        "--force",
        action="store_true",
        help="Force re-download",
    )

    # Stats command
    stats_parser = subparsers.add_parser("stats", help="Show dataset statistics")
    stats_parser.add_argument(
        "--data-dir",
        type=str,
        default="data/ait-dataset",
    )
    stats_parser.add_argument(
        "--max-alerts",
        type=int,
        default=None,
        help="Limit alerts to analyze",
    )

    # Generate command
    gen_parser = subparsers.add_parser("generate", help="Generate hybrid training data")
    gen_parser.add_argument(
        "--data-dir",
        type=str,
        default="data/ait-dataset",
    )
    gen_parser.add_argument(
        "--output",
        type=str,
        default="data/hybrid_train.jsonl",
        help="Output file",
    )
    gen_parser.add_argument(
        "--num-samples",
        type=int,
        default=10000,
        help="Total number of samples",
    )
    gen_parser.add_argument(
        "--real-ratio",
        type=float,
        default=0.3,
        help="Ratio of real alerts (0.0-1.0)",
    )
    gen_parser.add_argument(
        "--format",
        choices=["chat", "instruction", "sharegpt", "huggingface"],
        default="chat",
        help="Output format",
    )
    gen_parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    if args.command == "download":
        loader = AITDatasetLoader(data_dir=args.data_dir)
        if args.github:
            loader.download_from_github(force=args.force)
        else:
            loader.download(force=args.force)
        print("Download complete!")

    elif args.command == "stats":
        loader = AITDatasetLoader(data_dir=args.data_dir)
        alerts = loader.load_alerts(max_alerts=args.max_alerts)
        stats = loader.get_statistics(alerts)

        print("\n=== AIT Dataset Statistics ===")
        print(f"Total alerts: {stats['total_alerts']:,}")
        print(f"Attack alerts: {stats['attack_alerts']:,}")
        print(f"False positives: {stats['false_positives']:,}")
        print("\nBy Detector:")
        for det, count in sorted(stats["detectors"].items()):
            print(f"  {det}: {count:,}")
        print("\nBy Category:")
        for cat, count in sorted(stats["categories"].items()):
            print(f"  {cat}: {count:,}")

    elif args.command == "generate":
        loader = AITDatasetLoader(data_dir=args.data_dir, seed=args.seed)

        print(f"Generating hybrid dataset...")
        samples = loader.generate_hybrid_dataset(
            num_samples=args.num_samples,
            real_ratio=args.real_ratio,
            format_type=args.format,
        )

        # Save
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            for sample in samples:
                f.write(json.dumps(sample) + "\n")

        print(f"Saved {len(samples)} samples to {args.output}")

        # Print breakdown
        real_count = sum(1 for s in samples if s.get("_metadata", {}).get("source") == "ait_dataset")
        synth_count = len(samples) - real_count
        print(f"  Real: {real_count} ({100*real_count/len(samples):.1f}%)")
        print(f"  Synthetic: {synth_count} ({100*synth_count/len(samples):.1f}%)")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
