#!/usr/bin/env python3
"""Interactive demo for SOC Triage LLM.

This script provides an interactive demonstration of the SOC Triage model,
allowing users to test alert triage capabilities with sample or custom alerts.

Usage:
    python demo.py [--model MODEL_PATH] [--api openai|azure]

Examples:
    # Use local model
    python demo.py --model ./outputs/soc-triage-llm

    # Use OpenAI API (requires OPENAI_API_KEY env var)
    python demo.py --api openai

    # Use Azure OpenAI (requires AZURE_OPENAI_KEY and AZURE_OPENAI_ENDPOINT)
    python demo.py --api azure --deployment soc-triage-deployment

"""

import argparse
import json
import sys
from typing import Optional

# Sample alerts for demonstration
SAMPLE_ALERTS = [
    {
        "name": "Lateral Movement - Pass-the-Hash",
        "alert": {
            "alert_id": "DEMO-001",
            "timestamp": "2025-01-15T14:30:00Z",
            "category": "lateral_movement",
            "severity": "high",
            "title": "Pass-the-hash attack detected",
            "description": "Suspicious authentication using NTLM hash credentials detected from workstation to domain controller.",
            "indicators": {
                "source_host": "WS-PC-142",
                "destination_hosts": ["DC-01", "FILE-SRV-01"],
                "protocol": "SMB",
                "auth_type": "NTLM",
                "credentials_type": "pass_the_hash",
            },
            "user_context": {
                "username": "john.smith",
                "department": "Engineering",
                "role": "Developer",
                "is_vip": False,
                "risk_level": "medium",
            },
            "asset_context": {
                "hostname": "WS-PC-142",
                "asset_type": "workstation",
                "criticality": "medium",
                "data_classification": "internal",
            },
        },
    },
    {
        "name": "Malware - Suspicious Executable",
        "alert": {
            "alert_id": "DEMO-002",
            "timestamp": "2025-01-15T09:15:00Z",
            "category": "malware",
            "severity": "critical",
            "title": "Known malware signature detected",
            "description": "Executable matching known ransomware signature was blocked from execution.",
            "indicators": {
                "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
                "file_name": "invoice_update.exe",
                "file_path": "C:\\Users\\admin\\Downloads\\",
                "process_parent": "outlook.exe",
                "signature_match": "Ransomware.Generic.A",
            },
            "user_context": {
                "username": "admin.user",
                "department": "Finance",
                "role": "Manager",
                "is_vip": True,
                "risk_level": "high",
            },
            "asset_context": {
                "hostname": "FIN-WS-001",
                "asset_type": "workstation",
                "criticality": "high",
                "data_classification": "confidential",
            },
        },
    },
    {
        "name": "Phishing - Credential Harvesting",
        "alert": {
            "alert_id": "DEMO-003",
            "timestamp": "2025-01-15T11:45:00Z",
            "category": "phishing",
            "severity": "medium",
            "title": "Suspected phishing link clicked",
            "description": "User clicked on link in email that redirected to known credential harvesting page.",
            "indicators": {
                "url": "https://login-microsoft.com.suspicious.site/auth",
                "email_sender": "security@micr0soft-support.com",
                "email_subject": "Urgent: Password Reset Required",
                "user_action": "link_clicked",
            },
            "user_context": {
                "username": "new.employee",
                "department": "Sales",
                "role": "Representative",
                "is_vip": False,
                "risk_level": "low",
            },
            "asset_context": {
                "hostname": "SALES-WS-042",
                "asset_type": "workstation",
                "criticality": "low",
                "data_classification": "internal",
            },
        },
    },
    {
        "name": "Data Exfiltration - Large Upload",
        "alert": {
            "alert_id": "DEMO-004",
            "timestamp": "2025-01-15T23:30:00Z",
            "category": "data_exfiltration",
            "severity": "high",
            "title": "Unusual data upload to external service",
            "description": "Large volume of data uploaded to cloud storage service outside business hours.",
            "indicators": {
                "destination": "mega.nz",
                "data_volume_mb": 2500,
                "file_types": [".docx", ".xlsx", ".pdf", ".pptx"],
                "upload_time": "23:30",
                "is_business_hours": False,
            },
            "user_context": {
                "username": "departing.employee",
                "department": "R&D",
                "role": "Senior Engineer",
                "is_vip": False,
                "employment_status": "notice_period",
            },
            "asset_context": {
                "hostname": "RND-WS-007",
                "asset_type": "workstation",
                "criticality": "high",
                "data_classification": "confidential",
            },
        },
    },
]


def print_banner():
    """Print welcome banner."""
    print("\n" + "=" * 60)
    print("   SOC Triage LLM - Interactive Demo")
    print("=" * 60)
    print("\nThis demo showcases automated security alert triage using")
    print("fine-tuned language models.\n")


def print_alert(alert: dict) -> None:
    """Pretty print an alert."""
    print("\n" + "-" * 50)
    print(f"Alert ID: {alert.get('alert_id', 'N/A')}")
    print(f"Category: {alert.get('category', 'N/A')}")
    print(f"Severity: {alert.get('severity', 'N/A')}")
    print(f"Title: {alert.get('title', 'N/A')}")
    print("-" * 50)
    print(f"Description: {alert.get('description', 'N/A')}")
    if alert.get("indicators"):
        print(f"Indicators: {json.dumps(alert['indicators'], indent=2)}")
    print("-" * 50 + "\n")


def print_prediction(prediction) -> None:
    """Pretty print a prediction."""
    print("\n" + "=" * 50)
    print("TRIAGE RECOMMENDATION")
    print("=" * 50)
    print(f"Decision:     {prediction.decision.upper()}")
    print(f"Priority:     {prediction.priority} (1=highest, 5=lowest)")
    print(f"Confidence:   {prediction.confidence:.0%}")
    print(f"Escalation:   {'YES' if prediction.escalation_required else 'No'}")
    if prediction.escalation_target:
        print(f"Escalate To:  {prediction.escalation_target}")
    print(f"Impact:       {prediction.estimated_impact}")
    print("-" * 50)
    if prediction.reasoning:
        print(f"Reasoning:\n{prediction.reasoning}")
    if prediction.recommended_actions:
        print("\nRecommended Actions:")
        for i, action in enumerate(prediction.recommended_actions, 1):
            print(f"  {i}. {action}")
    print("=" * 50 + "\n")


def load_model(args: argparse.Namespace):
    """Load the SOC Triage model based on arguments."""
    try:
        from soc_triage_agent import SOCTriageModel
    except ImportError:
        print("Error: soc_triage_agent package not installed.")
        print("Run: pip install -e .")
        sys.exit(1)

    if args.api == "openai":
        print("Loading OpenAI model...")
        return SOCTriageModel.from_openai(
            model_name=args.model or "gpt-4",
        )
    elif args.api == "azure":
        print("Loading Azure OpenAI model...")
        if not args.deployment:
            print("Error: --deployment required for Azure OpenAI")
            sys.exit(1)
        return SOCTriageModel.from_azure_openai(
            deployment_name=args.deployment,
        )
    elif args.model:
        print(f"Loading model from {args.model}...")
        return SOCTriageModel.from_pretrained(args.model)
    else:
        print("No model specified. Running in demo mode (no predictions).")
        return None


def run_interactive(model: Optional[object]) -> None:
    """Run interactive demo session."""
    print_banner()

    while True:
        print("\nAvailable options:")
        print("  1-4: Run sample alert")
        for i, sample in enumerate(SAMPLE_ALERTS, 1):
            print(f"       {i}. {sample['name']}")
        print("  c:   Enter custom alert (JSON)")
        print("  q:   Quit")

        choice = input("\nSelect option: ").strip().lower()

        if choice == "q":
            print("\nGoodbye!")
            break

        alert = None

        if choice in ["1", "2", "3", "4"]:
            idx = int(choice) - 1
            if 0 <= idx < len(SAMPLE_ALERTS):
                alert = SAMPLE_ALERTS[idx]["alert"]
                print(f"\nSelected: {SAMPLE_ALERTS[idx]['name']}")

        elif choice == "c":
            print("\nEnter alert JSON (single line):")
            try:
                json_str = input().strip()
                alert = json.loads(json_str)
            except json.JSONDecodeError as e:
                print(f"Invalid JSON: {e}")
                continue

        if alert:
            print_alert(alert)

            if model:
                print("Generating triage recommendation...")
                try:
                    prediction = model.predict(alert)
                    print_prediction(prediction)
                except Exception as e:
                    print(f"Error during prediction: {e}")
            else:
                print("(No model loaded - skipping prediction)")


def main():
    """Run the interactive demo."""
    parser = argparse.ArgumentParser(
        description="Interactive demo for SOC Triage LLM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--model",
        type=str,
        help="Path to local model or Hugging Face model ID",
    )
    parser.add_argument(
        "--api",
        choices=["openai", "azure"],
        help="Use API-based model instead of local",
    )
    parser.add_argument(
        "--deployment",
        type=str,
        help="Azure OpenAI deployment name (required with --api azure)",
    )

    args = parser.parse_args()

    model = load_model(args)
    run_interactive(model)


if __name__ == "__main__":
    main()
