#!/usr/bin/env python3
"""Gradio web interface for SOC Alert Triage 8B.

This module provides an interactive web interface for testing the SOC Alert
Triage model. It supports both local model inference and API-based inference.

Usage:
    # Run with default settings (no model, demo mode)
    python app.py

    # Run with local model
    python app.py --model fmt0816/soc-alert-triage-8b

    # Run with OpenAI API
    python app.py --api openai

    # Run with Azure OpenAI
    python app.py --api azure --deployment your-deployment

"""

import argparse
import json
import logging
from typing import Optional

import gradio as gr

# Configure logging
logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# Sample alerts for the examples dropdown
SAMPLE_ALERTS = {
    "Lateral Movement - Pass-the-Hash": {
        "alert_id": "ALERT-2024-001",
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
    "Malware - Ransomware Detection": {
        "alert_id": "ALERT-2024-002",
        "timestamp": "2025-01-15T09:15:00Z",
        "category": "malware",
        "severity": "critical",
        "title": "Known ransomware signature detected",
        "description": "Executable matching known ransomware signature was blocked from execution on finance server.",
        "indicators": {
            "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "file_name": "invoice_update.exe",
            "file_path": "C:\\Users\\admin\\Downloads\\",
            "process_parent": "outlook.exe",
            "signature_match": "Ransomware.LockBit.A",
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
    "Phishing - Credential Harvesting": {
        "alert_id": "ALERT-2024-003",
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
    "Data Exfiltration - Large Upload": {
        "alert_id": "ALERT-2024-004",
        "timestamp": "2025-01-15T23:30:00Z",
        "category": "data_exfiltration",
        "severity": "high",
        "title": "Unusual data upload to external service",
        "description": "Large volume of data uploaded to cloud storage service outside business hours by employee on notice period.",
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
    "Brute Force - SSH Attack": {
        "alert_id": "ALERT-2024-005",
        "timestamp": "2025-01-15T03:22:00Z",
        "category": "brute_force",
        "severity": "medium",
        "title": "Multiple failed SSH login attempts",
        "description": "Over 500 failed SSH login attempts from external IP targeting production server.",
        "indicators": {
            "source_ip": "185.220.101.42",
            "target_host": "PROD-WEB-01",
            "failed_attempts": 523,
            "time_window_minutes": 15,
            "protocol": "SSH",
            "targeted_accounts": ["root", "admin", "ubuntu"],
        },
        "user_context": {
            "username": "N/A",
            "department": "N/A",
            "role": "N/A",
            "is_vip": False,
        },
        "asset_context": {
            "hostname": "PROD-WEB-01",
            "asset_type": "server",
            "criticality": "high",
            "data_classification": "public",
            "environment": "production",
        },
    },
}


def load_model(model_path: Optional[str], api_type: Optional[str], deployment: Optional[str]):
    """Load the SOC Triage model."""
    try:
        from soc_triage_agent import SOCTriageModel
    except ImportError:
        logger.warning("soc_triage_agent not installed, running in demo mode")
        return None

    if api_type == "openai":
        logger.info("Loading OpenAI model...")
        return SOCTriageModel.from_openai(model_name=model_path or "gpt-4")
    elif api_type == "azure":
        if not deployment:
            logger.error("Deployment name required for Azure OpenAI")
            return None
        logger.info(f"Loading Azure OpenAI deployment: {deployment}")
        return SOCTriageModel.from_azure_openai(deployment_name=deployment)
    elif model_path:
        logger.info(f"Loading model from {model_path}...")
        return SOCTriageModel.from_pretrained(model_path)
    else:
        logger.info("No model specified, running in demo mode")
        return None


def format_alert_display(alert: dict) -> str:
    """Format an alert for display."""
    lines = [
        f"**Alert ID:** {alert.get('alert_id', 'N/A')}",
        f"**Timestamp:** {alert.get('timestamp', 'N/A')}",
        f"**Category:** {alert.get('category', 'N/A')}",
        f"**Severity:** {alert.get('severity', 'N/A')}",
        f"**Title:** {alert.get('title', 'N/A')}",
        "",
        f"**Description:** {alert.get('description', 'N/A')}",
        "",
        "**Indicators:**",
        f"```json\n{json.dumps(alert.get('indicators', {}), indent=2)}\n```",
    ]

    if alert.get("user_context"):
        lines.extend(
            [
                "",
                "**User Context:**",
                f"```json\n{json.dumps(alert['user_context'], indent=2)}\n```",
            ]
        )

    if alert.get("asset_context"):
        lines.extend(
            [
                "",
                "**Asset Context:**",
                f"```json\n{json.dumps(alert['asset_context'], indent=2)}\n```",
            ]
        )

    return "\n".join(lines)


def format_prediction_display(prediction) -> str:
    """Format a prediction for display."""
    lines = [
        "## Triage Recommendation",
        "",
        "### Decision Summary",
        "| Field | Value |",
        "|-------|-------|",
        f"| **Decision** | {prediction.decision.upper()} |",
        f"| **Priority** | {prediction.priority} |",
        f"| **Confidence** | {prediction.confidence:.0%} |",
        f"| **Escalation Required** | {'Yes' if prediction.escalation_required else 'No'} |",
    ]

    if prediction.escalation_target:
        lines.append(f"| **Escalation Target** | {prediction.escalation_target} |")

    lines.append(f"| **Estimated Impact** | {prediction.estimated_impact} |")

    if prediction.reasoning:
        lines.extend(["", "### Reasoning", prediction.reasoning])

    if prediction.recommended_actions:
        lines.extend(["", "### Recommended Actions"])
        for i, action in enumerate(prediction.recommended_actions, 1):
            lines.append(f"{i}. {action}")

    return "\n".join(lines)


def create_demo_response(alert: dict) -> str:
    """Create a demo response when no model is loaded."""
    severity = alert.get("severity", "medium")
    category = alert.get("category", "unknown")

    # Simple rule-based demo logic
    if severity == "critical" or category in ["lateral_movement", "data_exfiltration"]:
        decision = "ESCALATE"
        priority = 1
        confidence = 92
    elif severity == "high":
        decision = "INVESTIGATE"
        priority = 2
        confidence = 85
    elif severity == "medium":
        decision = "INVESTIGATE"
        priority = 3
        confidence = 78
    else:
        decision = "MONITOR"
        priority = 4
        confidence = 70

    return f"""## Triage Recommendation (Demo Mode)

### Decision Summary
| Field | Value |
|-------|-------|
| **Decision** | {decision} |
| **Priority** | {priority} |
| **Confidence** | {confidence}% |
| **Escalation Required** | {'Yes' if decision == 'ESCALATE' else 'No'} |
| **Estimated Impact** | {severity} |

### Reasoning
*Demo mode: This is a simulated response based on alert severity and category.*

Based on the {severity} severity {category} alert, the recommended action is to {decision.lower()}.

### Recommended Actions
1. Review the alert details and indicators
2. Check for related alerts in the same timeframe
3. Validate the affected assets and users
4. Document findings and escalate if necessary

---
*Note: Running in demo mode. Load a model for actual predictions.*
"""


def triage_alert(
    alert_json: str, selected_example: str, model_state: Optional[object]
) -> tuple[str, str]:
    """Process an alert and return triage recommendation."""
    # Parse alert
    try:
        if selected_example and selected_example != "Custom JSON":
            alert = SAMPLE_ALERTS[selected_example]
        else:
            alert = json.loads(alert_json)
    except json.JSONDecodeError as e:
        return f"**Error:** Invalid JSON\n\n```\n{e}\n```", ""
    except KeyError:
        return "**Error:** Example not found", ""

    # Format alert display
    alert_display = format_alert_display(alert)

    # Get prediction
    if model_state is not None:
        try:
            prediction = model_state.predict(alert)
            result_display = format_prediction_display(prediction)
        except Exception as e:
            result_display = f"**Error during prediction:**\n\n```\n{e}\n```"
    else:
        result_display = create_demo_response(alert)

    return alert_display, result_display


def update_json_from_example(example_name: str) -> str:
    """Update JSON input when example is selected."""
    if example_name and example_name != "Custom JSON":
        return json.dumps(SAMPLE_ALERTS[example_name], indent=2)
    return ""


def create_interface(model: Optional[object]) -> gr.Blocks:
    """Create the Gradio interface."""
    with gr.Blocks(
        title="SOC Alert Triage 8B",
        theme=gr.themes.Soft(),
        css="""
        .container { max-width: 1200px; margin: auto; }
        .header { text-align: center; margin-bottom: 20px; }
        """,
    ) as interface:
        # Store model in state
        model_state = gr.State(model)

        gr.Markdown(
            """
            # SOC Alert Triage 8B

            Automated security alert triage powered by fine-tuned language models.
            Select a sample alert or enter custom JSON to get triage recommendations.
            """
        )

        with gr.Row():
            with gr.Column(scale=1):
                gr.Markdown("### Input")

                example_dropdown = gr.Dropdown(
                    choices=["Custom JSON"] + list(SAMPLE_ALERTS.keys()),
                    value="Custom JSON",
                    label="Select Example Alert",
                )

                alert_input = gr.Textbox(
                    label="Alert JSON",
                    placeholder='{"alert_id": "...", "category": "malware", ...}',
                    lines=15,
                    max_lines=25,
                )

                submit_btn = gr.Button("Analyze Alert", variant="primary", size="lg")

            with gr.Column(scale=1):
                gr.Markdown("### Alert Details")
                alert_display = gr.Markdown(
                    value="*Select an example or enter custom JSON*",
                )

        gr.Markdown("---")

        with gr.Row(), gr.Column():
            gr.Markdown("### Triage Recommendation")
            result_display = gr.Markdown(
                value="*Click 'Analyze Alert' to get recommendations*",
            )

        # Event handlers
        example_dropdown.change(
            fn=update_json_from_example,
            inputs=[example_dropdown],
            outputs=[alert_input],
        )

        submit_btn.click(
            fn=triage_alert,
            inputs=[alert_input, example_dropdown, model_state],
            outputs=[alert_display, result_display],
        )

        gr.Markdown(
            """
            ---
            ### About

            **SOC Alert Triage 8B** is a fine-tuned language model for automated security
            alert triage. It analyzes security alerts and provides structured recommendations
            including decision (escalate/investigate/monitor/close), priority, reasoning,
            and recommended actions.

            - **Model**: [fmt0816/soc-alert-triage-8b](https://huggingface.co/fmt0816/soc-alert-triage-8b)
            - **Dataset**: [fmt0816/soc-alert-triage-dataset](https://huggingface.co/datasets/fmt0816/soc-alert-triage-dataset)
            - **GitHub**: [github.com/ftrout/soc-alert-triage-8b](https://github.com/ftrout/soc-alert-triage-8b)

            *This tool is intended to assist security analysts, not replace human judgment.*
            """
        )

    return interface


def main():
    """Run the Gradio application."""
    parser = argparse.ArgumentParser(
        description="SOC Alert Triage 8B - Gradio Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Path to model or HuggingFace model ID",
    )
    parser.add_argument(
        "--api",
        choices=["openai", "azure"],
        help="Use API-based model",
    )
    parser.add_argument(
        "--deployment",
        type=str,
        help="Azure OpenAI deployment name",
    )
    parser.add_argument(
        "--share",
        action="store_true",
        help="Create public share link",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=7860,
        help="Port to run the server on",
    )

    args = parser.parse_args()

    # Load model
    model = load_model(args.model, args.api, args.deployment)

    # Create and launch interface
    interface = create_interface(model)
    interface.launch(
        server_port=args.port,
        share=args.share,
        show_error=True,
    )


if __name__ == "__main__":
    main()
