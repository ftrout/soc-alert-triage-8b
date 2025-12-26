"""Prompt Engineering and Few-Shot Examples.
===========================================

Provides optimized prompts, few-shot examples, and A/B testing
variants for the SOC Triage model.

Features:
- Multiple prompt variants for A/B testing
- Few-shot example injection
- Dynamic prompt construction
- Threshold tuning for decisions

Example:
    >>> from soc_triage_agent.prompts import PromptManager
    >>> manager = PromptManager(variant="concise")
    >>> prompt = manager.build_prompt(alert, include_examples=3)

"""

import random
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class PromptVariant:
    """A prompt variant for A/B testing."""

    name: str
    system_prompt: str
    description: str
    tags: list[str] = field(default_factory=list)


@dataclass
class FewShotExample:
    """A few-shot learning example."""

    alert: dict[str, Any]
    triage: dict[str, Any]
    category: str
    difficulty: str  # easy, medium, hard


@dataclass
class DecisionThresholds:
    """Configurable thresholds for triage decisions.

    These can be tuned based on organizational risk tolerance.

    """

    # Escalation thresholds
    escalate_min_severity: str = "high"
    escalate_min_priority: int = 2
    escalate_categories: list[str] = field(
        default_factory=lambda: [
            "lateral_movement",
            "command_and_control",
            "data_exfiltration",
        ]
    )

    # Investigation thresholds
    investigate_min_severity: str = "medium"
    investigate_min_priority: int = 3

    # False positive indicators
    fp_max_severity: str = "low"
    fp_require_historical_match: bool = True

    # VIP handling
    vip_priority_boost: int = 1
    critical_asset_priority_boost: int = 1

    def to_prompt_context(self) -> str:
        """Convert thresholds to prompt context."""
        return f"""
Decision Thresholds:
- Escalate for: {', '.join(self.escalate_categories)} categories
- Escalate if severity >= {self.escalate_min_severity} or priority <= {self.escalate_min_priority}
- Investigate if severity >= {self.investigate_min_severity}
- VIP users: boost priority by {self.vip_priority_boost}
- Critical assets: boost priority by {self.critical_asset_priority_boost}
"""


# Prompt Variants for A/B Testing
PROMPT_VARIANTS = {
    "default": PromptVariant(
        name="default",
        description="Original comprehensive prompt",
        tags=["production", "comprehensive"],
        system_prompt="""You are an expert Security Operations Center (SOC) analyst AI assistant. Your role is to analyze security alerts and provide comprehensive triage recommendations. For each alert, you should:

1. Assess the severity and potential impact based on all available context
2. Determine the appropriate triage decision (escalate, investigate, monitor, false_positive, or close)
3. Assign a priority level (1=highest/immediate, 5=lowest)
4. Provide clear, actionable reasoning for your decision
5. Recommend specific remediation and investigation actions
6. Identify indicators of compromise (IOCs) for threat hunting
7. Determine if escalation is required and to whom

Consider the full context including:
- User information (role, department, VIP status, employment status)
- Asset criticality and data classification
- Environmental factors (business hours, change windows, threat level)
- Historical patterns and related alerts

Provide your response in a structured format that can be easily parsed and actioned by the SOC team.""",
    ),
    "concise": PromptVariant(
        name="concise",
        description="Shorter, more direct prompt for faster inference",
        tags=["performance", "concise"],
        system_prompt="""You are a SOC analyst AI. Analyze security alerts and provide triage recommendations.

For each alert, provide:
- Decision: escalate, investigate, monitor, false_positive, or close
- Priority: 1 (critical) to 5 (low)
- Brief reasoning
- Key actions to take

Consider: severity, user context, asset criticality, and environmental factors.

Use structured markdown format.""",
    ),
    "structured": PromptVariant(
        name="structured",
        description="Highly structured prompt with explicit output format",
        tags=["structured", "parsing"],
        system_prompt="""You are a SOC analyst AI that triages security alerts.

ALWAYS respond with this exact structure:

### Triage Decision
| Field | Value |
|-------|-------|
| **Decision** | [escalate/investigate/monitor/false_positive/close] |
| **Priority** | [1-5] |
| **Confidence** | [0-100]% |
| **Escalation Required** | [Yes/No] |
| **Escalation Target** | [Team name or N/A] |
| **Estimated Impact** | [critical/high/moderate/low/minimal] |

### Reasoning
[2-3 sentences explaining the decision]

### Key Factors
1. [Factor 1]
2. [Factor 2]
3. [Factor 3]

### Recommended Actions
1. [Action 1]
2. [Action 2]
3. [Action 3]

Base your analysis on alert severity, user/asset context, and environmental factors.""",
    ),
    "expert": PromptVariant(
        name="expert",
        description="Expert-level prompt with advanced analysis",
        tags=["expert", "comprehensive"],
        system_prompt="""You are a senior SOC analyst with 10+ years of experience in threat detection and incident response. You specialize in:
- APT detection and attribution
- Malware analysis and reverse engineering
- Insider threat detection
- Cloud security incident response
- Compliance frameworks (PCI-DSS, HIPAA, SOX)

When analyzing alerts, apply your expertise to:
1. Identify attack patterns and potential kill chain stages
2. Correlate indicators with known threat actor TTPs
3. Assess blast radius and business impact
4. Recommend forensic investigation steps
5. Consider legal/compliance implications

Provide thorough analysis with technical depth while remaining actionable for junior analysts.

Structure your response with:
- Quick Assessment (decision, priority, confidence)
- Technical Analysis
- Key Indicators
- Recommended Response
- Additional Context""",
    ),
    "compliance": PromptVariant(
        name="compliance",
        description="Compliance-focused prompt for regulated environments",
        tags=["compliance", "regulated"],
        system_prompt="""You are a SOC analyst AI with expertise in compliance frameworks (PCI-DSS, HIPAA, SOX, GDPR).

For each alert, assess:
1. Security impact and triage decision
2. Compliance implications
3. Regulatory notification requirements
4. Evidence preservation needs
5. Documentation requirements

Always consider:
- Data classification and PII/PHI exposure
- Regulatory reporting timelines
- Chain of custody for forensics
- Audit trail requirements

Structure your response with both security and compliance perspectives.""",
    ),
}


# Few-Shot Examples Library
FEW_SHOT_EXAMPLES: list[FewShotExample] = [
    # Escalate - Lateral Movement
    FewShotExample(
        category="lateral_movement",
        difficulty="medium",
        alert={
            "alert_id": "FS-001",
            "category": "lateral_movement",
            "severity": "high",
            "title": "Pass-the-Hash Attack Detected",
            "description": "NTLM authentication using extracted hash from WORKSTATION-42 to access domain controller DC-01. Source user admin_service targeting domain admin group.",
            "indicators": {
                "source_host": "WORKSTATION-42",
                "destination_host": "DC-01",
                "protocol": "SMB",
                "authentication_type": "NTLM",
            },
            "user_context": {"username": "admin_service", "is_service_account": True},
            "asset_context": {"hostname": "DC-01", "criticality": "critical"},
        },
        triage={
            "decision": "escalate",
            "priority": 1,
            "reasoning": "Pass-the-hash targeting domain controller with service account credentials indicates active lateral movement. This represents immediate threat to domain infrastructure.",
            "recommended_actions": [
                "Isolate source workstation immediately",
                "Reset affected service account credentials",
                "Review DC-01 authentication logs for additional compromise",
                "Engage IR team for full scope assessment",
            ],
        },
    ),
    # Investigate - Brute Force
    FewShotExample(
        category="brute_force",
        difficulty="easy",
        alert={
            "alert_id": "FS-002",
            "category": "brute_force",
            "severity": "medium",
            "title": "Multiple Failed Login Attempts",
            "description": "15 failed login attempts for user john.doe from IP 192.168.1.100 within 5 minutes. No successful authentication.",
            "indicators": {
                "username": "john.doe",
                "source_ip": "192.168.1.100",
                "failed_attempts": 15,
                "timeframe_minutes": 5,
            },
            "user_context": {"username": "john.doe", "department": "Sales"},
            "asset_context": {"criticality": "medium"},
        },
        triage={
            "decision": "investigate",
            "priority": 3,
            "reasoning": "Failed login attempts may indicate password attack or user lockout. No successful auth reduces immediate risk but warrants investigation.",
            "recommended_actions": [
                "Verify with user if they experienced login issues",
                "Check if source IP is from expected location",
                "Review for similar patterns targeting other accounts",
            ],
        },
    ),
    # False Positive - Policy Violation
    FewShotExample(
        category="policy_violation",
        difficulty="easy",
        alert={
            "alert_id": "FS-003",
            "category": "policy_violation",
            "severity": "low",
            "title": "USB Device Connected",
            "description": "USB storage device connected to IT-WORKSTATION-12 during approved maintenance window by authorized IT administrator.",
            "indicators": {"device_type": "USB Storage", "vendor": "SanDisk"},
            "user_context": {
                "username": "it_admin_mike",
                "department": "IT",
                "role": "System Administrator",
            },
            "environmental_context": {"is_maintenance_window": True},
        },
        triage={
            "decision": "false_positive",
            "priority": 5,
            "reasoning": "USB usage by IT admin during maintenance window is expected behavior. Authorized activity with appropriate controls.",
            "recommended_actions": [
                "No action required",
                "Log for audit compliance",
            ],
        },
    ),
    # Monitor - Reconnaissance
    FewShotExample(
        category="reconnaissance",
        difficulty="medium",
        alert={
            "alert_id": "FS-004",
            "category": "reconnaissance",
            "severity": "low",
            "title": "Port Scan Detected",
            "description": "SYN scan of common ports from external IP targeting DMZ web server. 20 ports scanned over 2 minutes.",
            "indicators": {
                "source_ip": "203.0.113.50",
                "destination_ip": "192.168.100.10",
                "ports_scanned": 20,
            },
            "asset_context": {"hostname": "WEB-DMZ-01", "is_internet_facing": True},
        },
        triage={
            "decision": "monitor",
            "priority": 4,
            "reasoning": "Port scanning of internet-facing assets is common. Low severity but should be tracked for escalation if followed by exploitation attempts.",
            "recommended_actions": [
                "Add source IP to watchlist",
                "Correlate with other alerts from this source",
                "Verify DMZ firewall rules are current",
            ],
        },
    ),
    # Escalate - Data Exfiltration
    FewShotExample(
        category="data_exfiltration",
        difficulty="hard",
        alert={
            "alert_id": "FS-005",
            "category": "data_exfiltration",
            "severity": "critical",
            "title": "Large Data Transfer to External Cloud",
            "description": "500MB upload to personal Dropbox account by finance user at 2 AM. Data includes files from restricted finance share containing PII.",
            "indicators": {
                "destination": "dropbox.com",
                "data_size_mb": 500,
                "file_types": [".xlsx", ".pdf", ".csv"],
                "source_directory": "\\\\FINANCE-FS\\Restricted\\",
            },
            "user_context": {
                "username": "finance_analyst",
                "department": "Finance",
                "risk_level": "medium",
            },
            "environmental_context": {"local_time": "02:15:00", "is_business_hours": False},
        },
        triage={
            "decision": "escalate",
            "priority": 1,
            "reasoning": "Off-hours transfer of restricted PII data to personal cloud storage indicates potential insider threat or compromised account. Immediate response required due to PII exposure.",
            "recommended_actions": [
                "Immediately block user's cloud access",
                "Preserve all forensic evidence",
                "Contact user's manager and HR",
                "Engage legal for potential breach notification",
                "Full forensic analysis of user's activity",
            ],
        },
    ),
]


class PromptManager:
    """Manages prompt variants, few-shot examples, and thresholds.

    Provides dynamic prompt construction with configurable behavior.

    """

    def __init__(
        self,
        variant: str = "default",
        thresholds: Optional[DecisionThresholds] = None,
        seed: Optional[int] = None,
    ):
        """Initialize the prompt manager.

        Args:
            variant: Prompt variant name
            thresholds: Decision thresholds
            seed: Random seed for example selection

        """
        if variant not in PROMPT_VARIANTS:
            raise ValueError(
                f"Unknown variant: {variant}. Available: {list(PROMPT_VARIANTS.keys())}"
            )

        self.variant = PROMPT_VARIANTS[variant]
        self.thresholds = thresholds or DecisionThresholds()
        self._rng = random.Random(seed)

    @property
    def system_prompt(self) -> str:
        """Get the current system prompt."""
        return self.variant.system_prompt

    def get_variant_info(self) -> dict[str, Any]:
        """Get information about current variant."""
        return {
            "name": self.variant.name,
            "description": self.variant.description,
            "tags": self.variant.tags,
        }

    @classmethod
    def list_variants(cls) -> list[dict[str, Any]]:
        """List all available prompt variants."""
        return [
            {
                "name": v.name,
                "description": v.description,
                "tags": v.tags,
            }
            for v in PROMPT_VARIANTS.values()
        ]

    def get_few_shot_examples(
        self,
        count: int = 3,
        category: Optional[str] = None,
        difficulty: Optional[str] = None,
        balanced: bool = True,
    ) -> list[FewShotExample]:
        """Get few-shot examples.

        Args:
            count: Number of examples to return
            category: Filter by category
            difficulty: Filter by difficulty
            balanced: Try to balance across decisions

        Returns:
            List of FewShotExample objects

        """
        examples = FEW_SHOT_EXAMPLES.copy()

        if category:
            examples = [e for e in examples if e.category == category]

        if difficulty:
            examples = [e for e in examples if e.difficulty == difficulty]

        if balanced:
            # Group by decision
            by_decision: dict[str, list[FewShotExample]] = {}
            for ex in examples:
                decision = ex.triage["decision"]
                if decision not in by_decision:
                    by_decision[decision] = []
                by_decision[decision].append(ex)

            # Take from each decision type
            selected: list[FewShotExample] = []
            decisions = list(by_decision.keys())
            idx = 0
            while len(selected) < count and any(by_decision.values()):
                decision = decisions[idx % len(decisions)]
                if by_decision[decision]:
                    selected.append(by_decision[decision].pop(0))
                idx += 1

            return selected[:count]

        self._rng.shuffle(examples)
        return examples[:count]

    def format_few_shot_examples(
        self,
        examples: list[FewShotExample],
    ) -> str:
        """Format few-shot examples for inclusion in prompt.

        Args:
            examples: List of examples to format

        Returns:
            Formatted examples string

        """
        formatted = ["## Reference Examples\n"]

        for i, ex in enumerate(examples, 1):
            formatted.append(f"### Example {i}: {ex.alert.get('title', 'Alert')}")
            formatted.append(f"**Category:** {ex.category}")
            formatted.append(f"**Severity:** {ex.alert.get('severity', 'unknown')}")
            formatted.append(f"**Description:** {ex.alert.get('description', 'N/A')}")
            formatted.append("")
            formatted.append("**Triage Result:**")
            formatted.append(f"- Decision: {ex.triage['decision']}")
            formatted.append(f"- Priority: {ex.triage['priority']}")
            formatted.append(f"- Reasoning: {ex.triage['reasoning']}")
            formatted.append("")

        return "\n".join(formatted)

    def build_system_prompt(
        self,
        include_thresholds: bool = False,
        include_examples: int = 0,
        additional_context: Optional[str] = None,
    ) -> str:
        """Build complete system prompt with optional components.

        Args:
            include_thresholds: Include decision thresholds
            include_examples: Number of few-shot examples to include
            additional_context: Additional context to append

        Returns:
            Complete system prompt

        """
        parts = [self.variant.system_prompt]

        if include_thresholds:
            parts.append(self.thresholds.to_prompt_context())

        if include_examples > 0:
            examples = self.get_few_shot_examples(include_examples)
            parts.append(self.format_few_shot_examples(examples))

        if additional_context:
            parts.append(additional_context)

        return "\n\n".join(parts)

    def apply_threshold_adjustments(
        self,
        prediction: dict[str, Any],
        alert: dict[str, Any],
    ) -> dict[str, Any]:
        """Apply threshold-based adjustments to prediction.

        Args:
            prediction: Original model prediction
            alert: Alert context

        Returns:
            Adjusted prediction

        """
        adjusted = prediction.copy()
        priority = adjusted.get("priority", 3)

        # VIP boost
        user_ctx = alert.get("user_context", {})
        if user_ctx.get("is_vip"):
            priority = max(1, priority - self.thresholds.vip_priority_boost)

        # Critical asset boost
        asset_ctx = alert.get("asset_context", {})
        if asset_ctx.get("criticality") == "critical":
            priority = max(1, priority - self.thresholds.critical_asset_priority_boost)

        # Escalation category override
        category = alert.get("category", "")
        if (
            category in self.thresholds.escalate_categories
            and adjusted.get("decision") == "investigate"
            and priority <= self.thresholds.escalate_min_priority
        ):
            # Upgrade to escalate for these categories
            adjusted["decision"] = "escalate"
            adjusted["escalation_required"] = True

        adjusted["priority"] = priority

        return adjusted


def run_ab_test(
    model: Any,
    alerts: list[dict[str, Any]],
    variants: Optional[list[str]] = None,
    metrics_callback: Optional[Callable[..., Any]] = None,
) -> dict[str, Any]:
    """Run A/B test across prompt variants.

    Args:
        model: SOCTriageModel instance
        alerts: List of test alerts
        variants: Variants to test (default: all)
        metrics_callback: Optional callback for each prediction

    Returns:
        Results by variant

    """
    variants = variants or list(PROMPT_VARIANTS.keys())
    results: dict[str, Any] = {}

    for variant_name in variants:
        manager = PromptManager(variant=variant_name)

        variant_results: dict[str, Any] = {
            "predictions": [],
            "avg_confidence": 0.0,
            "decision_distribution": {},
        }

        for alert in alerts:
            # Update model's system prompt
            original_prompt = model.SYSTEM_PROMPT
            model.SYSTEM_PROMPT = manager.system_prompt

            try:
                prediction = model.predict(alert)
                variant_results["predictions"].append(prediction.to_dict())

                # Track decision distribution
                decision = prediction.decision
                variant_results["decision_distribution"][decision] = (
                    variant_results["decision_distribution"].get(decision, 0) + 1
                )

                if metrics_callback:
                    metrics_callback(variant_name, alert, prediction)

            finally:
                model.SYSTEM_PROMPT = original_prompt

        # Calculate averages
        if variant_results["predictions"]:
            confidences = [p.get("confidence", 0) for p in variant_results["predictions"]]
            variant_results["avg_confidence"] = sum(confidences) / len(confidences)

        results[variant_name] = variant_results

    return results
