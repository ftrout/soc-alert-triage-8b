"""Adversarial Example Generator for SOC Triage Models.
======================================================

Generates edge cases and challenging scenarios to improve model robustness.
These examples are designed to challenge rule-based triage logic and
expose model weaknesses.

Example:
    >>> from soc_triage_agent.adversarial import AdversarialGenerator
    >>> generator = AdversarialGenerator()
    >>> hard_cases = generator.generate_hard_cases(100)

"""

import random
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional, TypedDict, cast

from .data_generator import (
    AlertCategory,
    SecurityAlertGenerator,
    Severity,
    TriageDecision,
)


class ScenarioDict(TypedDict):
    """Type definition for adversarial scenario."""

    category: AlertCategory
    title: str
    description: str
    severity: Severity
    decision: TriageDecision
    reason: str


class AdversarialType(Enum):
    """Types of adversarial examples."""

    CONFLICTING_SIGNALS = "conflicting_signals"
    NEAR_MISS_FP = "near_miss_false_positive"
    PRIORITY_AMBIGUOUS = "priority_ambiguous"
    CATEGORY_BOUNDARY = "category_boundary"
    CONTEXT_OVERRIDE = "context_override"
    MULTI_STAGE = "multi_stage_attack"
    EVASION_PATTERN = "evasion_pattern"
    TEMPORAL_ANOMALY = "temporal_anomaly"


@dataclass
class AdversarialExample:
    """An adversarial training example."""

    alert: dict[str, Any]
    triage: dict[str, Any]
    adversarial_type: AdversarialType
    difficulty: str  # easy, medium, hard
    explanation: str  # Why this is challenging


class AdversarialGenerator:
    """Generator for adversarial and edge case examples.

    Creates challenging scenarios that test model robustness:
    - Conflicting indicators (high severity + low-risk user + critical asset)
    - Near-miss false positives (looks benign but is actually malicious)
    - Priority ambiguity (multiple valid priority levels)
    - Category boundaries (alerts that could belong to multiple categories)
    - Context overrides (where context should change the default decision)

    """

    def __init__(self, seed: Optional[int] = None):
        """Initialize the adversarial generator.

        Args:
            seed: Random seed for reproducibility

        """
        self.seed = seed
        self._rng = random.Random(seed)
        self._base_generator = SecurityAlertGenerator(seed=seed)

    def generate_hard_cases(
        self,
        num_samples: int = 100,
        difficulty_distribution: Optional[dict[str, float]] = None,
    ) -> list[AdversarialExample]:
        """Generate a set of challenging examples.

        Args:
            num_samples: Number of examples to generate
            difficulty_distribution: Distribution of difficulties
                Default: {"easy": 0.2, "medium": 0.5, "hard": 0.3}

        Returns:
            List of AdversarialExample objects

        """
        if difficulty_distribution is None:
            difficulty_distribution = {"easy": 0.2, "medium": 0.5, "hard": 0.3}

        examples = []

        # Generate by type
        generators = [
            (self._generate_conflicting_signals, 0.20),
            (self._generate_near_miss_fp, 0.15),
            (self._generate_priority_ambiguous, 0.15),
            (self._generate_category_boundary, 0.15),
            (self._generate_context_override, 0.15),
            (self._generate_multi_stage, 0.10),
            (self._generate_evasion_pattern, 0.05),
            (self._generate_temporal_anomaly, 0.05),
        ]

        for gen_func, ratio in generators:
            count = int(num_samples * ratio)
            for _ in range(count):
                difficulty = self._rng.choices(
                    list(difficulty_distribution.keys()),
                    weights=list(difficulty_distribution.values()),
                )[0]
                example = gen_func(difficulty)
                examples.append(example)

        # Fill remaining with random types
        while len(examples) < num_samples:
            gen_func, _ = self._rng.choice(generators)
            difficulty = self._rng.choices(
                list(difficulty_distribution.keys()),
                weights=list(difficulty_distribution.values()),
            )[0]
            examples.append(gen_func(difficulty))

        self._rng.shuffle(examples)
        return examples[:num_samples]

    def _generate_conflicting_signals(self, difficulty: str) -> AdversarialExample:
        """Generate alert with conflicting severity/context signals.

        Example: Critical severity alert, but user is VIP and asset is test server.
        Model must weigh competing factors.

        """
        # Pick conflicting combinations
        if difficulty == "hard":
            # High severity + very safe context
            severity = Severity.CRITICAL
            category = self._rng.choice(
                [
                    AlertCategory.MALWARE,
                    AlertCategory.PRIVILEGE_ESCALATION,
                    AlertCategory.LATERAL_MOVEMENT,
                ]
            )
            user_context = {
                "username": f"ceo_{self._rng.randint(1, 100)}",
                "department": "Executive",
                "role": "Chief Executive Officer",
                "is_vip": True,
                "is_service_account": False,
                "risk_level": "low",
                "employment_status": "active",
                "tenure_months": 120,
            }
            asset_context = {
                "hostname": f"DEV-TEST-{self._rng.randint(1, 100)}",
                "asset_type": "development",
                "criticality": "low",
                "data_classification": "public",
                "is_internet_facing": False,
            }
            # Despite scary category, context suggests lower risk
            correct_decision = TriageDecision.INVESTIGATE
            correct_priority = 2

        elif difficulty == "medium":
            # Medium severity but high-risk context
            severity = Severity.MEDIUM
            category = AlertCategory.POLICY_VIOLATION
            user_context = {
                "username": f"contractor_{self._rng.randint(1, 100)}",
                "department": "External",
                "role": "Third-party Contractor",
                "is_vip": False,
                "is_service_account": False,
                "risk_level": "high",
                "employment_status": "contractor",
                "access_level": "privileged",
            }
            asset_context = {
                "hostname": f"DB-PROD-{self._rng.randint(1, 10)}",
                "asset_type": "database_server",
                "criticality": "critical",
                "data_classification": "restricted",
                "contains_pii": True,
            }
            # Low severity but context demands attention
            correct_decision = TriageDecision.INVESTIGATE
            correct_priority = 2

        else:  # easy
            severity = Severity.LOW
            category = AlertCategory.RECONNAISSANCE
            user_context = {
                "username": f"user_{self._rng.randint(1, 1000)}",
                "department": "IT",
                "is_vip": False,
            }
            asset_context = {
                "hostname": f"WS-{self._rng.randint(1, 100)}",
                "criticality": "medium",
            }
            correct_decision = TriageDecision.MONITOR
            correct_priority = 4

        alert, _ = self._base_generator.generate_alert(
            category=category,
            severity=severity,
        )

        # Override contexts
        alert.user_context = user_context
        alert.asset_context = asset_context

        triage = {
            "decision": correct_decision.value,
            "priority": correct_priority,
            "escalation_required": correct_decision == TriageDecision.ESCALATE,
            "key_factors": [
                "Conflicting signals between alert severity and context",
                f"User context: {user_context.get('role', 'N/A')}",
                f"Asset criticality: {asset_context.get('criticality', 'N/A')}",
            ],
        }

        return AdversarialExample(
            alert=alert.__dict__,
            triage=triage,
            adversarial_type=AdversarialType.CONFLICTING_SIGNALS,
            difficulty=difficulty,
            explanation=f"Severity ({severity.value}) conflicts with context "
            f"(VIP={user_context.get('is_vip')}, "
            f"criticality={asset_context.get('criticality')})",
        )

    def _generate_near_miss_fp(self, difficulty: str) -> AdversarialExample:
        """Generate alert that looks like false positive but isn't.

        These are subtle attacks that might be dismissed as benign.

        """
        scenarios = {
            "hard": [
                {
                    "category": AlertCategory.DATA_EXFILTRATION,
                    "title": "Large file upload to approved cloud storage",
                    "description": "User uploaded 500MB to corporate OneDrive. "
                    "However, closer inspection reveals the upload occurred "
                    "at 3 AM and contains files from restricted directories.",
                    "severity": Severity.LOW,  # Intentionally low to deceive
                    "decision": TriageDecision.INVESTIGATE,
                    "reason": "Normal activity masks suspicious timing and data source",
                },
                {
                    "category": AlertCategory.PHISHING,
                    "title": "Email from known vendor domain",
                    "description": "Email received from microsoft-support.com (note: "
                    "not microsoft.com). User clicked link and entered credentials. "
                    "Domain was registered 2 days ago.",
                    "severity": Severity.MEDIUM,
                    "decision": TriageDecision.ESCALATE,
                    "reason": "Typosquatting domain with credential compromise",
                },
            ],
            "medium": [
                {
                    "category": AlertCategory.BRUTE_FORCE,
                    "title": "Failed login from user's home IP",
                    "description": "5 failed logins followed by success from IP "
                    "matching user's registered home address. Could be password "
                    "change or attacker pivoting through home network.",
                    "severity": Severity.LOW,
                    "decision": TriageDecision.INVESTIGATE,
                    "reason": "Legitimate IP but unusual pattern",
                },
            ],
            "easy": [
                {
                    "category": AlertCategory.POLICY_VIOLATION,
                    "title": "USB device connected during maintenance window",
                    "description": "USB storage device connected to workstation "
                    "during approved IT maintenance window by authorized technician.",
                    "severity": Severity.INFORMATIONAL,
                    "decision": TriageDecision.FALSE_POSITIVE,
                    "reason": "Authorized activity during maintenance window",
                },
            ],
        }

        scenario_list = scenarios.get(difficulty, scenarios["medium"])
        scenario = cast(ScenarioDict, self._rng.choice(scenario_list))

        alert, _ = self._base_generator.generate_alert(
            category=scenario["category"],
            severity=scenario["severity"],
        )

        alert.title = scenario["title"]
        alert.description = scenario["description"]

        triage = {
            "decision": scenario["decision"].value,
            "priority": 1 if scenario["decision"] == TriageDecision.ESCALATE else 3,
            "escalation_required": scenario["decision"] == TriageDecision.ESCALATE,
            "key_factors": [scenario["reason"]],
            "reasoning": scenario["reason"],
        }

        return AdversarialExample(
            alert=alert.__dict__,
            triage=triage,
            adversarial_type=AdversarialType.NEAR_MISS_FP,
            difficulty=difficulty,
            explanation=f"Appears benign due to {scenario['severity'].value} severity "
            f"but requires {scenario['decision'].value}",
        )

    def _generate_priority_ambiguous(self, difficulty: str) -> AdversarialExample:
        """Generate alert where multiple priority levels could be valid.

        Tests model's ability to make consistent priority decisions.

        """
        category = self._rng.choice(list(AlertCategory))
        severity = self._rng.choice([Severity.MEDIUM, Severity.HIGH])

        alert, base_triage = self._base_generator.generate_alert(
            category=category,
            severity=severity,
        )

        # Add competing priority factors
        if difficulty == "hard":
            # Add factors that pull in opposite directions
            alert.environment_context = {
                "is_business_hours": False,  # Lower priority
                "active_incident": True,  # Higher priority
                "change_window": True,  # Lower priority (expected changes)
                "threat_intel_match": True,  # Higher priority
            }
            alert.related_alerts = [
                "ALERT-RELATED-001",
                "ALERT-RELATED-002",
                "ALERT-RELATED-003",
            ]
            # Priority could validly be 1, 2, or 3
            valid_priorities = [1, 2, 3]

        elif difficulty == "medium":
            alert.environment_context = {
                "is_business_hours": True,
                "active_incident": False,
            }
            valid_priorities = [2, 3]

        else:
            valid_priorities = [3, 4]

        chosen_priority = self._rng.choice(valid_priorities)

        triage = {
            "decision": base_triage.decision,
            "priority": chosen_priority,
            "escalation_required": chosen_priority == 1,
            "key_factors": [
                "Multiple valid priority interpretations",
                f"Severity: {severity.value}",
                f"Valid priorities: {valid_priorities}",
            ],
        }

        return AdversarialExample(
            alert=alert.__dict__,
            triage=triage,
            adversarial_type=AdversarialType.PRIORITY_AMBIGUOUS,
            difficulty=difficulty,
            explanation=f"Priority could validly be {valid_priorities}, chose {chosen_priority}",
        )

    def _generate_category_boundary(self, difficulty: str) -> AdversarialExample:
        """Generate alert that spans multiple categories.

        Tests model's category discrimination.

        """
        # Define category overlaps
        overlaps = [
            (AlertCategory.MALWARE, AlertCategory.COMMAND_AND_CONTROL),
            (AlertCategory.PRIVILEGE_ESCALATION, AlertCategory.LATERAL_MOVEMENT),
            (AlertCategory.DATA_EXFILTRATION, AlertCategory.INSIDER_THREAT),
            (AlertCategory.BRUTE_FORCE, AlertCategory.RECONNAISSANCE),
            (AlertCategory.PHISHING, AlertCategory.MALWARE),
        ]

        cat1, cat2 = self._rng.choice(overlaps)

        alert, _ = self._base_generator.generate_alert(category=cat1)

        # Add indicators from second category
        if cat2 == AlertCategory.COMMAND_AND_CONTROL:
            alert.indicators["beacon_interval"] = "60s"
            alert.indicators["c2_domain"] = "suspicious-cdn.com"
        elif cat2 == AlertCategory.LATERAL_MOVEMENT:
            alert.indicators["lateral_hosts"] = ["DC-01", "FS-01"]
            alert.indicators["protocol"] = "SMB"
        elif cat2 == AlertCategory.INSIDER_THREAT:
            alert.indicators["off_hours_access"] = True
            alert.indicators["accessed_sensitive_files"] = 15

        # Primary category should drive decision
        decision = (
            TriageDecision.ESCALATE
            if cat1
            in [
                AlertCategory.LATERAL_MOVEMENT,
                AlertCategory.COMMAND_AND_CONTROL,
                AlertCategory.DATA_EXFILTRATION,
            ]
            else TriageDecision.INVESTIGATE
        )

        triage = {
            "decision": decision.value,
            "priority": 1 if decision == TriageDecision.ESCALATE else 2,
            "escalation_required": decision == TriageDecision.ESCALATE,
            "key_factors": [
                f"Primary category: {cat1.value}",
                f"Secondary indicators suggest: {cat2.value}",
                "Multi-category attack pattern",
            ],
        }

        return AdversarialExample(
            alert=alert.__dict__,
            triage=triage,
            adversarial_type=AdversarialType.CATEGORY_BOUNDARY,
            difficulty=difficulty,
            explanation=f"Alert spans {cat1.value} and {cat2.value} categories",
        )

    def _generate_context_override(self, difficulty: str) -> AdversarialExample:
        """Generate alert where context should override default decision.

        Tests model's ability to weight context properly.

        """
        # Low severity alert but critical context
        category = self._rng.choice(
            [
                AlertCategory.POLICY_VIOLATION,
                AlertCategory.RECONNAISSANCE,
            ]
        )
        severity = Severity.LOW

        alert, _ = self._base_generator.generate_alert(
            category=category,
            severity=severity,
        )

        if difficulty == "hard":
            # PCI-DSS compliance context should escalate even low severity
            alert.asset_context = {
                "hostname": "PCI-PAYMENT-01",
                "asset_type": "payment_processor",
                "criticality": "critical",
                "compliance_scope": ["PCI-DSS", "SOX"],
                "data_classification": "restricted",
            }
            alert.environment_context = {
                "compliance_audit_active": True,
                "threat_level": "elevated",
            }
            decision = TriageDecision.ESCALATE
            priority = 1
            explanation = "PCI-DSS scope + active audit overrides low severity"

        elif difficulty == "medium":
            # VIP user context elevates priority
            alert.user_context = {
                "username": "cfo_smith",
                "role": "Chief Financial Officer",
                "is_vip": True,
                "department": "Finance",
            }
            decision = TriageDecision.INVESTIGATE
            priority = 2
            explanation = "VIP user context elevates investigation priority"

        else:
            # Test environment context reduces priority
            alert.asset_context = {
                "hostname": "DEV-TEST-99",
                "criticality": "low",
                "environment": "development",
            }
            decision = TriageDecision.MONITOR
            priority = 4
            explanation = "Development environment reduces priority"

        triage = {
            "decision": decision.value,
            "priority": priority,
            "escalation_required": decision == TriageDecision.ESCALATE,
            "key_factors": [explanation],
        }

        return AdversarialExample(
            alert=alert.__dict__,
            triage=triage,
            adversarial_type=AdversarialType.CONTEXT_OVERRIDE,
            difficulty=difficulty,
            explanation=explanation,
        )

    def _generate_multi_stage(self, difficulty: str) -> AdversarialExample:
        """Generate alert that's part of a multi-stage attack.

        Individual alert might seem low risk, but pattern indicates campaign.

        """
        category = self._rng.choice(
            [
                AlertCategory.RECONNAISSANCE,
                AlertCategory.BRUTE_FORCE,
            ]
        )
        severity = Severity.MEDIUM if difficulty != "easy" else Severity.LOW

        alert, _ = self._base_generator.generate_alert(
            category=category,
            severity=severity,
        )

        # Add attack chain context
        if difficulty == "hard":
            alert.related_alerts = [
                "ALERT-CHAIN-001",
                "ALERT-CHAIN-002",
                "ALERT-CHAIN-003",
                "ALERT-CHAIN-004",
                "ALERT-CHAIN-005",
            ]
            alert.environment_context["attack_chain"] = {
                "chain": [
                    {"category": "reconnaissance", "time": "-4h"},
                    {"category": "brute_force", "time": "-2h"},
                    {"category": "privilege_escalation", "time": "-1h"},
                    {"category": "current_alert", "time": "now"},
                ],
                "attack_pattern": "APT-style intrusion chain",
                "threat_actor_profile": "advanced",
            }
            decision = TriageDecision.ESCALATE
            priority = 1
            related_count = 5

        elif difficulty == "medium":
            alert.related_alerts = [
                "ALERT-RELATED-001",
                "ALERT-RELATED-002",
                "ALERT-RELATED-003",
            ]
            alert.environment_context["similar_pattern_count"] = 3
            alert.environment_context["common_source"] = True
            decision = TriageDecision.INVESTIGATE
            priority = 2
            related_count = 3

        else:
            alert.related_alerts = ["ALERT-RELATED-001"]
            decision = TriageDecision.MONITOR
            priority = 3
            related_count = 1

        triage = {
            "decision": decision.value,
            "priority": priority,
            "escalation_required": decision == TriageDecision.ESCALATE,
            "key_factors": [
                "Part of multi-stage attack pattern",
                f"Related alerts in 24h: {related_count}",
            ],
        }

        return AdversarialExample(
            alert=alert.__dict__,
            triage=triage,
            adversarial_type=AdversarialType.MULTI_STAGE,
            difficulty=difficulty,
            explanation="Alert is part of larger attack chain",
        )

    def _generate_evasion_pattern(self, difficulty: str) -> AdversarialExample:
        """Generate alert showing attacker evasion techniques.

        Attacker trying to blend in with normal traffic.

        """
        category = AlertCategory.COMMAND_AND_CONTROL
        severity = Severity.LOW if difficulty == "hard" else Severity.MEDIUM

        alert, _ = self._base_generator.generate_alert(
            category=category,
            severity=severity,
        )

        # Add evasion indicators
        alert.indicators = {
            "protocol": "HTTPS",
            "destination": "cloudflare.com",  # Legitimate CDN
            "domain_age_days": 1500,  # Old domain
            "certificate_valid": True,
            "traffic_pattern": "matches_normal_browsing",
            # Subtle indicators of malice
            "beacon_jitter": 0.1,  # Very regular beaconing
            "packet_sizes": "consistent",  # Unusual consistency
            "timing": "every_60_seconds",  # Regular interval
        }

        if difficulty == "hard":
            alert.title = "HTTPS connection to CDN"
            alert.description = (
                "Regular HTTPS traffic to major CDN. Traffic pattern appears normal. "
                "However, packet timing shows unusual regularity (60s intervals) "
                "with minimal jitter, characteristic of C2 beaconing."
            )
            decision = TriageDecision.INVESTIGATE
            priority = 2
        else:
            decision = TriageDecision.INVESTIGATE
            priority = 3

        triage = {
            "decision": decision.value,
            "priority": priority,
            "escalation_required": False,
            "key_factors": [
                "Evasion techniques detected",
                "Traffic mimics legitimate patterns",
                "Subtle timing anomalies present",
            ],
        }

        return AdversarialExample(
            alert=alert.__dict__,
            triage=triage,
            adversarial_type=AdversarialType.EVASION_PATTERN,
            difficulty=difficulty,
            explanation="Attacker using legitimate services/traffic patterns for evasion",
        )

    def _generate_temporal_anomaly(self, difficulty: str) -> AdversarialExample:
        """Generate alert with temporal context that affects decision.

        Same alert might be benign or malicious depending on timing.

        """
        category = self._rng.choice(
            [
                AlertCategory.POLICY_VIOLATION,
                AlertCategory.BRUTE_FORCE,
            ]
        )
        severity = Severity.MEDIUM

        alert, _ = self._base_generator.generate_alert(
            category=category,
            severity=severity,
        )

        if difficulty == "hard":
            # 3 AM access by finance user during non-quarter-end
            alert.environment_context = {
                "local_time": "03:15:00",
                "is_business_hours": False,
                "is_quarter_end": False,
                "user_normal_hours": "09:00-18:00",
            }
            alert.user_context = {
                "username": "finance_user",
                "department": "Finance",
                "typical_access_hours": "business_hours",
            }
            decision = TriageDecision.INVESTIGATE
            priority = 2
            explanation = "Off-hours access by finance user outside quarter-end"

        elif difficulty == "medium":
            # Weekend access by IT admin during maintenance
            alert.environment_context = {
                "day_of_week": "Saturday",
                "is_maintenance_window": True,
            }
            alert.user_context = {
                "role": "IT Administrator",
                "on_call": True,
            }
            decision = TriageDecision.MONITOR
            priority = 4
            explanation = "Weekend access during maintenance window by on-call admin"

        else:
            alert.environment_context = {
                "is_business_hours": True,
            }
            decision = TriageDecision.MONITOR
            priority = 4
            explanation = "Normal business hours access"

        triage = {
            "decision": decision.value,
            "priority": priority,
            "escalation_required": False,
            "key_factors": [explanation],
        }

        return AdversarialExample(
            alert=alert.__dict__,
            triage=triage,
            adversarial_type=AdversarialType.TEMPORAL_ANOMALY,
            difficulty=difficulty,
            explanation=explanation,
        )

    def to_training_format(
        self,
        examples: list[AdversarialExample],
        format_type: str = "chat",
    ) -> list[dict[str, Any]]:
        """Convert adversarial examples to training format.

        Args:
            examples: List of AdversarialExample objects
            format_type: Output format (chat, instruction, etc.)

        Returns:
            List of formatted training examples

        """
        formatted = []

        for example in examples:
            # Use the base generator's formatting
            alert_obj = type("Alert", (), example.alert)()
            triage_obj = type("Triage", (), example.triage)()

            sample = self._base_generator.format_for_training(
                alert_obj,
                triage_obj,
                format_type,
            )

            # Add adversarial metadata
            sample["_metadata"] = sample.get("_metadata", {})
            sample["_metadata"]["adversarial"] = {
                "type": example.adversarial_type.value,
                "difficulty": example.difficulty,
                "explanation": example.explanation,
            }

            formatted.append(sample)

        return formatted


def main():
    """Generate adversarial examples."""
    import argparse
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Generate adversarial training examples")
    parser.add_argument("--num-samples", type=int, default=500, help="Number of examples")
    parser.add_argument("--output", type=str, default="data/adversarial.jsonl")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--format",
        choices=["chat", "instruction"],
        default="chat",
    )

    args = parser.parse_args()

    generator = AdversarialGenerator(seed=args.seed)

    print(f"Generating {args.num_samples} adversarial examples...")
    examples = generator.generate_hard_cases(args.num_samples)

    formatted = generator.to_training_format(examples, args.format)

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        for sample in formatted:
            f.write(json.dumps(sample) + "\n")

    print(f"Saved {len(formatted)} examples to {args.output}")

    # Print breakdown
    type_counts: dict[str, int] = {}
    difficulty_counts: dict[str, int] = {}

    for ex in examples:
        type_counts[ex.adversarial_type.value] = type_counts.get(ex.adversarial_type.value, 0) + 1
        difficulty_counts[ex.difficulty] = difficulty_counts.get(ex.difficulty, 0) + 1

    print("\nBy Type:")
    for t, c in sorted(type_counts.items()):
        print(f"  {t}: {c}")

    print("\nBy Difficulty:")
    for d, c in sorted(difficulty_counts.items()):
        print(f"  {d}: {c}")


if __name__ == "__main__":
    main()
