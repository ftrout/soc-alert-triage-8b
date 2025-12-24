"""
Tests for the Security Alert Data Generator
"""

import json

import pytest

from soc_triage_agent import (
    AlertCategory,
    SecurityAlertGenerator,
    Severity,
    TriageDecision,
)


@pytest.fixture
def generator():
    """Create a seeded generator for reproducible tests."""
    return SecurityAlertGenerator(seed=42)


class TestSecurityAlertGenerator:
    """Tests for SecurityAlertGenerator class."""

    def test_init_with_seed(self):
        """Test generator initialization with seed."""
        gen1 = SecurityAlertGenerator(seed=42)
        gen2 = SecurityAlertGenerator(seed=42)

        alert1, _ = gen1.generate_alert()
        alert2, _ = gen2.generate_alert()

        assert alert1.category == alert2.category
        assert alert1.severity == alert2.severity

    def test_init_without_seed(self):
        """Test generator initialization without seed."""
        gen = SecurityAlertGenerator()
        alert, triage = gen.generate_alert()

        assert alert is not None
        assert triage is not None

    def test_generate_alert_returns_tuple(self, generator):
        """Test that generate_alert returns alert and triage tuple."""
        result = generator.generate_alert()

        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_generate_alert_with_category(self, generator):
        """Test generating alert with specific category."""
        alert, triage = generator.generate_alert(category=AlertCategory.MALWARE)

        assert alert.category == "malware"

    def test_generate_alert_with_severity(self, generator):
        """Test generating alert with specific severity."""
        alert, triage = generator.generate_alert(severity=Severity.CRITICAL)

        assert alert.severity == "critical"

    def test_alert_has_required_fields(self, generator):
        """Test that generated alerts have all required fields."""
        alert, _ = generator.generate_alert()

        assert alert.alert_id is not None
        assert alert.timestamp is not None
        assert alert.source_system is not None
        assert alert.category is not None
        assert alert.severity is not None
        assert alert.title is not None
        assert alert.description is not None
        assert alert.indicators is not None
        assert alert.user_context is not None
        assert alert.asset_context is not None

    def test_triage_has_required_fields(self, generator):
        """Test that generated triage has all required fields."""
        _, triage = generator.generate_alert()

        assert triage.decision is not None
        assert triage.priority is not None
        assert triage.confidence_score is not None
        assert triage.reasoning is not None
        assert triage.recommended_actions is not None

    def test_triage_decision_valid(self, generator):
        """Test that triage decision is one of valid options."""
        valid_decisions = ["escalate", "investigate", "monitor", "false_positive", "close"]

        for _ in range(100):
            _, triage = generator.generate_alert()
            assert triage.decision in valid_decisions

    def test_triage_priority_in_range(self, generator):
        """Test that priority is between 1 and 5."""
        for _ in range(100):
            _, triage = generator.generate_alert()
            assert 1 <= triage.priority <= 5

    def test_triage_confidence_in_range(self, generator):
        """Test that confidence score is between 0 and 1."""
        for _ in range(100):
            _, triage = generator.generate_alert()
            assert 0.0 <= triage.confidence_score <= 1.0

    def test_all_categories_can_be_generated(self, generator):
        """Test that all alert categories can be generated."""
        for category in AlertCategory:
            alert, triage = generator.generate_alert(category=category)
            assert alert.category == category.value

    def test_all_severities_can_be_generated(self, generator):
        """Test that all severity levels can be generated."""
        for severity in Severity:
            alert, triage = generator.generate_alert(severity=severity)
            assert alert.severity == severity.value


class TestDatasetGeneration:
    """Tests for dataset generation functionality."""

    def test_generate_dataset_size(self, generator):
        """Test that dataset has correct number of samples."""
        samples = generator.generate_dataset(num_samples=50)
        assert len(samples) == 50

    def test_generate_dataset_balanced(self, generator):
        """Test balanced dataset generation."""
        samples = generator.generate_dataset(
            num_samples=120,  # 10 per category
            balanced=True,
            include_metadata=True,
        )

        categories = [s["_metadata"]["alert"]["category"] for s in samples]
        category_counts = {}
        for cat in categories:
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Should have all 12 categories
        assert len(category_counts) == 12

        # Each should have roughly 10 samples
        for count in category_counts.values():
            assert 8 <= count <= 12

    def test_generate_dataset_chat_format(self, generator):
        """Test chat format output."""
        samples = generator.generate_dataset(num_samples=5, format_type="chat")

        for sample in samples:
            assert "messages" in sample
            assert len(sample["messages"]) == 3
            assert sample["messages"][0]["role"] == "system"
            assert sample["messages"][1]["role"] == "user"
            assert sample["messages"][2]["role"] == "assistant"

    def test_generate_dataset_instruction_format(self, generator):
        """Test instruction format output."""
        samples = generator.generate_dataset(num_samples=5, format_type="instruction")

        for sample in samples:
            assert "instruction" in sample
            assert "input" in sample
            assert "output" in sample

    def test_generate_dataset_sharegpt_format(self, generator):
        """Test ShareGPT format output."""
        samples = generator.generate_dataset(num_samples=5, format_type="sharegpt")

        for sample in samples:
            assert "conversations" in sample
            assert len(sample["conversations"]) == 3

    def test_generate_dataset_with_metadata(self, generator):
        """Test dataset with metadata included."""
        samples = generator.generate_dataset(
            num_samples=5,
            include_metadata=True,
        )

        for sample in samples:
            assert "_metadata" in sample
            assert "alert" in sample["_metadata"]
            assert "triage" in sample["_metadata"]

    def test_save_dataset_jsonl(self, generator, tmp_path):
        """Test saving dataset to JSONL file."""
        output_file = tmp_path / "test_dataset.jsonl"
        samples = generator.generate_dataset(num_samples=10)

        generator.save_dataset(samples, str(output_file), format="jsonl")

        assert output_file.exists()

        # Verify content
        loaded = []
        with open(output_file) as f:
            for line in f:
                loaded.append(json.loads(line))

        assert len(loaded) == 10

    def test_save_dataset_json(self, generator, tmp_path):
        """Test saving dataset to JSON file."""
        output_file = tmp_path / "test_dataset.json"
        samples = generator.generate_dataset(num_samples=10)

        generator.save_dataset(samples, str(output_file), format="json")

        assert output_file.exists()

        with open(output_file) as f:
            loaded = json.load(f)

        assert len(loaded) == 10


class TestTriageLogic:
    """Tests for triage decision logic."""

    def test_critical_severity_escalates(self, generator):
        """Test that critical severity alerts tend to escalate."""
        escalate_count = 0
        total = 50

        for _ in range(total):
            _, triage = generator.generate_alert(severity=Severity.CRITICAL)
            if triage.decision == "escalate":
                escalate_count += 1

        # Most critical alerts should escalate
        assert escalate_count >= total * 0.7

    def test_lateral_movement_escalates(self, generator):
        """Test that lateral movement alerts typically escalate."""
        escalate_count = 0
        total = 50

        for _ in range(total):
            _, triage = generator.generate_alert(category=AlertCategory.LATERAL_MOVEMENT)
            if triage.decision == "escalate":
                escalate_count += 1

        # Lateral movement should almost always escalate
        assert escalate_count >= total * 0.8

    def test_informational_severity_rarely_escalates(self, generator):
        """Test that informational alerts rarely escalate."""
        escalate_count = 0
        total = 50

        for _ in range(total):
            _, triage = generator.generate_alert(severity=Severity.INFORMATIONAL)
            if triage.decision == "escalate":
                escalate_count += 1

        # Informational alerts should escalate less than critical/high severity
        # Allow up to 50% as some categories may still escalate for context reasons
        assert escalate_count <= total * 0.5


class TestEnums:
    """Tests for enum classes."""

    def test_severity_priority_weight(self):
        """Test severity priority weights."""
        assert Severity.CRITICAL.priority_weight == 1
        assert Severity.HIGH.priority_weight == 2
        assert Severity.MEDIUM.priority_weight == 3
        assert Severity.LOW.priority_weight == 4
        assert Severity.INFORMATIONAL.priority_weight == 5

    def test_triage_decision_requires_action(self):
        """Test which decisions require action."""
        assert TriageDecision.ESCALATE.requires_action is True
        assert TriageDecision.INVESTIGATE.requires_action is True
        assert TriageDecision.MONITOR.requires_action is False
        assert TriageDecision.FALSE_POSITIVE.requires_action is False
        assert TriageDecision.CLOSE.requires_action is False

    def test_alert_category_mitre_tactics(self):
        """Test MITRE ATT&CK tactic mappings."""
        assert "TA0008" in AlertCategory.LATERAL_MOVEMENT.mitre_tactics
        assert "TA0011" in AlertCategory.COMMAND_AND_CONTROL.mitre_tactics
        assert "TA0006" in AlertCategory.BRUTE_FORCE.mitre_tactics


class TestSerialization:
    """Tests for serialization methods."""

    def test_alert_to_dict(self, generator):
        """Test alert serialization to dictionary."""
        alert, _ = generator.generate_alert()
        alert_dict = alert.to_dict()

        assert isinstance(alert_dict, dict)
        assert "alert_id" in alert_dict
        assert "category" in alert_dict

    def test_alert_to_json(self, generator):
        """Test alert serialization to JSON."""
        alert, _ = generator.generate_alert()
        alert_json = alert.to_json()

        assert isinstance(alert_json, str)
        parsed = json.loads(alert_json)
        assert "alert_id" in parsed

    def test_triage_to_dict(self, generator):
        """Test triage serialization to dictionary."""
        _, triage = generator.generate_alert()
        triage_dict = triage.to_dict()

        assert isinstance(triage_dict, dict)
        assert "decision" in triage_dict
        assert "priority" in triage_dict

    def test_triage_to_json(self, generator):
        """Test triage serialization to JSON."""
        _, triage = generator.generate_alert()
        triage_json = triage.to_json()

        assert isinstance(triage_json, str)
        parsed = json.loads(triage_json)
        assert "decision" in parsed


class TestStatistics:
    """Tests for dataset statistics."""

    def test_get_statistics(self, generator):
        """Test statistics calculation."""
        samples = generator.generate_dataset(
            num_samples=100,
            include_metadata=True,
        )

        stats = generator.get_statistics(samples)

        assert stats["total_samples"] == 100
        assert "categories" in stats
        assert "severities" in stats
        assert "decisions" in stats
        assert sum(stats["categories"].values()) == 100
