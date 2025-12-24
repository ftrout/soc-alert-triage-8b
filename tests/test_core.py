"""
Unit tests for SOC Triage Agent
"""

import json
import tempfile
from pathlib import Path

import pytest

from soc_triage_agent import (
    AlertCategory,
    SecurityAlertGenerator,
    Severity,
    TriageDecision,
    TriageEvaluator,
)


class TestSecurityAlertGenerator:
    """Tests for the SecurityAlertGenerator class."""

    @pytest.fixture
    def generator(self):
        """Create a generator with fixed seed for reproducibility."""
        return SecurityAlertGenerator(seed=42)

    def test_generator_initialization(self, generator):
        """Test generator initializes correctly."""
        assert generator.seed == 42
        assert generator._alert_counter == 0

    def test_generate_single_alert(self, generator):
        """Test generating a single alert."""
        alert, triage = generator.generate_alert()

        # Check alert fields
        assert alert.alert_id is not None
        assert alert.timestamp is not None
        assert alert.category in [c.value for c in AlertCategory]
        assert alert.severity in [s.value for s in Severity]
        assert alert.title is not None
        assert alert.description is not None

        # Check triage fields
        assert triage.decision in [d.value for d in TriageDecision]
        assert 1 <= triage.priority <= 5
        assert 0.0 <= triage.confidence_score <= 1.0
        assert triage.reasoning is not None

    def test_generate_alert_with_specific_category(self, generator):
        """Test generating alert with specific category."""
        alert, triage = generator.generate_alert(category=AlertCategory.MALWARE)
        assert alert.category == "malware"

    def test_generate_alert_with_specific_severity(self, generator):
        """Test generating alert with specific severity."""
        alert, triage = generator.generate_alert(severity=Severity.CRITICAL)
        assert alert.severity == "critical"

    def test_generate_all_categories(self, generator):
        """Test that all categories can be generated."""
        for category in AlertCategory:
            alert, triage = generator.generate_alert(category=category)
            assert alert.category == category.value

    def test_generate_all_severities(self, generator):
        """Test that all severities can be generated."""
        for severity in Severity:
            alert, triage = generator.generate_alert(severity=severity)
            assert alert.severity == severity.value

    def test_alert_has_required_contexts(self, generator):
        """Test that alerts have all required context fields."""
        alert, _ = generator.generate_alert()

        # User context
        assert "username" in alert.user_context
        assert "department" in alert.user_context
        assert "is_vip" in alert.user_context

        # Asset context
        assert "hostname" in alert.asset_context
        assert "criticality" in alert.asset_context
        assert "data_classification" in alert.asset_context

        # Environment context
        assert "is_business_hours" in alert.environment_context
        assert "threat_level" in alert.environment_context

    def test_format_for_training_chat(self, generator):
        """Test formatting for chat training format."""
        alert, triage = generator.generate_alert()
        formatted = generator.format_for_training(alert, triage, format_type="chat")

        assert "messages" in formatted
        assert len(formatted["messages"]) == 3
        assert formatted["messages"][0]["role"] == "system"
        assert formatted["messages"][1]["role"] == "user"
        assert formatted["messages"][2]["role"] == "assistant"

    def test_format_for_training_instruction(self, generator):
        """Test formatting for instruction training format."""
        alert, triage = generator.generate_alert()
        formatted = generator.format_for_training(alert, triage, format_type="instruction")

        assert "instruction" in formatted
        assert "input" in formatted
        assert "output" in formatted

    def test_format_for_training_sharegpt(self, generator):
        """Test formatting for ShareGPT format."""
        alert, triage = generator.generate_alert()
        formatted = generator.format_for_training(alert, triage, format_type="sharegpt")

        assert "conversations" in formatted
        assert len(formatted["conversations"]) == 3
        assert formatted["conversations"][0]["from"] == "system"
        assert formatted["conversations"][1]["from"] == "human"
        assert formatted["conversations"][2]["from"] == "gpt"

    def test_generate_dataset(self, generator):
        """Test generating a full dataset."""
        dataset = generator.generate_dataset(num_samples=100, balanced=True)

        assert len(dataset) == 100
        assert all("messages" in sample for sample in dataset)

    def test_generate_dataset_with_metadata(self, generator):
        """Test generating dataset with metadata."""
        dataset = generator.generate_dataset(num_samples=50, include_metadata=True)

        assert all("_metadata" in sample for sample in dataset)
        assert all("alert" in sample["_metadata"] for sample in dataset)
        assert all("triage" in sample["_metadata"] for sample in dataset)

    def test_generate_balanced_dataset(self, generator):
        """Test that balanced dataset has reasonable category distribution."""
        dataset = generator.generate_dataset(
            num_samples=120, balanced=True, include_metadata=True  # 10 per category
        )

        # Count categories
        categories = [s["_metadata"]["alert"]["category"] for s in dataset]
        category_counts = {}
        for cat in categories:
            category_counts[cat] = category_counts.get(cat, 0) + 1

        # Each category should have 10 samples
        for count in category_counts.values():
            assert count == 10

    def test_save_dataset_jsonl(self, generator):
        """Test saving dataset to JSONL."""
        dataset = generator.generate_dataset(num_samples=10)

        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            output_path = f.name

        generator.save_dataset(dataset, output_path, format="jsonl")

        # Verify file
        loaded = []
        with open(output_path) as f:
            for line in f:
                loaded.append(json.loads(line))

        assert len(loaded) == 10
        Path(output_path).unlink()

    def test_save_dataset_json(self, generator):
        """Test saving dataset to JSON."""
        dataset = generator.generate_dataset(num_samples=10)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name

        generator.save_dataset(dataset, output_path, format="json")

        # Verify file
        with open(output_path) as f:
            loaded = json.load(f)

        assert len(loaded) == 10
        Path(output_path).unlink()

    def test_get_statistics(self, generator):
        """Test getting dataset statistics."""
        dataset = generator.generate_dataset(num_samples=50, include_metadata=True)

        stats = generator.get_statistics(dataset)

        assert stats["total_samples"] == 50
        assert "categories" in stats
        assert "severities" in stats
        assert "decisions" in stats

    def test_reproducibility(self):
        """Test that same seed produces same results."""
        gen1 = SecurityAlertGenerator(seed=12345)
        gen2 = SecurityAlertGenerator(seed=12345)

        alert1, triage1 = gen1.generate_alert()
        alert2, triage2 = gen2.generate_alert()

        assert alert1.category == alert2.category
        assert alert1.severity == alert2.severity
        assert triage1.decision == triage2.decision


class TestTriageEvaluator:
    """Tests for the TriageEvaluator class."""

    @pytest.fixture
    def evaluator(self):
        """Create an evaluator instance."""
        return TriageEvaluator()

    @pytest.fixture
    def sample_predictions(self):
        """Create sample predictions and ground truth."""
        predictions = [
            {"decision": "escalate", "priority": 1, "escalation_required": True},
            {"decision": "investigate", "priority": 2, "escalation_required": False},
            {"decision": "monitor", "priority": 3, "escalation_required": False},
            {"decision": "false_positive", "priority": 4, "escalation_required": False},
            {"decision": "escalate", "priority": 1, "escalation_required": True},
        ]
        ground_truth = [
            {"decision": "escalate", "priority": 1, "escalation_required": True},
            {"decision": "investigate", "priority": 2, "escalation_required": False},
            {"decision": "investigate", "priority": 3, "escalation_required": False},  # Wrong
            {"decision": "false_positive", "priority": 4, "escalation_required": False},
            {"decision": "investigate", "priority": 2, "escalation_required": False},  # Wrong
        ]
        return predictions, ground_truth

    def test_evaluator_initialization(self, evaluator):
        """Test evaluator initializes correctly."""
        assert len(evaluator.predictions) == 0
        assert len(evaluator.ground_truth) == 0

    def test_add_prediction(self, evaluator):
        """Test adding predictions."""
        pred = {"decision": "escalate", "priority": 1, "escalation_required": True}
        gt = {"decision": "escalate", "priority": 1, "escalation_required": True}

        evaluator.add_prediction(pred, gt, alert_category="malware")

        assert len(evaluator.predictions) == 1
        assert len(evaluator.ground_truth) == 1

    def test_evaluate(self, evaluator, sample_predictions):
        """Test evaluation calculation."""
        predictions, ground_truth = sample_predictions

        result = evaluator.evaluate(predictions, ground_truth)

        # Should have 3/5 correct = 60% accuracy
        assert result.decision_accuracy == 0.6
        assert result.total_samples == 5
        assert result.correct_samples == 3

    def test_evaluate_escalation_metrics(self, evaluator, sample_predictions):
        """Test escalation metrics calculation."""
        predictions, ground_truth = sample_predictions

        result = evaluator.evaluate(predictions, ground_truth)

        # Escalation: 2 predicted, 1 true
        # TP=1, FP=1, FN=0
        assert result.escalation_precision == 0.5
        assert result.escalation_recall == 1.0

    def test_evaluate_priority_metrics(self, evaluator):
        """Test priority metrics calculation."""
        predictions = [
            {"decision": "escalate", "priority": 1, "escalation_required": True},
            {"decision": "escalate", "priority": 2, "escalation_required": True},
            {"decision": "escalate", "priority": 3, "escalation_required": True},
        ]
        ground_truth = [
            {"decision": "escalate", "priority": 1, "escalation_required": True},
            {"decision": "escalate", "priority": 2, "escalation_required": True},
            {"decision": "escalate", "priority": 2, "escalation_required": True},
        ]

        result = evaluator.evaluate(predictions, ground_truth)

        # MAE: (0 + 0 + 1) / 3 = 0.333
        assert abs(result.priority_mae - 0.333) < 0.01
        # Within 1: 3/3 = 100%
        assert result.priority_within_one == 1.0

    def test_confusion_matrix(self, evaluator, sample_predictions):
        """Test confusion matrix generation."""
        predictions, ground_truth = sample_predictions

        result = evaluator.evaluate(predictions, ground_truth)

        assert "escalate" in result.confusion_matrix
        assert "investigate" in result.confusion_matrix

    def test_per_decision_metrics(self, evaluator, sample_predictions):
        """Test per-decision metrics."""
        predictions, ground_truth = sample_predictions

        result = evaluator.evaluate(predictions, ground_truth)

        assert "escalate" in result.decision_metrics
        assert "precision" in result.decision_metrics["escalate"]
        assert "recall" in result.decision_metrics["escalate"]
        assert "f1" in result.decision_metrics["escalate"]

    def test_generate_report(self, evaluator, sample_predictions):
        """Test report generation."""
        predictions, ground_truth = sample_predictions

        result = evaluator.evaluate(predictions, ground_truth)
        report = evaluator.generate_report(result)

        assert "Decision Accuracy" in report
        assert "ESCALATION" in report  # Section header is uppercase
        assert "PRIORITY" in report  # Section header is uppercase

    def test_reset(self, evaluator, sample_predictions):
        """Test resetting evaluator."""
        predictions, ground_truth = sample_predictions
        evaluator.evaluate(predictions, ground_truth)

        evaluator.reset()

        assert len(evaluator.predictions) == 0
        assert len(evaluator.ground_truth) == 0

    def test_result_to_dict(self, evaluator, sample_predictions):
        """Test result serialization."""
        predictions, ground_truth = sample_predictions

        result = evaluator.evaluate(predictions, ground_truth)
        result_dict = result.to_dict()

        assert "overall" in result_dict
        assert "priority" in result_dict
        assert "escalation" in result_dict


class TestAlertCategory:
    """Tests for AlertCategory enum."""

    def test_all_categories_exist(self):
        """Test that all expected categories exist."""
        expected = [
            "malware",
            "phishing",
            "brute_force",
            "data_exfiltration",
            "privilege_escalation",
            "lateral_movement",
            "command_and_control",
            "insider_threat",
            "policy_violation",
            "vulnerability_exploit",
            "reconnaissance",
            "denial_of_service",
        ]

        actual = [c.value for c in AlertCategory]
        assert set(expected) == set(actual)

    def test_mitre_tactics(self):
        """Test MITRE tactics mapping."""
        assert len(AlertCategory.MALWARE.mitre_tactics) > 0
        assert len(AlertCategory.LATERAL_MOVEMENT.mitre_tactics) > 0


class TestSeverity:
    """Tests for Severity enum."""

    def test_all_severities_exist(self):
        """Test that all severity levels exist."""
        expected = ["critical", "high", "medium", "low", "informational"]
        actual = [s.value for s in Severity]
        assert set(expected) == set(actual)

    def test_priority_weight(self):
        """Test priority weight ordering."""
        assert Severity.CRITICAL.priority_weight < Severity.HIGH.priority_weight
        assert Severity.HIGH.priority_weight < Severity.MEDIUM.priority_weight
        assert Severity.MEDIUM.priority_weight < Severity.LOW.priority_weight
        assert Severity.LOW.priority_weight < Severity.INFORMATIONAL.priority_weight


class TestTriageDecision:
    """Tests for TriageDecision enum."""

    def test_all_decisions_exist(self):
        """Test that all decision types exist."""
        expected = ["escalate", "investigate", "monitor", "false_positive", "close"]
        actual = [d.value for d in TriageDecision]
        assert set(expected) == set(actual)

    def test_requires_action(self):
        """Test requires_action property."""
        assert TriageDecision.ESCALATE.requires_action
        assert TriageDecision.INVESTIGATE.requires_action
        assert not TriageDecision.MONITOR.requires_action
        assert not TriageDecision.FALSE_POSITIVE.requires_action
        assert not TriageDecision.CLOSE.requires_action


class TestIntegration:
    """Integration tests for the full pipeline."""

    def test_full_pipeline(self):
        """Test full data generation and evaluation pipeline."""
        # Generate data
        generator = SecurityAlertGenerator(seed=42)
        dataset = generator.generate_dataset(num_samples=50, include_metadata=True)

        # Simulate predictions (use ground truth as predictions for testing)
        predictions = []
        ground_truth = []

        for sample in dataset:
            gt = sample["_metadata"]["triage"]
            ground_truth.append(gt)
            # Simulate mostly correct predictions
            predictions.append(gt.copy())

        # Evaluate
        evaluator = TriageEvaluator()
        result = evaluator.evaluate(predictions, ground_truth)

        # Perfect predictions should give 100% accuracy
        assert result.decision_accuracy == 1.0
        assert (
            result.escalation_precision == 1.0 or result.escalation_precision == 0.0
        )  # No escalations possible

    def test_serialization_roundtrip(self):
        """Test that generated data survives JSON roundtrip."""
        generator = SecurityAlertGenerator(seed=42)
        alert, triage = generator.generate_alert()

        # Serialize
        alert_json = alert.to_json()
        triage_json = triage.to_json()

        # Deserialize
        alert_dict = json.loads(alert_json)
        triage_dict = json.loads(triage_json)

        # Verify
        assert alert_dict["category"] == alert.category
        assert triage_dict["decision"] == triage.decision


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
