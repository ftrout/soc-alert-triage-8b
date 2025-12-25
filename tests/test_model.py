"""
Unit tests for SOCTriageModel inference.
"""

import json
import pytest
from unittest.mock import MagicMock, patch

from soc_triage_agent.model import (
    SOCTriageModel,
    TriagePrediction,
    TriageModelError,
    ModelNotLoadedError,
    InferenceError,
    ResponseParsingError,
)


class TestTriagePrediction:
    """Tests for the TriagePrediction dataclass."""

    def test_prediction_creation(self):
        """Test creating a TriagePrediction."""
        pred = TriagePrediction(
            decision="escalate",
            priority=1,
            confidence=0.95,
            reasoning="Critical malware detected",
            recommended_actions=["Isolate host", "Collect forensics"],
            escalation_required=True,
            escalation_target="Tier 3 SOC",
            estimated_impact="critical",
            raw_output="Full response text",
        )

        assert pred.decision == "escalate"
        assert pred.priority == 1
        assert pred.confidence == 0.95
        assert pred.escalation_required is True
        assert len(pred.recommended_actions) == 2

    def test_prediction_to_dict(self):
        """Test converting prediction to dictionary."""
        pred = TriagePrediction(
            decision="investigate",
            priority=2,
            confidence=0.85,
            reasoning="Suspicious activity detected",
            recommended_actions=["Review logs"],
            escalation_required=False,
            escalation_target=None,
            estimated_impact="moderate",
            raw_output="test",
        )

        result = pred.to_dict()

        assert isinstance(result, dict)
        assert result["decision"] == "investigate"
        assert result["priority"] == 2
        assert result["confidence"] == 0.85


class TestSOCTriageModelInitialization:
    """Tests for SOCTriageModel initialization."""

    def test_default_initialization(self):
        """Test default model initialization."""
        model = SOCTriageModel()

        assert model.model_type == "transformers"
        assert model.model is None
        assert model.tokenizer is None

    def test_initialization_with_model_type(self):
        """Test initialization with specific model type."""
        model = SOCTriageModel(model_type="openai")

        assert model.model_type == "openai"


class TestSOCTriageModelExceptions:
    """Tests for custom exceptions."""

    def test_triage_model_error(self):
        """Test base exception."""
        with pytest.raises(TriageModelError):
            raise TriageModelError("Test error")

    def test_model_not_loaded_error(self):
        """Test ModelNotLoadedError is subclass of TriageModelError."""
        with pytest.raises(TriageModelError):
            raise ModelNotLoadedError("Model not loaded")

    def test_inference_error(self):
        """Test InferenceError is subclass of TriageModelError."""
        with pytest.raises(TriageModelError):
            raise InferenceError("Inference failed")

    def test_response_parsing_error(self):
        """Test ResponseParsingError is subclass of TriageModelError."""
        with pytest.raises(TriageModelError):
            raise ResponseParsingError("Parsing failed")


class TestSOCTriageModelPredict:
    """Tests for the predict method."""

    def test_predict_without_loaded_model(self):
        """Test that predict raises error when model not loaded."""
        model = SOCTriageModel()

        with pytest.raises(ModelNotLoadedError):
            model.predict({"category": "malware", "severity": "high"})

    def test_predict_without_api_client(self):
        """Test that API predict raises error when client not initialized."""
        model = SOCTriageModel(model_type="openai")

        with pytest.raises(ModelNotLoadedError):
            model.predict({"category": "malware", "severity": "high"})


class TestParseResponse:
    """Tests for the parse_response method."""

    @pytest.fixture
    def model(self):
        """Create a model instance for testing."""
        return SOCTriageModel()

    def test_parse_complete_response(self, model):
        """Test parsing a complete response with markdown format."""
        response = """## Triage Summary

| Field | Value |
|-------|-------|
| **Decision** | escalate |
| **Priority** | 1 |
| **Confidence** | 95 |
| **Escalation Required** | Yes |
| **Escalation Target** | Incident Response Team |
| **Estimated Impact** | critical |

### Reasoning
Critical malware detected on a high-value asset.

### Recommended Actions
1. Isolate the host immediately
2. Collect memory dump
3. Review network connections
"""

        result = model.parse_response(response)

        assert result.decision == "escalate"
        assert result.priority == 1
        assert result.confidence == 0.95
        assert result.escalation_required is True
        assert "Incident Response Team" in result.escalation_target
        assert len(result.recommended_actions) >= 3

    def test_parse_response_with_explicit_no_escalation(self, model):
        """Test parsing response with explicit no escalation."""
        response = """
| **Decision** | investigate |
| **Priority** | 2 |
| **Escalation Required** | No |
"""

        result = model.parse_response(response)

        assert result.decision == "investigate"
        assert result.escalation_required is False

    def test_parse_malformed_response(self, model):
        """Test parsing a malformed response returns defaults."""
        response = "This is not a valid triage response"

        result = model.parse_response(response)

        # Should return with default values
        assert result.decision == "investigate"
        assert result.priority == 3
        assert result.raw_output == response

    def test_parse_empty_response(self, model):
        """Test parsing an empty response."""
        result = model.parse_response("")

        assert result.decision == "investigate"
        assert result.priority == 3

    def test_parse_none_response(self, model):
        """Test parsing a None response."""
        result = model.parse_response(None)

        assert result.decision == "investigate"
        assert result.priority == 3

    def test_priority_valid_range(self, model):
        """Test that priority values in valid range are preserved."""
        response = """
| **Decision** | monitor |
| **Priority** | 4 |
"""
        result = model.parse_response(response)

        assert result.priority == 4

    def test_confidence_parsing(self, model):
        """Test confidence is parsed and normalized."""
        response = """
| **Decision** | escalate |
| **Priority** | 1 |
| **Confidence** | 95 |
"""
        result = model.parse_response(response)

        assert result.confidence == 0.95


class TestFormatAlert:
    """Tests for alert formatting."""

    @pytest.fixture
    def model(self):
        """Create a model instance for testing."""
        return SOCTriageModel()

    def test_format_dict_alert(self, model):
        """Test formatting a dictionary alert."""
        alert = {
            "alert_id": "alert-001",
            "category": "malware",
            "severity": "critical",
            "title": "Ransomware Detected",
            "description": "Suspicious encryption activity detected",
            "indicators": {"file_hash": "abc123", "file_name": "ransom.exe"},
        }

        prompt = model.format_alert(alert)

        assert "alert-001" in prompt
        assert "malware" in prompt
        assert "critical" in prompt
        assert "Ransomware Detected" in prompt

    def test_format_alert_with_user_context(self, model):
        """Test formatting alert with user context."""
        alert = {
            "alert_id": "test-001",
            "category": "phishing",
            "severity": "high",
            "user_context": {
                "username": "jdoe",
                "department": "Finance",
                "role": "Analyst",
                "is_vip": True,
            },
        }

        prompt = model.format_alert(alert)

        assert "jdoe" in prompt
        assert "Finance" in prompt
        assert "VIP" in prompt

    def test_format_alert_with_asset_context(self, model):
        """Test formatting alert with asset context."""
        alert = {
            "alert_id": "test-002",
            "category": "lateral_movement",
            "severity": "high",
            "asset_context": {
                "hostname": "server-prod-01",
                "asset_type": "server",
                "criticality": "high",
                "data_classification": "confidential",
            },
        }

        prompt = model.format_alert(alert)

        assert "server-prod-01" in prompt
        assert "criticality" in prompt.lower()

    def test_format_string_alert(self, model):
        """Test formatting a string alert (passthrough)."""
        alert_str = "Suspicious activity detected on endpoint"

        prompt = model.format_alert({"description": alert_str})

        assert alert_str in prompt


class TestSystemPrompt:
    """Tests for system prompt configuration."""

    def test_default_system_prompt(self):
        """Test default system prompt is set."""
        model = SOCTriageModel()

        assert model.SYSTEM_PROMPT is not None
        assert "SOC" in model.SYSTEM_PROMPT or "security" in model.SYSTEM_PROMPT.lower()


class TestBatchPredict:
    """Tests for batch prediction."""

    def test_batch_predict_empty_list(self):
        """Test batch predict with empty list."""
        model = SOCTriageModel()
        model.model = MagicMock()
        model.tokenizer = MagicMock()

        results = model.batch_predict([])

        assert results == []

    def test_batch_predict_without_model(self):
        """Test batch predict raises error without loaded model."""
        model = SOCTriageModel()

        with pytest.raises(ModelNotLoadedError):
            model.batch_predict([{"category": "malware"}])


class TestSavePretrained:
    """Tests for model saving."""

    def test_save_without_model_raises_error(self):
        """Test that saving without model raises error."""
        model = SOCTriageModel(model_type="openai")

        with pytest.raises(ValueError):
            model.save_pretrained("/tmp/test-model")


class TestPushToHub:
    """Tests for Hub pushing."""

    def test_push_without_model_raises_error(self):
        """Test that pushing without model raises error."""
        model = SOCTriageModel(model_type="openai")

        with pytest.raises(ValueError):
            model.push_to_hub("test/model")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
