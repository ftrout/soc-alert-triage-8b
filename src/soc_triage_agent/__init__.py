"""SOC Triage Agent - Security Operations Center Alert Triage Model.
================================================================

A fine-tuned language model for automated security alert triage,
designed for Security Operations Centers (SOC).

Features:
- 12 security alert categories
- 5 triage decision types
- Context-aware priority assignment
- Actionable recommendations

License: Apache 2.0
"""

__version__ = "1.0.0"
__author__ = "SOC Triage Agent Contributors"
__license__ = "Apache-2.0"

from .ait_dataset import AITDatasetLoader
from .data_generator import (
    AlertCategory,
    SecurityAlertGenerator,
    Severity,
    TriageDecision,
)
from .evaluation import TriageEvaluator
from .model import SOCTriageModel

__all__ = [
    "SecurityAlertGenerator",
    "AITDatasetLoader",
    "AlertCategory",
    "Severity",
    "TriageDecision",
    "SOCTriageModel",
    "TriageEvaluator",
    "__version__",
]
