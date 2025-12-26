"""Feedback Loop API for Analyst Corrections.
=============================================

Provides mechanisms for collecting, storing, and analyzing analyst
feedback on model predictions for continuous improvement.

Features:
- Store analyst corrections
- Track accuracy over time
- Identify systematic errors
- Generate fine-tuning datasets from corrections

Example:
    >>> from soc_triage_agent.feedback import FeedbackCollector
    >>> collector = FeedbackCollector()
    >>> collector.record_correction(
    ...     alert_id="ALERT-001",
    ...     prediction=model_output,
    ...     correction={"decision": "escalate", "priority": 1},
    ...     analyst_id="analyst@company.com"
    ... )

"""

import json
import logging
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class FeedbackRecord:
    """A single feedback/correction record."""

    id: str
    timestamp: str
    alert_id: str
    alert_category: Optional[str]

    # Model prediction
    predicted_decision: str
    predicted_priority: int
    predicted_confidence: float

    # Analyst correction
    corrected_decision: Optional[str]
    corrected_priority: Optional[int]
    correction_reason: Optional[str]

    # Metadata
    analyst_id: Optional[str]
    was_correct: bool
    model_version: Optional[str]

    # Additional context
    tags: list[str] = field(default_factory=list)
    notes: Optional[str] = None


@dataclass
class FeedbackAnalytics:
    """Analytics from feedback data."""

    total_predictions: int
    total_corrections: int
    accuracy_rate: float

    # Per-decision metrics
    decision_accuracy: dict[str, float]
    decision_confusion: dict[str, dict[str, int]]

    # Priority metrics
    priority_mae: float
    priority_distribution: dict[int, int]

    # Common correction patterns
    top_correction_patterns: list[tuple[str, str, int]]  # (from, to, count)

    # Time-based metrics
    accuracy_trend: list[tuple[str, float]]  # (date, accuracy)

    # Category-specific metrics
    category_accuracy: dict[str, float]


class FeedbackCollector:
    """Collects and manages analyst feedback on model predictions.

    Provides persistent storage and analytics for continuous improvement.

    """

    def __init__(
        self,
        storage_path: str = "data/feedback.db",
        model_version: Optional[str] = None,
    ):
        """Initialize the feedback collector.

        Args:
            storage_path: Path to SQLite database
            model_version: Current model version identifier

        """
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.model_version = model_version or "unknown"
        self._init_db()

    def _init_db(self) -> None:
        """Initialize the SQLite database schema."""
        conn = sqlite3.connect(self.storage_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS feedback (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                alert_id TEXT NOT NULL,
                alert_category TEXT,
                predicted_decision TEXT NOT NULL,
                predicted_priority INTEGER NOT NULL,
                predicted_confidence REAL,
                corrected_decision TEXT,
                corrected_priority INTEGER,
                correction_reason TEXT,
                analyst_id TEXT,
                was_correct INTEGER NOT NULL,
                model_version TEXT,
                tags TEXT,
                notes TEXT,
                raw_alert TEXT,
                raw_prediction TEXT
            )
        """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_timestamp ON feedback(timestamp)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_alert_category ON feedback(alert_category)
        """
        )
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_was_correct ON feedback(was_correct)
        """
        )

        conn.commit()
        conn.close()

    def record_prediction(
        self,
        alert_id: str,
        alert: dict[str, Any],
        prediction: dict[str, Any],
        analyst_id: Optional[str] = None,
    ) -> str:
        """Record a model prediction (before analyst review).

        Args:
            alert_id: Unique alert identifier
            alert: The original alert data
            prediction: Model prediction dictionary
            analyst_id: Optional analyst ID

        Returns:
            Feedback record ID

        """
        record_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()

        conn = sqlite3.connect(self.storage_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO feedback (
                id, timestamp, alert_id, alert_category,
                predicted_decision, predicted_priority, predicted_confidence,
                was_correct, model_version, analyst_id,
                raw_alert, raw_prediction
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                record_id,
                timestamp,
                alert_id,
                alert.get("category"),
                prediction.get("decision", "investigate"),
                prediction.get("priority", 3),
                prediction.get("confidence", 0.0),
                -1,  # Unknown until reviewed
                self.model_version,
                analyst_id,
                json.dumps(alert),
                json.dumps(prediction),
            ),
        )

        conn.commit()
        conn.close()

        logger.debug(f"Recorded prediction {record_id} for alert {alert_id}")
        return record_id

    def record_correction(
        self,
        alert_id: str,
        prediction: dict[str, Any],
        correction: dict[str, Any],
        analyst_id: Optional[str] = None,
        reason: Optional[str] = None,
        alert: Optional[dict[str, Any]] = None,
        tags: Optional[list[str]] = None,
        notes: Optional[str] = None,
    ) -> str:
        """Record an analyst correction to a prediction.

        Args:
            alert_id: Unique alert identifier
            prediction: Original model prediction
            correction: Analyst's corrected values
            analyst_id: Analyst identifier
            reason: Reason for correction
            alert: Original alert data (optional)
            tags: Categorization tags
            notes: Additional notes

        Returns:
            Feedback record ID

        """
        record_id = str(uuid.uuid4())
        timestamp = datetime.utcnow().isoformat()

        # Determine if prediction was correct
        was_correct = prediction.get("decision") == correction.get("decision") and prediction.get(
            "priority"
        ) == correction.get("priority")

        conn = sqlite3.connect(self.storage_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO feedback (
                id, timestamp, alert_id, alert_category,
                predicted_decision, predicted_priority, predicted_confidence,
                corrected_decision, corrected_priority, correction_reason,
                analyst_id, was_correct, model_version, tags, notes,
                raw_alert, raw_prediction
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                record_id,
                timestamp,
                alert_id,
                alert.get("category") if alert else None,
                prediction.get("decision", "investigate"),
                prediction.get("priority", 3),
                prediction.get("confidence", 0.0),
                correction.get("decision"),
                correction.get("priority"),
                reason,
                analyst_id,
                1 if was_correct else 0,
                self.model_version,
                json.dumps(tags or []),
                notes,
                json.dumps(alert) if alert else None,
                json.dumps(prediction),
            ),
        )

        conn.commit()
        conn.close()

        logger.info(
            f"Recorded correction {record_id}: "
            f"{prediction.get('decision')} -> {correction.get('decision')}"
        )
        return record_id

    def mark_correct(
        self,
        alert_id: str,
        analyst_id: Optional[str] = None,
    ) -> bool:
        """Mark a prediction as correct (analyst confirmed).

        Args:
            alert_id: Alert ID to mark
            analyst_id: Reviewing analyst

        Returns:
            True if record was updated

        """
        conn = sqlite3.connect(self.storage_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE feedback
            SET was_correct = 1, analyst_id = COALESCE(?, analyst_id)
            WHERE alert_id = ? AND was_correct = -1
        """,
            (analyst_id, alert_id),
        )

        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()

        return updated

    def get_analytics(
        self,
        since: Optional[str] = None,
        until: Optional[str] = None,
        category: Optional[str] = None,
    ) -> FeedbackAnalytics:
        """Calculate analytics from feedback data.

        Args:
            since: Start date (ISO format)
            until: End date (ISO format)
            category: Filter by category

        Returns:
            FeedbackAnalytics with comprehensive metrics

        """
        conn = sqlite3.connect(self.storage_path)
        cursor = conn.cursor()

        # Build query conditions
        conditions = ["was_correct != -1"]  # Only reviewed records
        params: list[Any] = []

        if since:
            conditions.append("timestamp >= ?")
            params.append(since)
        if until:
            conditions.append("timestamp <= ?")
            params.append(until)
        if category:
            conditions.append("alert_category = ?")
            params.append(category)

        where_clause = " AND ".join(conditions)

        # Total predictions and corrections
        cursor.execute(
            f"""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN was_correct = 1 THEN 1 ELSE 0 END) as correct,
                SUM(CASE WHEN was_correct = 0 THEN 1 ELSE 0 END) as incorrect
            FROM feedback
            WHERE {where_clause}
        """,
            params,
        )

        row = cursor.fetchone()
        total = row[0] or 0
        correct = row[1] or 0
        incorrect = row[2] or 0

        accuracy_rate = correct / total if total > 0 else 0.0

        # Decision confusion matrix
        cursor.execute(
            f"""
            SELECT predicted_decision, corrected_decision, COUNT(*)
            FROM feedback
            WHERE {where_clause} AND corrected_decision IS NOT NULL
            GROUP BY predicted_decision, corrected_decision
        """,
            params,
        )

        decision_confusion: dict[str, dict[str, int]] = {}
        for pred, corr, count in cursor.fetchall():
            if pred not in decision_confusion:
                decision_confusion[pred] = {}
            decision_confusion[pred][corr] = count

        # Per-decision accuracy
        cursor.execute(
            f"""
            SELECT
                predicted_decision,
                COUNT(*) as total,
                SUM(CASE WHEN was_correct = 1 THEN 1 ELSE 0 END) as correct
            FROM feedback
            WHERE {where_clause}
            GROUP BY predicted_decision
        """,
            params,
        )

        decision_accuracy = {}
        for decision, dec_total, dec_correct in cursor.fetchall():
            decision_accuracy[decision] = dec_correct / dec_total if dec_total > 0 else 0.0

        # Priority MAE
        cursor.execute(
            f"""
            SELECT AVG(ABS(predicted_priority - corrected_priority))
            FROM feedback
            WHERE {where_clause} AND corrected_priority IS NOT NULL
        """,
            params,
        )

        priority_mae = cursor.fetchone()[0] or 0.0

        # Priority distribution
        cursor.execute(
            f"""
            SELECT predicted_priority, COUNT(*)
            FROM feedback
            WHERE {where_clause}
            GROUP BY predicted_priority
        """,
            params,
        )

        priority_distribution = dict(cursor.fetchall())

        # Top correction patterns
        cursor.execute(
            f"""
            SELECT predicted_decision, corrected_decision, COUNT(*) as cnt
            FROM feedback
            WHERE {where_clause} AND was_correct = 0
            GROUP BY predicted_decision, corrected_decision
            ORDER BY cnt DESC
            LIMIT 10
        """,
            params,
        )

        top_correction_patterns = [(row[0], row[1], row[2]) for row in cursor.fetchall()]

        # Accuracy trend (daily)
        cursor.execute(
            f"""
            SELECT
                DATE(timestamp) as date,
                AVG(was_correct) as accuracy
            FROM feedback
            WHERE {where_clause}
            GROUP BY DATE(timestamp)
            ORDER BY date
        """,
            params,
        )

        accuracy_trend = [(row[0], row[1]) for row in cursor.fetchall()]

        # Category accuracy
        cursor.execute(
            f"""
            SELECT
                alert_category,
                AVG(was_correct) as accuracy
            FROM feedback
            WHERE {where_clause} AND alert_category IS NOT NULL
            GROUP BY alert_category
        """,
            params,
        )

        category_accuracy = dict(cursor.fetchall())

        conn.close()

        return FeedbackAnalytics(
            total_predictions=total,
            total_corrections=incorrect,
            accuracy_rate=accuracy_rate,
            decision_accuracy=decision_accuracy,
            decision_confusion=decision_confusion,
            priority_mae=priority_mae,
            priority_distribution=priority_distribution,
            top_correction_patterns=top_correction_patterns,
            accuracy_trend=accuracy_trend,
            category_accuracy=category_accuracy,
        )

    def export_corrections(
        self,
        output_path: str,
        format_type: str = "chat",
        min_confidence: float = 0.0,
    ) -> int:
        """Export corrections as training data for fine-tuning.

        Args:
            output_path: Output file path
            format_type: Training data format
            min_confidence: Minimum prediction confidence to include

        Returns:
            Number of examples exported

        """
        conn = sqlite3.connect(self.storage_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT raw_alert, corrected_decision, corrected_priority
            FROM feedback
            WHERE was_correct = 0
                AND corrected_decision IS NOT NULL
                AND raw_alert IS NOT NULL
        """
        )

        records = cursor.fetchall()
        conn.close()

        samples = []
        for raw_alert, decision, priority in records:
            try:
                alert = json.loads(raw_alert)

                # Create corrected triage
                triage = {
                    "decision": decision,
                    "priority": priority,
                    "confidence_score": 0.95,  # Human-corrected
                    "escalation_required": decision == "escalate",
                    "key_factors": ["Analyst-corrected triage decision"],
                    "recommended_actions": [],
                    "estimated_impact": "moderate",
                }

                # Format for training (chat format)
                sample: dict[str, Any] = {
                    "messages": [
                        {
                            "role": "system",
                            "content": "You are an expert SOC analyst. Analyze alerts and provide triage decisions.",
                        },
                        {
                            "role": "user",
                            "content": f"Analyze this alert: {json.dumps(alert)}",
                        },
                        {
                            "role": "assistant",
                            "content": json.dumps(triage),
                        },
                    ],
                    "_metadata": {
                        "source": "analyst_correction",
                        "alert": alert,
                        "triage": triage,
                    },
                }
                samples.append(sample)

            except (json.JSONDecodeError, KeyError) as e:
                logger.warning(f"Failed to process correction: {e}")
                continue

        # Save
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        with open(output, "w") as f:
            for sample in samples:
                f.write(json.dumps(sample) + "\n")

        logger.info(f"Exported {len(samples)} corrections to {output_path}")
        return len(samples)

    def generate_report(self, output_path: Optional[str] = None) -> str:
        """Generate a feedback analytics report.

        Args:
            output_path: Optional file to save report

        Returns:
            Report text

        """
        analytics = self.get_analytics()

        report_lines = [
            "=" * 70,
            "KODIAK SECOPS 1 - FEEDBACK ANALYTICS REPORT",
            "=" * 70,
            "",
            f"Generated: {datetime.utcnow().isoformat()}",
            "",
            "OVERALL METRICS",
            "-" * 40,
            f"Total Reviewed Predictions: {analytics.total_predictions}",
            f"Total Corrections Made:     {analytics.total_corrections}",
            f"Overall Accuracy Rate:      {analytics.accuracy_rate:.2%}",
            f"Priority MAE:               {analytics.priority_mae:.2f}",
            "",
            "DECISION ACCURACY",
            "-" * 40,
        ]

        for decision, acc in sorted(analytics.decision_accuracy.items()):
            report_lines.append(f"  {decision:20} {acc:.2%}")

        report_lines.extend(
            [
                "",
                "TOP CORRECTION PATTERNS (Predicted -> Corrected)",
                "-" * 40,
            ]
        )

        for pred, corr, count in analytics.top_correction_patterns[:5]:
            report_lines.append(f"  {pred} -> {corr}: {count} times")

        if analytics.category_accuracy:
            report_lines.extend(
                [
                    "",
                    "CATEGORY ACCURACY",
                    "-" * 40,
                ]
            )
            for cat, acc in sorted(analytics.category_accuracy.items()):
                report_lines.append(f"  {cat:25} {acc:.2%}")

        report_lines.extend(
            [
                "",
                "=" * 70,
            ]
        )

        report = "\n".join(report_lines)

        if output_path:
            Path(output_path).write_text(report)

        return report


class FeedbackMiddleware:
    """Middleware for automatic feedback collection during inference.

    Wraps a SOCTriageModel to automatically record predictions.

    """

    def __init__(
        self,
        model: Any,
        collector: FeedbackCollector,
        auto_record: bool = True,
    ):
        """Initialize the middleware.

        Args:
            model: SOCTriageModel instance
            collector: FeedbackCollector instance
            auto_record: Automatically record all predictions

        """
        self.model = model
        self.collector = collector
        self.auto_record = auto_record

    def predict(self, alert: dict[str, Any], **kwargs) -> Any:
        """Predict with automatic feedback recording.

        Args:
            alert: Alert to triage
            **kwargs: Additional prediction arguments

        Returns:
            TriagePrediction from the model

        """
        prediction = self.model.predict(alert, **kwargs)

        if self.auto_record:
            alert_id = alert.get("alert_id", str(uuid.uuid4()))
            self.collector.record_prediction(
                alert_id=alert_id,
                alert=alert,
                prediction=prediction.to_dict(),
            )

        return prediction


def main():
    """Demo and CLI for feedback operations."""
    import argparse

    parser = argparse.ArgumentParser(description="Feedback Loop Management")
    subparsers = parser.add_subparsers(dest="command")

    # Analytics command
    analytics_parser = subparsers.add_parser("analytics", help="Show feedback analytics")
    analytics_parser.add_argument("--db", default="data/feedback.db")
    analytics_parser.add_argument("--output", help="Save report to file")

    # Export command
    export_parser = subparsers.add_parser("export", help="Export corrections for training")
    export_parser.add_argument("--db", default="data/feedback.db")
    export_parser.add_argument("--output", default="data/corrections.jsonl")
    export_parser.add_argument("--format", default="chat")

    args = parser.parse_args()

    if args.command == "analytics":
        collector = FeedbackCollector(storage_path=args.db)
        report = collector.generate_report(args.output)
        print(report)

    elif args.command == "export":
        collector = FeedbackCollector(storage_path=args.db)
        count = collector.export_corrections(args.output, args.format)
        print(f"Exported {count} corrections to {args.output}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
