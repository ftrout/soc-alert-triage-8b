"""Evaluation Metrics for SOC Triage Models.
==========================================

Provides comprehensive evaluation metrics for security
alert triage models, including:
- Decision accuracy
- Priority correlation
- Escalation precision/recall
- Response quality metrics
"""

import json
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class EvaluationResult:
    """Comprehensive evaluation results."""

    # Overall metrics
    decision_accuracy: float = 0.0
    decision_f1_macro: float = 0.0
    decision_f1_weighted: float = 0.0

    # Priority metrics
    priority_mae: float = 0.0  # Mean Absolute Error
    priority_correlation: float = 0.0  # Spearman correlation
    priority_within_one: float = 0.0  # % within 1 of ground truth

    # Escalation metrics
    escalation_precision: float = 0.0
    escalation_recall: float = 0.0
    escalation_f1: float = 0.0

    # Per-category metrics
    category_metrics: dict[str, Any] = field(default_factory=dict)

    # Per-decision metrics
    decision_metrics: dict[str, dict[str, float]] = field(default_factory=dict)

    # Confusion matrix
    confusion_matrix: dict[str, dict[str, int]] = field(default_factory=dict)

    # Sample counts
    total_samples: int = 0
    correct_samples: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert evaluation results to dictionary."""
        return {
            "overall": {
                "decision_accuracy": round(self.decision_accuracy, 4),
                "decision_f1_macro": round(self.decision_f1_macro, 4),
                "decision_f1_weighted": round(self.decision_f1_weighted, 4),
            },
            "priority": {
                "mae": round(self.priority_mae, 4),
                "correlation": round(self.priority_correlation, 4),
                "within_one": round(self.priority_within_one, 4),
            },
            "escalation": {
                "precision": round(self.escalation_precision, 4),
                "recall": round(self.escalation_recall, 4),
                "f1": round(self.escalation_f1, 4),
            },
            "category_metrics": self.category_metrics,
            "decision_metrics": self.decision_metrics,
            "confusion_matrix": self.confusion_matrix,
            "sample_counts": {
                "total": self.total_samples,
                "correct": self.correct_samples,
            },
        }

    def __str__(self) -> str:
        """Return formatted string representation of results."""
        return f"""
=== SOC Triage Model Evaluation Results ===

Overall Performance:
  Decision Accuracy:     {self.decision_accuracy:.2%}
  Decision F1 (Macro):   {self.decision_f1_macro:.4f}
  Decision F1 (Weighted):{self.decision_f1_weighted:.4f}

Priority Assessment:
  Mean Absolute Error:   {self.priority_mae:.2f}
  Spearman Correlation:  {self.priority_correlation:.4f}
  Within 1 Priority:     {self.priority_within_one:.2%}

Escalation Detection:
  Precision:             {self.escalation_precision:.2%}
  Recall:                {self.escalation_recall:.2%}
  F1 Score:              {self.escalation_f1:.4f}

Samples: {self.correct_samples}/{self.total_samples} correct
"""


class TriageEvaluator:
    """Evaluator for security triage model predictions.

    Example:
        >>> evaluator = TriageEvaluator()
        >>> results = evaluator.evaluate(predictions, ground_truth)
        >>> print(results)

    """

    DECISION_LABELS = ["escalate", "investigate", "monitor", "false_positive", "close"]

    def __init__(self):
        self.predictions = []
        self.ground_truth = []

    def add_prediction(
        self,
        prediction: dict[str, Any],
        ground_truth: dict[str, Any],
        alert_category: Optional[str] = None,
    ) -> None:
        """Add a single prediction for evaluation.

        Args:
            prediction: Model prediction
            ground_truth: Ground truth labels
            alert_category: Optional category for per-category metrics

        """
        self.predictions.append(
            {
                "decision": prediction.get("decision", "").lower(),
                "priority": prediction.get("priority", 3),
                "escalation_required": prediction.get("escalation_required", False),
                "category": alert_category,
            }
        )
        self.ground_truth.append(
            {
                "decision": ground_truth.get("decision", "").lower(),
                "priority": ground_truth.get("priority", 3),
                "escalation_required": ground_truth.get("escalation_required", False),
                "category": alert_category,
            }
        )

    def reset(self) -> None:
        """Clear all predictions."""
        self.predictions = []
        self.ground_truth = []

    def _calculate_f1(
        self,
        predictions: list[str],
        ground_truth: list[str],
        labels: list[str],
        average: str = "macro",
    ) -> tuple[float, dict[str, dict[str, float]]]:
        """Calculate F1 score with per-class breakdown."""
        per_class = {}

        for label in labels:
            tp = sum(1 for p, g in zip(predictions, ground_truth) if p == label and g == label)
            fp = sum(1 for p, g in zip(predictions, ground_truth) if p == label and g != label)
            fn = sum(1 for p, g in zip(predictions, ground_truth) if p != label and g == label)

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

            support = sum(1 for g in ground_truth if g == label)

            per_class[label] = {
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "support": support,
            }

        if average == "macro":
            f1_scores = [m["f1"] for m in per_class.values() if m["support"] > 0]
            avg_f1 = sum(f1_scores) / len(f1_scores) if f1_scores else 0.0
        elif average == "weighted":
            total_support = sum(m["support"] for m in per_class.values())
            if total_support > 0:
                avg_f1 = sum(m["f1"] * m["support"] for m in per_class.values()) / total_support
            else:
                avg_f1 = 0.0
        else:
            avg_f1 = 0.0

        return avg_f1, per_class

    def _calculate_confusion_matrix(
        self,
        predictions: list[str],
        ground_truth: list[str],
        labels: list[str],
    ) -> dict[str, dict[str, int]]:
        """Calculate confusion matrix."""
        matrix = {label: dict.fromkeys(labels, 0) for label in labels}

        for pred, true in zip(predictions, ground_truth):
            if pred in labels and true in labels:
                matrix[true][pred] += 1

        return matrix

    def _spearman_correlation(self, x: list[float], y: list[float]) -> float:
        """Calculate Spearman rank correlation."""
        n = len(x)
        if n < 2:
            return 0.0

        # Rank the values
        def rank(values):
            sorted_idx = sorted(range(len(values)), key=lambda i: values[i])
            ranks = [0.0] * len(values)
            for rank_val, idx in enumerate(sorted_idx, 1):
                ranks[idx] = rank_val
            return ranks

        rank_x = rank(x)
        rank_y = rank(y)

        # Calculate Spearman correlation
        d_squared = sum((rx - ry) ** 2 for rx, ry in zip(rank_x, rank_y))
        correlation: float = 1 - (6 * d_squared) / (n * (n**2 - 1))

        return correlation

    def evaluate(
        self,
        predictions: Optional[list[dict[str, Any]]] = None,
        ground_truth: Optional[list[dict[str, Any]]] = None,
    ) -> EvaluationResult:
        """Evaluate model predictions against ground truth.

        Args:
            predictions: List of prediction dicts (uses stored if None)
            ground_truth: List of ground truth dicts (uses stored if None)

        Returns:
            EvaluationResult with comprehensive metrics

        """
        if predictions is not None and ground_truth is not None:
            self.reset()
            for pred, gt in zip(predictions, ground_truth):
                self.add_prediction(pred, gt, pred.get("category"))

        if not self.predictions:
            raise ValueError("No predictions to evaluate")

        result = EvaluationResult()
        result.total_samples = len(self.predictions)

        # Extract lists
        pred_decisions = [p["decision"] for p in self.predictions]
        true_decisions = [g["decision"] for g in self.ground_truth]
        pred_priorities = [p["priority"] for p in self.predictions]
        true_priorities = [g["priority"] for g in self.ground_truth]
        pred_escalations = [p["escalation_required"] for p in self.predictions]
        true_escalations = [g["escalation_required"] for g in self.ground_truth]

        # Decision accuracy
        result.correct_samples = sum(1 for p, g in zip(pred_decisions, true_decisions) if p == g)
        result.decision_accuracy = result.correct_samples / result.total_samples

        # Decision F1 scores
        result.decision_f1_macro, result.decision_metrics = self._calculate_f1(
            pred_decisions, true_decisions, self.DECISION_LABELS, "macro"
        )
        result.decision_f1_weighted, _ = self._calculate_f1(
            pred_decisions, true_decisions, self.DECISION_LABELS, "weighted"
        )

        # Confusion matrix
        result.confusion_matrix = self._calculate_confusion_matrix(
            pred_decisions, true_decisions, self.DECISION_LABELS
        )

        # Priority metrics
        priority_errors = [abs(p - g) for p, g in zip(pred_priorities, true_priorities)]
        result.priority_mae = sum(priority_errors) / len(priority_errors)
        result.priority_within_one = sum(1 for e in priority_errors if e <= 1) / len(
            priority_errors
        )
        result.priority_correlation = self._spearman_correlation(
            [float(p) for p in pred_priorities], [float(g) for g in true_priorities]
        )

        # Escalation metrics
        tp = sum(1 for p, g in zip(pred_escalations, true_escalations) if p and g)
        fp = sum(1 for p, g in zip(pred_escalations, true_escalations) if p and not g)
        fn = sum(1 for p, g in zip(pred_escalations, true_escalations) if not p and g)

        result.escalation_precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        result.escalation_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        if (result.escalation_precision + result.escalation_recall) > 0:
            result.escalation_f1 = (
                2
                * result.escalation_precision
                * result.escalation_recall
                / (result.escalation_precision + result.escalation_recall)
            )

        # Per-category metrics
        categories = {p.get("category") for p in self.predictions if p.get("category")}
        for category in categories:
            cat_mask = [i for i, p in enumerate(self.predictions) if p.get("category") == category]
            if not cat_mask:
                continue

            cat_pred = [pred_decisions[i] for i in cat_mask]
            cat_true = [true_decisions[i] for i in cat_mask]

            cat_correct = sum(1 for p, g in zip(cat_pred, cat_true) if p == g)
            cat_accuracy = cat_correct / len(cat_mask)

            _, cat_metrics = self._calculate_f1(cat_pred, cat_true, self.DECISION_LABELS, "macro")

            result.category_metrics[category] = {
                "accuracy": round(cat_accuracy, 4),
                "support": len(cat_mask),
                "per_decision": cat_metrics,
            }

        return result

    def evaluate_from_files(
        self,
        predictions_file: str,
        ground_truth_file: str,
    ) -> EvaluationResult:
        """Evaluate predictions from JSONL files.

        Args:
            predictions_file: Path to predictions JSONL
            ground_truth_file: Path to ground truth JSONL

        Returns:
            EvaluationResult

        """
        predictions = []
        ground_truth = []

        with open(predictions_file) as f:
            for line in f:
                predictions.append(json.loads(line))

        with open(ground_truth_file) as f:
            for line in f:
                data = json.loads(line)
                if "_metadata" in data:
                    ground_truth.append(data["_metadata"]["triage"])
                else:
                    ground_truth.append(data)

        return self.evaluate(predictions, ground_truth)

    def generate_report(
        self,
        result: EvaluationResult,
        output_file: Optional[str] = None,
    ) -> str:
        """Generate a detailed evaluation report.

        Args:
            result: Evaluation results
            output_file: Optional file to save report

        Returns:
            Report as string

        """
        report = [
            "=" * 70,
            "SOC TRIAGE MODEL EVALUATION REPORT",
            "=" * 70,
            "",
            "OVERALL PERFORMANCE",
            "-" * 40,
            f"Decision Accuracy:      {result.decision_accuracy:.2%}",
            f"Decision F1 (Macro):    {result.decision_f1_macro:.4f}",
            f"Decision F1 (Weighted): {result.decision_f1_weighted:.4f}",
            "",
            "PRIORITY ASSESSMENT",
            "-" * 40,
            f"Mean Absolute Error:    {result.priority_mae:.2f}",
            f"Spearman Correlation:   {result.priority_correlation:.4f}",
            f"Within 1 Priority:      {result.priority_within_one:.2%}",
            "",
            "ESCALATION DETECTION",
            "-" * 40,
            f"Precision:              {result.escalation_precision:.2%}",
            f"Recall:                 {result.escalation_recall:.2%}",
            f"F1 Score:               {result.escalation_f1:.4f}",
            "",
            "PER-DECISION METRICS",
            "-" * 40,
        ]

        for decision, metrics in result.decision_metrics.items():
            if metrics["support"] > 0:
                report.append(
                    f"  {decision:20} P:{metrics['precision']:.3f} "
                    f"R:{metrics['recall']:.3f} F1:{metrics['f1']:.3f} "
                    f"(n={metrics['support']})"
                )

        if result.category_metrics:
            report.extend(
                [
                    "",
                    "PER-CATEGORY METRICS",
                    "-" * 40,
                ]
            )
            for category, metrics in sorted(result.category_metrics.items()):
                report.append(
                    f"  {category:25} Accuracy: {metrics['accuracy']:.2%} (n={metrics['support']})"
                )

        report.extend(
            [
                "",
                "CONFUSION MATRIX",
                "-" * 40,
                "Rows: True labels, Columns: Predictions",
                "",
            ]
        )

        # Header
        header = "              " + " ".join(f"{d[:8]:>8}" for d in self.DECISION_LABELS)
        report.append(header)

        for true_label in self.DECISION_LABELS:
            row = f"{true_label[:12]:12}"
            for pred_label in self.DECISION_LABELS:
                count = result.confusion_matrix.get(true_label, {}).get(pred_label, 0)
                row += f" {count:>8}"
            report.append(row)

        report.extend(
            [
                "",
                "-" * 70,
                f"Total Samples: {result.total_samples}",
                f"Correctly Classified: {result.correct_samples}",
                "=" * 70,
            ]
        )

        report_text = "\n".join(report)

        if output_file:
            with open(output_file, "w") as f:
                f.write(report_text)

        return report_text


def main():
    """Run evaluation demo."""
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate SOC Triage Model")
    parser.add_argument("--predictions", required=True, help="Predictions JSONL file")
    parser.add_argument("--ground-truth", required=True, help="Ground truth JSONL file")
    parser.add_argument("--output", help="Output report file")

    args = parser.parse_args()

    evaluator = TriageEvaluator()
    result = evaluator.evaluate_from_files(args.predictions, args.ground_truth)

    report = evaluator.generate_report(result, args.output)
    print(report)

    # Also save JSON metrics
    if args.output:
        json_output = args.output.replace(".txt", ".json")
        with open(json_output, "w") as f:
            json.dump(result.to_dict(), f, indent=2)
        print(f"\nJSON metrics saved to: {json_output}")


if __name__ == "__main__":
    main()
