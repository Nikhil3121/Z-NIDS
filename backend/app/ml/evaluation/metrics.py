"""Evaluation metrics for open-set (known + unknown) intrusion detection."""

from __future__ import annotations

from typing import Any

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

CLASSES = ("NORMAL", "KNOWN_ATTACK", "ANOMALOUS", "POTENTIAL_UNKNOWN")


def _safe_div(a: float, b: float) -> float | None:
    return round(a / b, 6) if b else None


def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, scores: np.ndarray | None = None) -> dict[str, Any]:
    """y_true/y_pred: 1 = attack. Scores are used for threshold-free AUCs."""
    y_true = y_true.astype(bool)
    y_pred = y_pred.astype(bool)
    tp = int(np.sum(y_true & y_pred))
    fp = int(np.sum(~y_true & y_pred))
    fn = int(np.sum(y_true & ~y_pred))
    tn = int(np.sum(~y_true & ~y_pred))
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = (
        round(2 * precision * recall / (precision + recall), 6)
        if precision is not None and recall is not None and (precision + recall) > 0
        else None
    )
    out: dict[str, Any] = {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": _safe_div(fp, fp + tn),
        "detection_rate": recall,
    }
    if scores is not None and 0 < y_true.sum() < len(y_true):
        out["roc_auc"] = round(float(roc_auc_score(y_true, scores)), 6)
        out["pr_auc"] = round(float(average_precision_score(y_true, scores)), 6)
    else:
        # AUCs are undefined with a single class; say so rather than report 0/1.
        out["roc_auc"] = None
        out["pr_auc"] = None
    return out


def confusion(true_labels: np.ndarray, predicted: np.ndarray) -> dict[str, dict[str, int]]:
    matrix: dict[str, dict[str, int]] = {}
    for label in sorted(set(true_labels.tolist())):
        mask = true_labels == label
        matrix[label] = {c: int(np.sum(predicted[mask] == c)) for c in CLASSES}
    return matrix


def detection_latency(
    ts: np.ndarray, episodes: np.ndarray, flagged: np.ndarray
) -> dict[str, dict[str, float | int | None]]:
    """Per attack episode: time and flow count from its first flow to its first flagged flow."""
    out: dict[str, dict[str, float | int | None]] = {}
    for ep in sorted({e for e in episodes.tolist() if e}):
        idx = np.flatnonzero(episodes == ep)
        idx = idx[np.argsort(ts[idx], kind="stable")]
        hits = np.flatnonzero(flagged[idx])
        if len(hits) == 0:
            out[ep] = {
                "flows": len(idx),
                "detected": 0,
                "seconds_to_first_detection": None,
                "flows_before_first_detection": None,
            }
        else:
            first = hits[0]
            out[ep] = {
                "flows": len(idx),
                "detected": len(hits),
                "seconds_to_first_detection": round(float(ts[idx[first]] - ts[idx[0]]), 3),
                "flows_before_first_detection": int(first),
            }
    return out
