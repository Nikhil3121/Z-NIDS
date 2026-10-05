"""Population Stability Index for feature drift.

PSI = Σ (a_i - e_i) · ln(a_i / e_i) over quantile bins fixed on the training
(normal) distribution. Common reading: < 0.1 stable, 0.1-0.25 moderate,
> 0.25 significant shift.
"""

from __future__ import annotations

import numpy as np

EPS = 1e-4


def psi(expected: list[float], edges: list[float], actual_values: np.ndarray) -> float:
    exp = np.asarray(expected, dtype=float)
    counts = np.bincount(
        np.searchsorted(np.asarray(edges, dtype=float), actual_values, side="right"), minlength=len(exp)
    )[: len(exp)]
    act = counts / max(len(actual_values), 1)
    exp = np.clip(exp, EPS, None)
    act = np.clip(act, EPS, None)
    return float(np.sum((act - exp) * np.log(act / exp)))


def feature_psi(
    edges: dict[str, list[float]], expected: dict[str, list[float]], names: list[str], x: np.ndarray
) -> dict[str, float]:
    return {name: round(psi(expected[name], edges[name], x[:, j]), 6) for j, name in enumerate(names) if name in edges}
