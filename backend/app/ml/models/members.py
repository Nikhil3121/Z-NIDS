"""Pluggable anomaly-detector members.

Every member is trained on NORMAL traffic only (it never sees an attack label)
and returns a raw score where higher = more anomalous. New members register in
MEMBER_REGISTRY and become selectable in the training config without any API
change.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.kernel_approximation import Nystroem
from sklearn.linear_model import SGDOneClassSVM
from sklearn.neural_network import MLPRegressor
from sklearn.pipeline import make_pipeline


class AnomalyMember(ABC):
    name: ClassVar[str]
    #: True when `feature_contributions` is a genuine model attribution
    #: (e.g. reconstruction error per feature) rather than unavailable.
    provides_attribution: ClassVar[bool] = False

    @abstractmethod
    def fit(self, x_normal: np.ndarray) -> AnomalyMember: ...

    @abstractmethod
    def score(self, x: np.ndarray) -> np.ndarray: ...

    def feature_contributions(self, x: np.ndarray) -> np.ndarray | None:
        return None

    def params(self) -> dict[str, Any]:
        return {}


class IsolationForestMember(AnomalyMember):
    """Isolation Forest (Liu et al., 2008): anomalies are isolated by fewer random splits."""

    name = "isolation_forest"

    def __init__(self, n_estimators: int = 200, max_samples: int = 4096, seed: int = 0) -> None:
        self.model = IsolationForest(
            n_estimators=n_estimators, max_samples=max_samples, contamination="auto", random_state=seed, n_jobs=-1
        )

    def fit(self, x_normal: np.ndarray) -> IsolationForestMember:
        self.model.fit(x_normal)
        return self

    def score(self, x: np.ndarray) -> np.ndarray:
        return -self.model.score_samples(x)

    def params(self) -> dict[str, Any]:
        return {"n_estimators": self.model.n_estimators, "max_samples": self.model.max_samples}


class AutoencoderMember(AnomalyMember):
    """Under-complete MLP autoencoder; score = mean squared reconstruction error.

    Trained to reproduce normal traffic through a narrow bottleneck. Per-feature
    squared error is a direct attribution: it says which inputs the model could
    not reconstruct.
    """

    name = "autoencoder"
    provides_attribution = True

    def __init__(self, hidden: tuple[int, ...] = (32, 12, 32), max_iter: int = 150, seed: int = 0) -> None:
        self.model = MLPRegressor(
            hidden_layer_sizes=hidden,
            activation="relu",
            alpha=1e-4,
            batch_size=512,
            learning_rate_init=1e-3,
            max_iter=max_iter,
            early_stopping=True,
            validation_fraction=0.1,
            n_iter_no_change=6,
            random_state=seed,
        )

    def fit(self, x_normal: np.ndarray) -> AutoencoderMember:
        self.model.fit(x_normal, x_normal)
        return self

    def _errors(self, x: np.ndarray) -> np.ndarray:
        return (self.model.predict(x) - x) ** 2

    def score(self, x: np.ndarray) -> np.ndarray:
        return self._errors(x).mean(axis=1)

    def feature_contributions(self, x: np.ndarray) -> np.ndarray:
        err = self._errors(x)
        total = err.sum(axis=1, keepdims=True)
        return np.divide(err, total, out=np.zeros_like(err), where=total > 0)

    def params(self) -> dict[str, Any]:
        return {"hidden": list(self.model.hidden_layer_sizes), "n_iter": int(getattr(self.model, "n_iter_", 0))}


class OneClassSVMMember(AnomalyMember):
    """One-Class SVM with an RBF kernel approximated by Nystroem features.

    SGDOneClassSVM on a Nystroem map scales linearly with data size, unlike the
    exact kernel OCSVM, while keeping the same decision-boundary idea.
    """

    name = "one_class_svm"

    def __init__(self, n_components: int = 300, nu: float = 0.01, seed: int = 0) -> None:
        self.model = make_pipeline(
            Nystroem(gamma=0.05, n_components=n_components, random_state=seed),
            SGDOneClassSVM(nu=nu, random_state=seed, max_iter=30, tol=1e-4),
        )

    def fit(self, x_normal: np.ndarray) -> OneClassSVMMember:
        self.model.fit(x_normal)
        return self

    def score(self, x: np.ndarray) -> np.ndarray:
        return -self.model.decision_function(x)

    def params(self) -> dict[str, Any]:
        return {"n_components": self.model[0].n_components, "nu": self.model[1].nu}


MEMBER_REGISTRY: dict[str, type[AnomalyMember]] = {
    IsolationForestMember.name: IsolationForestMember,
    AutoencoderMember.name: AutoencoderMember,
    OneClassSVMMember.name: OneClassSVMMember,
}
