"""ML correctness: feature consistency, no look-ahead leakage, artifact integrity, unseen-family evaluation."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from app.ml.evaluation.experiment import run_heldout_experiment
from app.ml.features.extractor import extract_features
from app.ml.features.registry import FEATURE_NAMES, FEATURES
from app.ml.registry.store import ArtifactIntegrityError, load_bundle, save_bundle
from app.ml.synthetic.generator import SyntheticTrafficGenerator
from app.ml.training.train import TrainingConfig, train_bundle

START = 1_779_926_400.0 + 9 * 3600  # 09:00 UTC on a fixed day


@pytest.fixture(scope="module")
def dataset() -> pd.DataFrame:
    return SyntheticTrafficGenerator(seed=11).generate(START, hours=3, episodes_per_family=2, intensity=0.4)


def test_feature_registry_is_documented_and_unique() -> None:
    assert len(FEATURE_NAMES) == len(set(FEATURE_NAMES)) == 46
    assert all(f.description and f.label for f in FEATURES)


def test_features_are_deterministic_and_order_independent(dataset: pd.DataFrame) -> None:
    sample = dataset.iloc[:4000]
    a, _ = extract_features(sample)
    shuffled = sample.sample(frac=1.0, random_state=3)
    b, _ = extract_features(shuffled)
    b = b.set_axis(shuffled.index).loc[sample.index].reset_index(drop=True)
    np.testing.assert_allclose(a.to_numpy(), b.to_numpy())
    assert np.isfinite(a.to_numpy()).all()


def test_no_look_ahead_leakage(dataset: pd.DataFrame) -> None:
    """Appending future flows must not change the features of earlier flows."""
    frame = dataset.sort_values("ts").reset_index(drop=True)
    cut = len(frame) // 2
    past, _ = extract_features(frame.iloc[:cut])
    full, _ = extract_features(frame)
    np.testing.assert_allclose(past.to_numpy(), full.iloc[:cut].to_numpy())


def test_live_batch_with_context_matches_offline_features(dataset: pd.DataFrame) -> None:
    """The pipeline computes a batch plus its look-back context; results must equal a full offline pass."""
    frame = dataset.sort_values("ts").reset_index(drop=True)
    full, _ = extract_features(frame)
    batch_start = len(frame) // 2
    batch = frame.iloc[batch_start:batch_start + 500]
    lo = batch["ts"].min() - 300
    context = frame[(frame["ts"] >= lo) & (frame.index < batch_start)]
    combined = pd.concat([context, batch])
    live, _ = extract_features(combined)
    live_batch = live.iloc[len(context):].to_numpy()
    np.testing.assert_allclose(live_batch, full.iloc[batch_start:batch_start + 500].to_numpy(), atol=1e-9)


def test_artifact_checksum_blocks_tampering(dataset: pd.DataFrame, tmp_path) -> None:
    frame = dataset[dataset["label"] == "normal"].sort_values("ts").reset_index(drop=True).iloc[:6000]
    x, raw = extract_features(frame)
    bundle, _ = train_bundle(x, raw, frame["label"], frame["ts"],
                             TrainingConfig(members=["isolation_forest"], use_classifier=False))
    path, checksum = save_bundle(bundle, tmp_path, "t", 1)
    loaded = load_bundle(path, checksum)
    np.testing.assert_allclose(loaded.predict(x.to_numpy()).anomaly_score, bundle.predict(x.to_numpy()).anomaly_score)
    with pytest.raises(FileExistsError):
        save_bundle(bundle, tmp_path, "t", 1)  # versions are immutable
    with path.open("ab") as fh:
        fh.write(b"tamper")
    with pytest.raises(ArtifactIntegrityError):
        load_bundle(path, checksum)


def test_unknown_families_beat_supervised_baseline(dataset: pd.DataFrame) -> None:
    heldout = ["exfiltration", "dns_tunneling", "lateral_movement", "slow_dos", "c2_beaconing"]
    result = run_heldout_experiment(dataset, heldout, TrainingConfig(members=["isolation_forest", "autoencoder"]))
    s = result.summary
    assert set(s["heldout_families"]) == set(heldout)
    assert s["split"]["heldout_rows_removed_from_train"] > 0
    assert set(result.bundle.known_families).isdisjoint(heldout)  # nothing held out reached training
    unknown = s["unknown_attacks"]
    assert unknown["macro_detection_rate"] > s["supervised_baseline"]["unknown_recall"] + 0.3
    assert s["false_positive_rate"] < 0.02
    assert s["known_macro_detection_rate"] > 0.9
    tested = [f for f in heldout if f in result.per_family]  # families with episodes in the test period
    assert len(tested) >= 3
    for fam in tested:
        assert result.per_family[fam]["group"] == "unknown"
