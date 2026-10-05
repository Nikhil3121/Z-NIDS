"""Leave-one-family-out comparison of anomaly-member configurations (research experiment).

For every attack family F and every member set M: train with F withheld, then
report F's detection rate, the false-positive rate and the supervised baseline.
Writes JSON + Markdown to ML_REPORTS_DIR/comparisons/. Nothing is registered.

    python -m app.cli.compare_models --dataset synthetic-s7-h8-e5-i0.5.csv.gz
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
from typing import Any

import numpy as np

from app.cli._common import setup
from app.core.config import get_settings
from app.ml.datasets import load_dataset
from app.ml.evaluation.experiment import run_heldout_experiment
from app.ml.training.train import TrainingConfig
from app.services import ml_pipeline, model_service

CONFIGS = {
    "isolation_forest": ["isolation_forest"],
    "autoencoder": ["autoencoder"],
    "one_class_svm": ["one_class_svm"],
    "ensemble_if_ae": ["isolation_forest", "autoencoder"],
}


def _pct(v: float | None, digits: int = 1) -> str:
    return "n/a" if v is None else f"{100 * v:.{digits}f}%"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Compare anomaly members with leave-one-family-out")
    p.add_argument("--dataset", required=True)
    p.add_argument("--format", default="normalized", choices=["normalized", "cicids2017"])
    p.add_argument("--configs", nargs="+", default=list(CONFIGS), choices=list(CONFIGS))
    p.add_argument("--families", nargs="*", default=None, help="families to hold out (default: all)")
    args = p.parse_args(argv)
    setup()

    frame, sha = load_dataset([ml_pipeline.dataset_path(args.dataset)], args.format)
    families = args.families or sorted(set(frame["label"]) - {"normal"})
    rows: list[dict[str, Any]] = []
    for family in families:
        for name in args.configs:
            res = run_heldout_experiment(frame, [family], TrainingConfig(members=CONFIGS[name]))
            fam = res.per_family.get(family)
            rows.append({
                "heldout": family,
                "config": name,
                "detection_rate": fam["detection_rate"] if fam else None,
                "supervised_baseline_recall": fam.get("supervised_baseline_recall") if fam else None,
                "false_positive_rate": res.summary["false_positive_rate"],
                "unknown_roc_auc": (res.summary["unknown_attacks"] or {}).get("roc_auc"),
            })
            print(f"{family:18s} {name:18s} detect={_pct(rows[-1]['detection_rate'])} "
                  f"fpr={_pct(rows[-1]['false_positive_rate'], 2)}")

    summary: dict[str, dict[str, float | None]] = {}
    for name in args.configs:
        rates = [r["detection_rate"] for r in rows if r["config"] == name and r["detection_rate"] is not None]
        fprs = [r["false_positive_rate"] for r in rows if r["config"] == name]
        summary[name] = {"mean_unknown_detection": float(np.mean(rates)) if rates else None,
                         "mean_false_positive_rate": float(np.mean(fprs)) if fprs else None}
    base = [r["supervised_baseline_recall"] for r in rows if r["supervised_baseline_recall"] is not None]
    summary["supervised_baseline"] = {"mean_unknown_detection": float(np.mean(base)) if base else None,
                                      "mean_false_positive_rate": None}

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
    path = model_service.write_report(get_settings().ml_reports_dir / "comparisons", f"loo-{stamp}",
                                      {"dataset": args.dataset, "dataset_sha256": sha, "rows": rows,
                                       "summary": summary})
    header = "| Held-out family | " + " | ".join(args.configs) + " | Supervised baseline |"
    lines = [f"# Leave-one-family-out comparison ({args.dataset})", "",
             "Each row: that family was withheld from training and appears only in the test period.", "",
             header, "|---|" + "---|" * (len(args.configs) + 1)]
    for family in families:
        cells = [_pct(next(x for x in rows if x["heldout"] == family and x["config"] == n)["detection_rate"])
                 for n in args.configs]
        b = next(x for x in rows if x["heldout"] == family)["supervised_baseline_recall"]
        lines.append(f"| {family} | " + " | ".join(cells) + f" | {_pct(b)} |")
    lines += ["", "| Config | Mean unknown detection | Mean FPR |", "|---|---|---|"]
    for name, s in summary.items():
        lines.append(f"| {name} | {_pct(s['mean_unknown_detection'])} | {_pct(s['mean_false_positive_rate'], 2)} |")
    path.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"report: {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
