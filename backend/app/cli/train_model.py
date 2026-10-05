"""Train a model with the held-out-family protocol and register it (status TRAINED).

    python -m app.cli.train_model --dataset synthetic-s7-h8-e5-i0.5.csv.gz \
        --heldout exfiltration c2_beaconing dns_tunneling lateral_movement slow_dos
    python -m app.cli.train_model --generate --heldout ... --activate

Activation is opt-in (--activate) and audited; training never replaces the
production model on its own.
"""

from __future__ import annotations

import argparse

from app.cli._common import dump, setup
from app.db.session import session_scope
from app.ml.models.members import MEMBER_REGISTRY
from app.ml.synthetic.generator import ATTACK_FAMILIES
from app.ml.training.train import TrainingConfig
from app.services import ml_pipeline, model_service


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Train and register a Z-NIDS anomaly model")
    p.add_argument("--dataset", help="file name inside ML_DATASETS_DIR")
    p.add_argument("--format", default="normalized", choices=["normalized", "cicids2017"])
    p.add_argument("--generate", action="store_true", help="generate the default synthetic lab dataset first")
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--hours", type=float, default=8.0)
    p.add_argument("--heldout", nargs="*", default=[], help="attack families withheld from training")
    p.add_argument("--members", nargs="+", default=["isolation_forest", "autoencoder"],
                   choices=sorted(MEMBER_REGISTRY))
    p.add_argument("--train-fraction", type=float, default=0.6)
    p.add_argument("--activate", action="store_true", help="promote the new version to ACTIVE after training")
    args = p.parse_args(argv)
    setup()

    dataset = args.dataset
    if args.generate:
        dataset, sha = ml_pipeline.generate_synthetic_dataset(seed=args.seed, hours=args.hours)
        print(f"dataset {dataset} sha256={sha[:16]}")
    if not dataset:
        p.error("--dataset or --generate is required")
    if dataset.startswith("synthetic-"):
        unknown = set(args.heldout) - set(ATTACK_FAMILIES)
        if unknown:
            p.error(f"unknown families for the synthetic dataset: {sorted(unknown)}")

    with session_scope() as db:
        outcome = ml_pipeline.train_and_register(
            db, dataset=dataset, fmt=args.format, heldout=args.heldout,
            config=TrainingConfig(members=args.members), train_fraction=args.train_fraction,
            notes="trained via CLI")
        if args.activate:
            model_service.activate(db, outcome.model.id, None)
        tag, model_id, status, metrics = (outcome.model.tag, outcome.model.id, outcome.model.status.value,
                                          outcome.model.metrics)
    print(f"registered {tag} (id={model_id}, status={status})")
    print(f"report: {outcome.report_path}")
    print(dump(metrics))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
