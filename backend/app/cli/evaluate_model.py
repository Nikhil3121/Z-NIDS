"""Evaluate a registered model on a dataset; families it never trained on count as unknown.

    python -m app.cli.evaluate_model --model-id 1 --dataset synthetic-s21-h8-e5-i0.5.csv.gz
"""

from __future__ import annotations

import argparse

from app.cli._common import dump, setup
from app.db.session import session_scope
from app.services import ml_pipeline


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Evaluate a registered Z-NIDS model")
    p.add_argument("--model-id", type=int, required=True)
    p.add_argument("--dataset", required=True)
    p.add_argument("--format", default="normalized", choices=["normalized", "cicids2017"])
    p.add_argument("--heldout", nargs="*", default=None)
    args = p.parse_args(argv)
    setup()
    with session_scope() as db:
        result = ml_pipeline.evaluate_registered(db, args.model_id, dataset=args.dataset, fmt=args.format,
                                                 heldout=args.heldout)
    s = result["summary"]
    print(dump({"evaluation_id": result["evaluation_id"], "report": result["report"],
                "false_positive_rate": s["false_positive_rate"], "overall": s["overall"],
                "unknown_attacks": s["unknown_attacks"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
