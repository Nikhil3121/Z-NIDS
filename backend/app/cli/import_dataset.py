"""Import a research dataset (CIC-IDS2017 TrafficLabelling or Z-NIDS normalised CSV).

The files are normalised into one versioned, gzipped dataset with a manifest
(row counts, labels, SHA-256) inside ML_DATASETS_DIR, ready for train_model /
evaluate_model / compare_models.

    python -m app.cli.import_dataset --format cicids2017 --name cicids2017-wed \
        "D:/data/CIC-IDS2017/TrafficLabelling/Wednesday-workingHours.pcap_ISCX.csv"
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from app.cli._common import setup
from app.core.config import get_settings
from app.ml.datasets import load_dataset, write_dataset


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Import and normalise a labelled flow dataset")
    p.add_argument("files", nargs="+", type=Path)
    p.add_argument("--format", required=True, choices=["normalized", "cicids2017"])
    p.add_argument("--name", required=True, help="dataset name, e.g. cicids2017-full")
    args = p.parse_args(argv)
    setup()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{1,80}", args.name):
        p.error("--name may contain letters, digits, '.', '_' and '-' only")
    missing = [str(f) for f in args.files if not f.is_file()]
    if missing:
        p.error(f"not found: {missing}")
    frame, source_sha = load_dataset(args.files, args.format)
    out = get_settings().ml_datasets_dir / f"{args.name}.csv.gz"
    if out.exists():
        p.error(f"{out.name} already exists; datasets are immutable, choose a new --name")
    sha, manifest = write_dataset(frame, out, {"source_format": args.format, "source_sha256": source_sha,
                                               "source_files": [f.name for f in args.files], "synthetic": False})
    print(f"wrote {out.name} ({len(frame)} flows) sha256={sha}\nmanifest {manifest.name}")
    print(frame["label"].value_counts().to_string())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
