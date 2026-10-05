"""Synthetic LAB telemetry generator (flow metadata only — nothing is sent on any network).

Two modes:
  dataset  write a labelled, versioned dataset file for ML research
  live     generate flows ending "now" and push them through the real ingestion
           API with a sensor key (exactly like a real sensor would)

    python -m app.cli.generate_synthetic_events dataset --seed 7 --hours 8
    python -m app.cli.generate_synthetic_events live --api http://127.0.0.1:8010 \
        --sensor-key $ZNIDS_SENSOR_KEY --scenario port_scan --minutes 10
"""

from __future__ import annotations

import argparse
import os
import sys

import httpx

from app.cli._common import setup
from app.services import ml_pipeline
from app.services.lab_service import ALIASES, SCENARIOS, frame_to_records, generate_frame


def _dataset(args: argparse.Namespace) -> int:
    name, sha = ml_pipeline.generate_synthetic_dataset(seed=args.seed, hours=args.hours, episodes=args.episodes,
                                                       intensity=args.intensity)
    print(f"dataset {name}\nsha256  {sha}")
    return 0


def _live(args: argparse.Namespace) -> int:
    key = args.sensor_key or os.environ.get("ZNIDS_SENSOR_KEY")
    if not key:
        print("A sensor key is required (--sensor-key or ZNIDS_SENSOR_KEY). Create a demo sensor in Settings.",
              file=sys.stderr)
        return 2
    frame = generate_frame(args.scenario, args.minutes, args.seed, args.intensity)
    records = frame_to_records(frame)
    accepted = rejected = 0
    with httpx.Client(base_url=args.api, timeout=60.0) as client:
        for i in range(0, len(records), args.batch):
            r = client.post("/api/v1/events/ingest", headers={"X-Sensor-Key": key},
                            json={"events": records[i : i + args.batch]})
            if r.status_code != 202:
                print(f"ingestion failed: HTTP {r.status_code} {r.text[:300]}", file=sys.stderr)
                return 1
            body = r.json()
            accepted += body["accepted"]
            rejected += len(body["rejected"])
    labels = frame["label"].value_counts().to_dict()
    print(f"scenario={args.scenario} flows={len(records)} accepted={accepted} rejected={rejected} labels={labels}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Synthetic lab telemetry (no real traffic is generated)")
    sub = p.add_subparsers(dest="mode", required=True)
    d = sub.add_parser("dataset", help="write a labelled research dataset")
    d.add_argument("--seed", type=int, default=7)
    d.add_argument("--hours", type=float, default=8.0)
    d.add_argument("--episodes", type=int, default=5)
    d.add_argument("--intensity", type=float, default=0.5)
    live = sub.add_parser("live", help="push a scenario through the ingestion API")
    live.add_argument("--api", default="http://127.0.0.1:8010")
    live.add_argument("--sensor-key")
    live.add_argument("--scenario", default="normal", choices=[*SCENARIOS, *ALIASES])
    live.add_argument("--minutes", type=float, default=10.0)
    live.add_argument("--intensity", type=float, default=0.3)
    live.add_argument("--seed", type=int, default=None)
    live.add_argument("--batch", type=int, default=1000)
    args = p.parse_args(argv)
    setup()
    return _dataset(args) if args.mode == "dataset" else _live(args)


if __name__ == "__main__":
    raise SystemExit(main())
