"""Seed LAB / DEMO data through the real pipeline (development and staging only).

Registers the lab network's assets and a lab sensor, then runs a sequence of
synthetic scenarios ending "now". Every record is flagged is_demo and the UI
shows "LAB / DEMO DATA". Refuses to run unless DEMO_MODE=true, and never in
production. Nothing is sent on any network.

    python -m app.cli.seed_demo_data --minutes 20
"""

from __future__ import annotations

import argparse

from app.cli._common import dump, setup
from app.core.exceptions import PermissionDeniedError
from app.db.session import get_sessionmaker
from app.services import lab_service

DEFAULT_SEQUENCE = ["normal", "port_scan", "brute_force", "exfiltration", "lateral_movement", "dns_tunneling"]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Seed LAB / DEMO data (never in production)")
    p.add_argument("--scenarios", nargs="+", default=DEFAULT_SEQUENCE,
                   choices=[*lab_service.SCENARIOS, *lab_service.ALIASES])
    p.add_argument("--minutes", type=float, default=15.0)
    p.add_argument("--intensity", type=float, default=0.3)
    p.add_argument("--seed", type=int, default=7)
    args = p.parse_args(argv)
    setup()
    try:
        lab_service.ensure_enabled()
    except PermissionDeniedError as exc:
        print(exc.message)
        return 2
    db = get_sessionmaker()()
    try:
        for i, scenario in enumerate(args.scenarios):
            # Background traffic is generated once; later scenarios add only their attack flows.
            result = lab_service.run_scenario(db, scenario, args.minutes, args.intensity, args.seed + i,
                                              background=(i == 0))
            print(dump({k: result[k] for k in ("scenario", "flows_generated", "accepted", "ground_truth_labels")}))
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
