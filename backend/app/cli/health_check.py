"""Probe a running Z-NIDS API: liveness, readiness and security headers. Exit 0 only if healthy.

    python -m app.cli.health_check --api http://127.0.0.1:8010
"""

from __future__ import annotations

import argparse
import sys

import httpx

REQUIRED_HEADERS = ("x-content-type-options", "x-frame-options", "content-security-policy", "x-request-id")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Z-NIDS health check")
    p.add_argument("--api", default="http://127.0.0.1:8010")
    p.add_argument("--timeout", type=float, default=5.0)
    args = p.parse_args(argv)
    ok = True
    try:
        with httpx.Client(base_url=args.api, timeout=args.timeout) as c:
            live = c.get("/health")
            print(f"/health  {live.status_code} {live.json()}")
            ok &= live.status_code == 200
            missing = [h for h in REQUIRED_HEADERS if h not in live.headers]
            if missing:
                print(f"missing security headers: {missing}")
                ok = False
            ready = c.get("/ready")
            print(f"/ready   {ready.status_code} {ready.json()}")
            ok &= ready.status_code == 200
    except httpx.HTTPError as exc:
        print(f"unreachable: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print("HEALTHY" if ok else "UNHEALTHY")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
