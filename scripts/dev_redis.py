"""Development-only Redis stand-in for machines without Docker or a native Redis.

Runs fakeredis' TCP server (RESP protocol, pub/sub, expiry, pipelines) on
127.0.0.1. Data lives in memory and is lost on exit. NEVER use in production:
deploy real Redis there (see docs/deployment.md).

    python scripts/dev_redis.py --port 6380
"""

from __future__ import annotations

import argparse
import logging

from fakeredis import TcpFakeServer


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6380)
    args = parser.parse_args()
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        raise SystemExit("dev_redis only binds to loopback")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s dev-redis %(message)s")
    server = TcpFakeServer((args.host, args.port), server_type="redis")
    server.daemon_threads = True
    logging.info("listening on %s:%s (in-memory, development only)", args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
