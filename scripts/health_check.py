"""Wrapper for app.cli.health_check: python scripts/health_check.py --help"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.cli.health_check import main

raise SystemExit(main())
