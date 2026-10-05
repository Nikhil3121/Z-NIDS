"""Wrapper for app.cli.seed_demo_data: python scripts/seed_demo_data.py --help"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.cli.seed_demo_data import main

raise SystemExit(main())
