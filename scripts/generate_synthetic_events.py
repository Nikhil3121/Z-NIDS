"""Wrapper for app.cli.generate_synthetic_events: python scripts/generate_synthetic_events.py --help"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.cli.generate_synthetic_events import main

raise SystemExit(main())
