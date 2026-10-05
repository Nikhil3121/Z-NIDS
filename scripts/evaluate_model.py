"""Wrapper for app.cli.evaluate_model: python scripts/evaluate_model.py --help"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.cli.evaluate_model import main

raise SystemExit(main())
