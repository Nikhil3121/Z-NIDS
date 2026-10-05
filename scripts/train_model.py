"""Wrapper for app.cli.train_model: python scripts/train_model.py --help"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.cli.train_model import main

raise SystemExit(main())
