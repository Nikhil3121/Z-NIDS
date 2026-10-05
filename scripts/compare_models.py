"""Wrapper for app.cli.compare_models: python scripts/compare_models.py --help"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.cli.compare_models import main

raise SystemExit(main())
