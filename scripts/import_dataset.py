"""Wrapper for app.cli.import_dataset: python scripts/import_dataset.py --help"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.cli.import_dataset import main

raise SystemExit(main())
