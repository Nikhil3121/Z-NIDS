"""Wrapper for app.cli.create_admin: python scripts/create_admin.py --help"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from app.cli.create_admin import main

raise SystemExit(main())
