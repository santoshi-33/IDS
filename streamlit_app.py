"""
Streamlit Community Cloud default entry: set Main file to `streamlit_app.py` (repo root)
or to `app/streamlit_app.py` if you prefer.
"""
from __future__ import annotations

import runpy
from pathlib import Path

_APP = Path(__file__).resolve().parent / "app" / "streamlit_app.py"
runpy.run_path(str(_APP), run_name="__main__")
