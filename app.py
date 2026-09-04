#!/usr/bin/env python3
"""Streamlitダッシュボードのエントリーポイント。

起動: streamlit run app.py
"""
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent))

from dashboard.streamlit_app import render

if __name__ == "__main__":
    render()