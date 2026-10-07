#!/usr/bin/env python3
"""Launcher used by the Windows service: makes the project importable
regardless of the working directory the service manager picks."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from shatter.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(["--config", os.path.join(ROOT, "config.json")]))
