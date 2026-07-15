#!/usr/bin/env python3
"""Run the shared handoff driver against the Honey two-agent fixture."""

from __future__ import annotations

import runpy
import hashlib
from pathlib import Path


SHARED_DRIVER_SHA256 = (
    "bc366d8964c2a620ab0467235af1bfaef0c0c8ee47be003773e38ecbca5dedec"
)


if __name__ == "__main__":
    shared_driver = Path(__file__).resolve().parents[1] / "agent-handoff" / "driver.py"
    if hashlib.sha256(shared_driver.read_bytes()).hexdigest() != SHARED_DRIVER_SHA256:
        raise SystemExit("honey two-agent driver dependency does not match")
    runpy.run_path(
        str(shared_driver),
        run_name="__main__",
    )
