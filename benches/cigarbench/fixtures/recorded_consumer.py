#!/usr/bin/env python3
"""Deterministic harness-smoke consumer; never valid as performance evidence."""

from __future__ import annotations

import json
import sys
from typing import Any


def main() -> int:
    assignment: dict[str, Any] = json.load(sys.stdin)
    treatment = assignment["treatment"]
    index = int(assignment["sample_index"])
    baseline = treatment == "baseline"
    # These values test paired analysis branches. They are recorded fixture data,
    # not measurements, and the enclosing plan is permanently `harness_smoke`.
    metrics = {
        "physical_input_tokens": 10000 + index * 10 if baseline else 5500 + index * 5,
        "cache_read_tokens": 0 if baseline else 1200,
        "cache_write_tokens": 0 if baseline else 300,
        "verified_success": True,
        "critical_recall": 0.97 if baseline else 0.995,
        "context_precision": 0.60 if baseline else 0.93,
        "prohibited_context_rate": 0.01 if baseline else 0.0,
        "context_caused_harm": baseline,
        "stale_harm": 0.01 if baseline else 0.0,
        "rework_count": 2 if baseline else 1,
        "latency_ms": 80.0 + index if baseline else 90.0 + index,
        "intervention_count": 1 if baseline else 0,
        "cost": 1.0 if baseline else 0.55,
        "unauthorized_context_count": 1 if baseline else 0,
        "calibration_variance": 0.01,
    }
    json.dump(
        metrics, sys.stdout, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
