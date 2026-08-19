#!/usr/bin/env python3
"""Independently recompute and verify H094-G07 packing-allocation evidence."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import packing_allocation


def evidence_paths(evidence: Path) -> tuple[Path, Path, dict[str, object]]:
    try:
        supplied_is_symlink = evidence.is_symlink()
        root = evidence.resolve(strict=True)
    except OSError as error:
        raise packing_allocation.PackingAllocationError(
            "packing-allocation evidence directory is unavailable"
        ) from error
    if supplied_is_symlink or not root.is_dir():
        packing_allocation.fail("packing-allocation evidence path is not a directory")
    try:
        entries = list(root.iterdir())
    except OSError as error:
        raise packing_allocation.PackingAllocationError(
            "packing-allocation evidence inventory is unavailable"
        ) from error
    names = sorted(path.name for path in entries)
    expected_names = sorted(
        [packing_allocation.RAW_NAME, packing_allocation.REPORT_NAME]
    )
    if names != expected_names:
        packing_allocation.fail("packing-allocation evidence inventory is not exact")
    raw_path = root / packing_allocation.RAW_NAME
    report_path = root / packing_allocation.REPORT_NAME
    raw_binding = packing_allocation.file_binding(raw_path, relative=False)
    packing_allocation.file_binding(report_path, relative=False)
    return raw_path, report_path, raw_binding


def verify(evidence: Path, driver: Path) -> str:
    raw_path, report_path, raw_binding = evidence_paths(evidence)
    raw = packing_allocation.load_object(raw_path)
    report = packing_allocation.load_object(report_path)
    expected_keys = {
        "schema_version",
        "status",
        "source",
        "bindings",
        "configuration_id",
        "evaluation",
        "report_id",
    }
    if set(report) != expected_keys:
        packing_allocation.fail("packing-allocation report fields are invalid")
    report_id = report.pop("report_id")
    if not isinstance(report_id, str) or report_id != packing_allocation.sha256_bytes(
        packing_allocation.canonical(report)
    ):
        packing_allocation.fail("packing-allocation report identity disagrees")
    configuration = packing_allocation.load_configuration()
    source = packing_allocation.clean_source_snapshot()
    if report["source"] != source:
        packing_allocation.fail("packing-allocation source binding disagrees")
    bindings = packing_allocation._exact_keys(
        report["bindings"],
        {"configuration", "driver_source", "driver_lock", "driver_binary", "raw"},
        "packing-allocation bindings",
    )
    expected_bindings = {
        "configuration": packing_allocation.file_binding(
            packing_allocation.CONFIGURATION, relative=True
        ),
        "driver_source": packing_allocation.file_binding(
            packing_allocation.DRIVER_SOURCE, relative=True
        ),
        "driver_lock": packing_allocation.file_binding(
            packing_allocation.DRIVER_LOCK, relative=True
        ),
        "driver_binary": packing_allocation.file_binding(driver, relative=False),
        "raw": raw_binding,
    }
    if bindings != expected_bindings:
        packing_allocation.fail("packing-allocation file binding disagrees")
    evaluation = packing_allocation.evaluate(raw, configuration)
    if (
        report["schema_version"] != "cigar.h094-packing-allocation-report.v1"
        or report["configuration_id"] != configuration["schema_version"]
        or report["evaluation"] != evaluation
        or report["status"] != evaluation["status"]
    ):
        packing_allocation.fail("packing-allocation evaluation disagrees")
    return report_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--driver", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report_id = verify(arguments.evidence, arguments.driver)
    except packing_allocation.PackingAllocationError as error:
        print(f"packing-allocation verification failed: {error}", file=sys.stderr)
        return 2
    print(f"packing-allocation evidence verified: {report_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
