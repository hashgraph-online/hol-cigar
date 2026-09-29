"""Exercise entry points as installed consumers would, including failure output."""

from __future__ import annotations

import json
import os
import sys
from importlib import resources

import pytest

from cigar_sdk import LocalContextError, ValidationError, local_cli, qualify_bundle


@pytest.mark.parametrize("command", ["doctor", "demo"])
@pytest.mark.parametrize("machine_readable", [False, True])
def test_local_commands_need_no_service(command, machine_readable, capsys):
    args = [command] + (["--json"] if machine_readable else [])
    if worker := os.environ.get("CIGAR_TEST_WORKER"):
        args.extend(["--worker", worker])
    assert local_cli.main(args) == 0
    output = capsys.readouterr().out
    if machine_readable or command == "demo":
        result = json.loads(output)
        assert result["status"] in {"ready", "passed"}
    else:
        assert "No HOL service" in output


@pytest.mark.parametrize("machine_readable", [False, True])
def test_missing_worker_diagnostic_is_content_free(tmp_path, machine_readable, capsys):
    args = ["doctor", "--worker", str(tmp_path / "PRIVATE_WORKER")]
    if machine_readable:
        args.append("--json")
    assert local_cli.main(args) == 1
    output = capsys.readouterr().out
    assert "PRIVATE_WORKER" not in output
    assert "WorkerUnavailable" in output


@pytest.mark.parametrize("failure", [LocalContextError("Integrity"), RuntimeError("PRIVATE_DATA")])
def test_cli_failures_have_stable_content_free_output(failure, monkeypatch, capsys):
    def fail(**kwargs):
        raise failure

    monkeypatch.setattr(local_cli, "run_local_workflow", fail)
    assert local_cli.main(["demo", "--json"]) == 1
    result = capsys.readouterr().out
    assert "PRIVATE_DATA" not in result
    assert json.loads(result)["compile_verified"] is False


def test_shared_fixture_cli_and_invalid_inputs(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["cigar-qualify-bundle"])
    qualify_bundle.main()
    source = json.loads(resources.files("cigar_sdk.fixtures").joinpath("semantic-bundle-v1.json").read_text())
    assert capsys.readouterr().out.strip() == source["expected_bundle_id"]
    path = tmp_path / "fixture.json"
    monkeypatch.setattr(sys, "argv", ["cigar-qualify-bundle", str(path)])
    for value in (
        {**source, "schema_version": "bad"},
        {**source, "bundle": []},
        {**source, "expected_bundle_id": "bad"},
    ):
        path.write_text(json.dumps(value))
        with pytest.raises(ValueError):
            qualify_bundle.main()
    path.write_text('{"a":1,"\\u0061":2}')
    with pytest.raises(ValidationError):
        qualify_bundle.main()
