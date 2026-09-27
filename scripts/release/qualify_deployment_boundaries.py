"""Run deployment filesystem checks on a disposable GitHub-hosted Linux runner.

Installs two temporary systemd test units and the template's cigar user/directories.
The service executable is a filesystem probe, not a production daemon. Kubernetes
init commands and volume boundaries execute in the pinned container without a
cluster or external services. All credentials are newly created dummy fixtures.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import tempfile

from release_lib import reject_evidence_directory


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def command(argv, *, expected=0, timeout=60):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if result.returncode != expected:
        raise RuntimeError(
            f"{argv[0]} exited {result.returncode}, expected {expected}: "
            + result.stderr[-4000:]
        )
    return result.stdout.strip()


PROBE = """import os, pathlib, stat, sys
directory = pathlib.Path(sys.argv[1])
assert os.getuid() == int(sys.argv[2]) != 0
metadata = directory.stat()
assert metadata.st_uid == os.getuid()
assert stat.S_IMODE(metadata.st_mode) == 0o700
status = pathlib.Path("/proc/self/status").read_text()
assert "NoNewPrivs:\\t1" in status
assert "CapEff:\\t0000000000000000" in status
temporary = directory / "cigar-boundary-smoke.tmp"
committed = directory / "cigar-boundary-smoke.json"
try:
    with temporary.open("xb") as stream:
        stream.write(b'{"fixture":"atomic-checkpoint"}\\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, committed)
except OSError as error:
    if error.errno == 30:
        sys.exit(30)  # the negative-control read-only mount
    raise
assert committed.read_bytes() == b'{"fixture":"atomic-checkpoint"}\\n'
committed.unlink()
try:
    pathlib.Path("/etc/cigar-boundary-must-not-write").write_bytes(b"denied")
except PermissionError:
    pass
except OSError as error:
    assert error.errno == 30
else:
    raise AssertionError("immutable path became writable")
"""


def systemd(fixture, directory):
    paths = [
        Path("/run/cigar"),
        Path("/var/lib/cigar"),
        Path("/var/lib/cigar-effect-checkpoints"),
        Path("/var/cache/cigar"),
    ]
    require(all(not p.exists() for p in paths), "refuse existing CIGAR host state")
    try:
        pwd.getpwnam("cigar")
    except KeyError:
        command(["useradd", "--system", "--user-group", "--no-create-home", "cigar"])
    else:
        raise RuntimeError("refuse an existing cigar account")
    owner = pwd.getpwnam("cigar").pw_uid
    tmpfiles = directory / "cigar.tmpfiles"
    tmpfiles.write_text(fixture["tmpfiles"])
    command(["systemd-tmpfiles", "--create", str(tmpfiles)])
    probe = directory / "probe.py"
    probe.write_text(PROBE)
    probe.chmod(0o644)
    checkpoint = Path(fixture["checkpoint_file"]).parent
    require(checkpoint == paths[2], "unexpected checkpoint destination")
    source = fixture["systemd_unit"]
    original = "ExecStart=/usr/bin/cigard serve --config /etc/cigar/cigard.toml"
    require(source.count(original) == 1, "service executable drift")
    # Preserve every sandbox directive; only the workload/lifetime changes.
    unit = source.replace(
        original, f"ExecStart=/usr/bin/python3 {probe} {checkpoint} {owner}"
    )
    unit = unit.replace("Type=simple", "Type=oneshot").replace(
        "Restart=on-failure", "Restart=no"
    )
    outcomes = []
    for control in (False, True):
        name = "cigar-boundary-smoke" + ("-negative" if control else "")
        path = Path("/run/systemd/system") / (name + ".service")
        require(not path.exists(), "refuse existing test unit")
        content = unit
        if control:
            content = (
                "\n".join(
                    line.replace(" /var/lib/cigar-effect-checkpoints", "")
                    if line.startswith("ReadWritePaths=")
                    else line
                    for line in unit.splitlines()
                )
                + "\n"
            )
            require(content != unit, "negative control did not remove writable path")
        path.write_text(content)
        try:
            command(["systemctl", "daemon-reload"])
            started = subprocess.run(
                ["systemctl", "start", name], capture_output=True, text=True, timeout=60
            )
            exit_status = int(
                command(
                    ["systemctl", "show", name, "--property=ExecMainStatus", "--value"]
                )
            )
            require(
                exit_status == (30 if control else 0),
                f"systemd probe failed: {name}, {exit_status}",
            )
            require((started.returncode != 0) is control, "unexpected service result")
            outcomes.append({"negative_control": control, "exit_status": exit_status})
        finally:
            command(["systemctl", "stop", name])
            path.unlink()
            command(["systemctl", "daemon-reload"])
    return outcomes


def container(fixture, directory):
    spec = fixture["deployment"]["spec"]["template"]["spec"]
    require(spec["securityContext"]["runAsUser"] == 65532, "fixture UID drift")
    require(spec["securityContext"]["runAsGroup"] == 65532, "fixture GID drift")
    init = spec["initContainers"][0]
    require(len(spec["initContainers"]) == 1, "unexpected init inventory")
    image = init["image"]
    require(
        image.startswith("busybox@sha256:") and len(image.split(":")[-1]) == 64,
        "unpinned image",
    )
    command(["docker", "pull", image], timeout=180)
    initial = [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--user=65532:65532",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=32",
        "--memory=64m",
    ]
    expected_names = {
        "raw-runtime",
        "raw-tls",
        "raw-telemetry-tls",
        "raw-postgres-tls",
        "prepared-secrets",
        "prepared-postgres-tls",
        "state",
        "runtime",
        "effect-checkpoints",
    }
    require(
        {v["name"] for v in init["volumeMounts"]} == expected_names,
        "volume inventory drift",
    )
    outcomes = []
    for missing in (False, True):
        root = directory / ("container-missing-ca" if missing else "container-complete")
        root.mkdir()
        for name in expected_names:
            target = root / name
            target.mkdir(mode=0o700)
            os.chown(target, 65532, 65532)

        def put(volume, name, payload, mode=0o440):
            target = root / volume / name
            target.write_bytes(payload)
            os.chown(target, 65532, 65532)
            target.chmod(mode)

        for name in (
            "postgres-runtime-url",
            "object-access-key",
            "object-secret-key",
            "object-session-token",
            "object-blinding-key",
            "keystore-passphrase",
            "keystore.cigar",
            "cursor.key",
        ):
            put("raw-runtime", name, b"inert deployment fixture\n")
        for name in ("tls.crt", "tls.key", "ca.crt"):
            put("raw-tls", name, b"distinct client TLS fixture\n")
        telemetry = b"distinct telemetry CA bytes: copy/permission fixture only\n"
        if not missing:
            put("raw-telemetry-tls", "ca.crt", telemetry)
        put("raw-postgres-tls", "ca.crt", b"distinct postgres CA fixture\n")
        put("effect-checkpoints", "checkpoints.json", b'{"fixture":true}\n', 0o600)
        mounts = []
        for volume in init["volumeMounts"]:
            value = f"type=bind,src={root / volume['name']},dst={volume['mountPath']}"
            mounts.extend(
                ["--mount", value + (",readonly" if volume.get("readOnly") else "")]
            )
        argv = (
            initial
            + mounts
            + ["--entrypoint", init["command"][0], image]
            + init["command"][1:]
            + init["args"]
        )
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        require(
            (completed.returncode != 0) is missing,
            "init did not enforce required CA input",
        )
        if not missing:
            prepared = root / "prepared-secrets/telemetry-ca.pem"
            require(prepared.read_bytes() == telemetry, "wrong CA copied")
            metadata = prepared.stat()
            require(
                metadata.st_uid == 65532 and stat.S_IMODE(metadata.st_mode) == 0o600,
                "unsafe CA ownership/mode",
            )
            app = spec["containers"][0]
            volume = next(
                v for v in app["volumeMounts"] if v["name"] == "prepared-secrets"
            )
            require(volume["readOnly"] is True, "runtime secrets writable")
            ca = fixture["telemetry_ca_file"]
            require(
                ca == volume["mountPath"] + "/telemetry-ca.pem",
                "runtime CA path mismatch",
            )
            command(
                initial
                + [
                    "--mount",
                    f"type=bind,src={root / 'prepared-secrets'},dst={volume['mountPath']},readonly",
                    "--entrypoint",
                    "/bin/sh",
                    image,
                    "-euc",
                    f'test -s {ca}; test "$(stat -c %u {ca})" = 65532; '
                    f"if echo denied >> {ca}; then exit 1; fi",
                ]
            )
        outcomes.append({"missing_ca": missing, "exit_status": completed.returncode})
    return {"image": image, "outcomes": outcomes, "network": "none"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-ephemeral-host-mutations", action="store_true")
    parser.add_argument(
        "--evidence-dir", type=Path, help="inapplicable to deployment diagnostics"
    )
    args = parser.parse_args()
    reject_evidence_directory(args.evidence_dir, "deployment diagnostics")
    require(
        args.allow_ephemeral_host_mutations
        and os.geteuid() == 0
        and os.uname().sysname == "Linux"
        and os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
        "requires explicit opt-in on a disposable GitHub-hosted Linux runner",
    )
    payload = args.fixture.read_bytes()
    fixture = json.loads(payload)
    require(
        fixture["schema"] == "cigar.deployment-boundary-fixture.v1", "fixture schema"
    )
    require(not args.output.exists(), "refuse existing evidence")
    # /run remains visible with PrivateTmp and ProtectHome from the real unit.
    with tempfile.TemporaryDirectory(prefix="cigar-boundary-", dir="/run") as temp:
        directory = Path(temp)
        directory.chmod(0o755)
        report = {
            "schema": "cigar.deployment-boundary-runtime.v1",
            "fixture_sha256": hashlib.sha256(payload).hexdigest(),
            "scope": "systemd filesystem policy and container init/volume boundaries",
            "systemd": systemd(fixture, directory),
            "container": container(fixture, directory),
            "production_daemon_or_cluster_qualification": False,
        }
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
