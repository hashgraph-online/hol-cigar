#!/usr/bin/env python3
"""Run the macOS live PostgreSQL migration/recovery qualification.

The harness owns one uniquely labelled Docker container and one private directory
under ``target``. It generates a fresh CA and DNS-only localhost server identity,
starts PostgreSQL with plaintext TCP rejected, runs the Rust qualification, and
removes only those resources in a ``finally`` block.
"""

from __future__ import annotations

import os
import platform
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import quote


DEFAULT_IMAGE = "postgres:18.2-bookworm"
READY_TIMEOUT_SECONDS = 90
PORT_PATTERN = re.compile(r"^127\.0\.0\.1:(?P<port>[0-9]{1,5})$")


class QualificationError(RuntimeError):
    """A content-free qualification failure."""


def _run(
    command: list[str],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    capture: bool = True,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=check,
        capture_output=capture,
        text=True,
    )


def _require_commands() -> None:
    missing = [name for name in ("cargo", "docker", "openssl") if shutil.which(name) is None]
    if missing:
        raise QualificationError("a required local qualification command is unavailable")
    _run(["docker", "version", "--format", "{{.Server.Version}}"])
    _run(["cargo", "nextest", "--version"])


def _write_private(path: Path, content: str, *, executable: bool = False) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | (stat.S_IXUSR if executable else 0))


def _generate_certificate_authority(directory: Path, stem: str, common_name: str) -> tuple[Path, Path]:
    key = directory / f"{stem}.key"
    certificate = directory / f"{stem}.crt"
    _run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:3072",
            "-sha256",
            "-days",
            "2",
            "-nodes",
            "-subj",
            f"/CN={common_name}",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
        ]
    )
    key.chmod(stat.S_IRUSR | stat.S_IWUSR)
    certificate.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return key, certificate


def _generate_tls_material(directory: Path) -> tuple[Path, Path, Path]:
    ca_key, ca_certificate = _generate_certificate_authority(
        directory, "ca", "CIGAR PostgreSQL Qualification CA"
    )
    _wrong_key, wrong_certificate = _generate_certificate_authority(
        directory, "wrong-ca", "CIGAR Untrusted Qualification CA"
    )
    server_key = directory / "server.key"
    request = directory / "server.csr"
    server_certificate = directory / "server.crt"
    extensions = directory / "server.ext"
    _write_private(
        extensions,
        "\n".join(
            (
                "basicConstraints=critical,CA:FALSE",
                "keyUsage=critical,digitalSignature,keyEncipherment",
                "extendedKeyUsage=serverAuth",
                "subjectAltName=DNS:localhost",
                "",
            )
        ),
    )
    _run(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:3072",
            "-sha256",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-keyout",
            str(server_key),
            "-out",
            str(request),
        ]
    )
    _run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(request),
            "-CA",
            str(ca_certificate),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-days",
            "2",
            "-sha256",
            "-extfile",
            str(extensions),
            "-out",
            str(server_certificate),
        ]
    )
    server_key.chmod(stat.S_IRUSR | stat.S_IWUSR)
    server_certificate.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return ca_certificate, wrong_certificate, server_certificate


def _write_postgres_init(directory: Path) -> Path:
    script = directory / "001-cigar-tls.sh"
    _write_private(
        script,
        """#!/bin/sh
set -eu
install -o postgres -g postgres -m 0600 /cigar-tls/server.key "$PGDATA/server.key"
install -o postgres -g postgres -m 0644 /cigar-tls/server.crt "$PGDATA/server.crt"
install -o postgres -g postgres -m 0644 /cigar-tls/ca.crt "$PGDATA/ca.crt"
cat >"$PGDATA/pg_hba.conf" <<'EOF'
local all all trust
hostnossl all all 0.0.0.0/0 reject
hostnossl all all ::/0 reject
hostssl all all 0.0.0.0/0 scram-sha-256
hostssl all all ::/0 scram-sha-256
EOF
cat >>"$PGDATA/postgresql.conf" <<'EOF'
listen_addresses = '*'
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
ssl_ca_file = 'ca.crt'
ssl_min_protocol_version = 'TLSv1.3'
password_encryption = 'scram-sha-256'
EOF
""",
        executable=True,
    )
    return script


def _wait_until_ready(container: str) -> None:
    deadline = time.monotonic() + READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        result = _run(
            ["docker", "exec", container, "pg_isready", "-U", "postgres", "-d", "postgres"],
            check=False,
        )
        if result.returncode == 0:
            return
        time.sleep(0.5)
    raise QualificationError("the disposable PostgreSQL server did not become ready")


def _published_port(container: str) -> int:
    output = _run(["docker", "port", container, "5432/tcp"]).stdout.strip()
    match = PORT_PATTERN.fullmatch(output)
    if match is None:
        raise QualificationError("the disposable PostgreSQL loopback port was not unique")
    port = int(match.group("port"))
    if port <= 0 or port > 65535:
        raise QualificationError("the disposable PostgreSQL loopback port was invalid")
    return port


def _remove_owned_container(container: str, run_identity: str) -> None:
    inspected = _run(
        [
            "docker",
            "inspect",
            "--format",
            '{{ index .Config.Labels "cigar.qualification.run" }}',
            container,
        ],
        check=False,
    )
    if inspected.returncode == 0 and inspected.stdout.strip() == run_identity:
        _run(["docker", "rm", "--force", "--volumes", container], check=False)


def qualify(repo_root: Path) -> None:
    if platform.system() != "Darwin":
        raise QualificationError("this qualification is currently defined only for macOS")
    _require_commands()
    image = os.environ.get("CIGAR_POSTGRES_MIGRATION_IMAGE", DEFAULT_IMAGE)
    run_identity = f"{os.getpid()}-{secrets.token_hex(8)}"
    container = f"cigar-pg-migration-{run_identity}"
    target_root = repo_root / "target"
    target_root.mkdir(mode=stat.S_IRWXU, exist_ok=True)
    if target_root.is_symlink() or not target_root.is_dir():
        raise QualificationError("the local qualification workspace is unsafe")
    temporary_root = Path(
        tempfile.mkdtemp(prefix="cigar-postgres-migration-", dir=target_root)
    )
    temporary_root.chmod(stat.S_IRWXU)
    try:
        ca_certificate, wrong_certificate, _server_certificate = _generate_tls_material(
            temporary_root
        )
        init_script = _write_postgres_init(temporary_root)
        password = secrets.token_urlsafe(36)
        environment_file = temporary_root / "postgres.env"
        _write_private(
            environment_file,
            f"POSTGRES_USER=postgres\nPOSTGRES_PASSWORD={password}\n"
            "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=trust\n",
        )
        _run(
            [
                "docker",
                "run",
                "--detach",
                "--pull=never",
                "--name",
                container,
                "--label",
                "cigar.qualification=postgres-migrations",
                "--label",
                f"cigar.qualification.run={run_identity}",
                "--env-file",
                str(environment_file),
                "--publish",
                "127.0.0.1::5432",
                "--mount",
                f"type=bind,src={temporary_root},dst=/cigar-tls,readonly",
                "--mount",
                f"type=bind,src={init_script},dst=/docker-entrypoint-initdb.d/001-cigar-tls.sh,readonly",
                image,
            ]
        )
        _wait_until_ready(container)
        port = _published_port(container)
        encoded_password = quote(password, safe="")
        test_environment = os.environ.copy()
        test_environment.update(
            {
                "CIGAR_TEST_POSTGRES_TLS_ADMIN_URL": (
                    f"postgresql://postgres:{encoded_password}@localhost:{port}/postgres"
                ),
                "CIGAR_TEST_POSTGRES_TLS_IP_ADMIN_URL": (
                    f"postgresql://postgres:{encoded_password}@127.0.0.1:{port}/postgres"
                ),
                "CIGAR_TEST_POSTGRES_TLS_SERVER_NAME": "localhost",
                "CIGAR_TEST_POSTGRES_TLS_CA_PATH": str(ca_certificate),
                "CIGAR_TEST_POSTGRES_TLS_WRONG_CA_PATH": str(wrong_certificate),
                "CIGAR_REQUIRE_LIVE_POSTGRES_MIGRATIONS": "1",
            }
        )
        _run(
            [
                "cargo",
                "nextest",
                "run",
                "--locked",
                "--config-file",
                ".config/nextest.toml",
                "--user-config-file",
                "none",
                "-P",
                "macos-qualification",
                "--no-tests",
                "fail",
                "-p",
                "cigar-store",
                "--features",
                "migration-fault-injection",
                "--test",
                "postgres_migration_tls",
            ],
            cwd=repo_root,
            env=test_environment,
            capture=False,
        )
    finally:
        _remove_owned_container(container, run_identity)
        shutil.rmtree(temporary_root, ignore_errors=True)


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    try:
        qualify(repo_root)
    except (OSError, subprocess.SubprocessError, QualificationError) as error:
        print(f"PostgreSQL migration qualification failed: {type(error).__name__}", file=sys.stderr)
        return 1
    print("PostgreSQL TLS migration qualification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
