#!/usr/bin/env bash
# Called only by security CI inside its fresh D-Bus session and private XDG roots.
set -euo pipefail

test "${CIGAR_ISOLATED_SECRET_SERVICE_TEST:?}" = "1"
test -n "${DBUS_SESSION_BUS_ADDRESS:?}"
test -d "${XDG_DATA_HOME:?}"
test -d "${XDG_RUNTIME_DIR:?}"
test -d "${CIGAR_TEST_KEYRING_CONTROL:?}"

printf '%s' 'cigar-ci-synthetic-session' | gnome-keyring-daemon \
  --unlock --components=secrets \
  --control-directory="${CIGAR_TEST_KEYRING_CONTROL}"

# Check registration first: a misspelled filter must not pass with zero tests.
cargo test --locked -p cigar-crypto --lib -- --ignored --list | python3 -c '
import sys
expected = "keystore::native_keychain::tests::linux_secret_service_reuses_legacy_credentials: test"
assert expected in sys.stdin.read().splitlines()
'
cargo test --locked -p cigar-crypto --lib -- \
  --ignored --exact \
  keystore::native_keychain::tests::linux_secret_service_reuses_legacy_credentials \
  --test-threads=1
