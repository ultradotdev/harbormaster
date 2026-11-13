#!/bin/bash
# End-to-end check against an independent HomeKit controller (aiohomekit):
# discover, reject a wrong setup code, pair, read, receive an event, restart
# the bridge, reconnect with the saved pairing, then unpair.
#
# Usage: tools/e2e/run.sh VENV_PARENT
# VENV_PARENT needs a Python virtualenv at VENV_PARENT/venv with aiohomekit
# installed (python3 -m venv VENV_PARENT/venv && VENV_PARENT/venv/bin/pip install aiohomekit).
# Bridge state goes under target/e2e, which keeps the control socket path short.
set -u
V="${1:?virtualenv parent directory required}"
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/../../target/debug/harbormaster"
W="$(cd "$HERE/../.." && pwd)/target/e2e"
cargo build -q --manifest-path "$HERE/../../Cargo.toml" || exit 1
start() { "$BIN" daemon --state-dir "$W/state" --listen 0.0.0.0:51900 --demo >> "$W/state/bridge.log" 2>&1 & PID=$!; sleep 2; }
rm -rf "$W/state"; mkdir -p "$W/state"
start
"$V/venv/bin/python" -I "$HERE/pair_test.py" main "$W/state/state.json"; R1=$?
kill $PID; wait $PID 2>/dev/null
start
"$V/venv/bin/python" -I "$HERE/pair_test.py" resume "$W/state/state.json"; R2=$?
kill $PID; wait $PID 2>/dev/null
exit $((R1 + R2))
