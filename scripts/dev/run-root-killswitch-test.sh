#!/usr/bin/env bash
#
# run-root-killswitch-test.sh - run the root-only WarrenGuard killswitch tests,
# building as the invoking user.
#
# Why this wrapper exists: the real `/dev/pf` path needs root on macOS (there is no
# capability model, and `/dev/pf` is mode 0600 root:wheel), while cargo must run
# unprivileged or every artifact it writes lands owned by root and the next normal
# build fails with permission errors. So the build happens here, as you, and ONLY
# the compiled test binary is elevated.
#
# The test it runs is DESTRUCTIVE on purpose: it installs the killswitch policy and
# purges every connection the policy does not pass, on this host. That is what a
# killswitch install does. Run it on an idle Mac, and read the test's doc comment in
# crates/warrenguard-killswitch-os/src/macos.rs for what it asserts and what it
# restores.
#
# A pre-flight refusal (`UnconfirmedStates`, which a busy host triggers) makes the
# test exit NON-ZERO on purpose, with an "inconclusive" message: the anchor was never
# loaded, so no install/uninstall cycle ran and the run proves nothing. Rerun it when
# the host is idle.
#
# Usage:
#   scripts/dev/run-root-killswitch-test.sh                  # run, tee to target/
#   scripts/dev/run-root-killswitch-test.sh --print-only     # build, print the command
#   scripts/dev/run-root-killswitch-test.sh --log /tmp/pf.log
#   scripts/dev/run-root-killswitch-test.sh --filter real_pf_install
#
# Exit status is the test binary's; the log path is printed at the end either way.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
CRATE="warrenguard-killswitch-os"
DEFAULT_FILTER="real_pf_install_and_uninstall_cycle"
DEFAULT_LOG="$REPO_ROOT/target/root-killswitch-test.log"

PRINT_ONLY=0
LOG="$DEFAULT_LOG"
FILTER="$DEFAULT_FILTER"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --print-only) PRINT_ONLY=1; shift ;;
        --log) LOG="${2:?--log needs a path}"; shift 2 ;;
        --filter) FILTER="${2:?--filter needs a test name}"; shift 2 ;;
        -h | --help) sed -n '2,29p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [[ "$(uname)" != "Darwin" ]]; then
    echo "error: this wrapper exists for macOS (/dev/pf needs root there)" >&2
    exit 2
fi

echo "==> building $CRATE as $(id -un)"
artifacts="$(mktemp -t warren-killswitch-artifacts.XXXXXX)"
trap 'rm -f "$artifacts"' EXIT

# `--no-run` keeps the build unprivileged; the JSON stream is what carries the
# executable path, which a plain `--no-run` prints in a form that is awkward to
# parse reliably.
cargo test --manifest-path "$REPO_ROOT/Cargo.toml" -p "$CRATE" --no-run \
    --message-format=json >"$artifacts"

test_binary="$(
    python3 - "$artifacts" <<'PYEOF'
import json
import sys

path = ""
with open(sys.argv[1], encoding="utf-8") as stream:
    for line in stream:
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if message.get("reason") != "compiler-artifact":
            continue
        target = message.get("target", {})
        if target.get("name") != "warrenguard_killswitch_os":
            continue
        if not str(target.get("src_path", "")).endswith("src/lib.rs"):
            continue
        if message.get("executable"):
            path = message["executable"]
print(path)
PYEOF
)"

if [[ -z "$test_binary" || ! -x "$test_binary" ]]; then
    echo "error: could not find the lib test executable for $CRATE" >&2
    exit 2
fi
echo "==> lib test binary: $test_binary"

if ! "$test_binary" --list --ignored "$FILTER" | grep -qE '^[^[:space:]].*: test$'; then
    echo "error: no ignored test matches filter: $FILTER" >&2
    exit 2
fi

# The test refuses to run without this opt-in, because installing the policy purges
# the host's off-policy connections. Both halves are required: root for /dev/pf, and
# the variable so an accidental `cargo test -- --ignored` fails before mutation.
command=(sudo env "WARREN_KILLSWITCH_ROOT_TEST=1" "$test_binary" --ignored --nocapture "$FILTER")

echo "==> this purges every connection this policy does not pass, on THIS host"
echo "==> if it is interrupted, recover with:"
echo "      sudo pfctl -a com.apple/250.warrenguard_killswitch_os -F rules"
echo "    and, only if this host had pf off before: sudo pfctl -d"
echo "==> note: a pre-flight refusal FAILS this test on purpose, as 'inconclusive':"
echo "==>       the anchor was never loaded, so no install/uninstall cycle ran"
echo "==> running: ${command[*]}"

if [[ "$PRINT_ONLY" == "1" ]]; then
    echo "==> --print-only: nothing was run"
    exit 0
fi

set +e
"${command[@]}" 2>&1 | tee "$LOG"
status="${PIPESTATUS[0]}"
set -e

echo "==> log: $LOG"
exit "$status"
