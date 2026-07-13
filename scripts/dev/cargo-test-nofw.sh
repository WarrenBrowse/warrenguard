#!/usr/bin/env bash
#
# cargo-test-nofw - wrapper that temporarily disables the macOS
# Application Firewall during a cargo test/run/bench, to avoid the
# recurring popups triggered by each freshly compiled binary hash.
#
# Disables the 3 modes of the macOS Application Firewall:
#   - --setglobalstate     : global firewall on/off
#   - --setblockall        : strict "block all incoming" mode
#   - --setstealthmode     : does not answer pings
# All 3 are restored to their initial state via `trap` at the end,
# including on Ctrl-C, panic, or a kill of the wrapper.
#
# Usage:
#   ./scripts/dev/cargo-test-nofw.sh test --workspace
#   ./scripts/dev/cargo-test-nofw.sh test -p warrenguard-transport --test bench --release -- --ignored
#   ./scripts/dev/cargo-test-nofw.sh run -p warrenguard-cli -- --use-tun ...
#
# Hint: `alias nofw='./scripts/dev/cargo-test-nofw.sh'` in your ~/.zshrc.
#
# On Linux, transparent passthrough to cargo.

set -euo pipefail

# ---------------------------------------------------------------------------
# Linux / non-macOS: passthrough.
# ---------------------------------------------------------------------------
if [[ "$(uname)" != "Darwin" ]]; then
    exec cargo "$@"
fi

FW_BIN=/usr/libexec/ApplicationFirewall/socketfilterfw

# ---------------------------------------------------------------------------
# Check that sudo can call `socketfilterfw` without a password.
#
# Ideally the user configured `/etc/sudoers.d/warren-firewall` with
# NOPASSWD for socketfilterfw only, so `sudo -n socketfilterfw
# --getglobalstate` passes immediately.
#
# `sudo -v` (generic credential validation) prompts for a password even
# with a scoped NOPASSWD, so we avoid it and test the target command
# directly.
# ---------------------------------------------------------------------------
if ! sudo -n "$FW_BIN" --getglobalstate >/dev/null 2>&1; then
    echo "==> sudo password required for socketfilterfw" >&2
    echo "==> Configure a scoped NOPASSWD sudoers rule to avoid this prompt" >&2
    sudo -v
fi

# ---------------------------------------------------------------------------
# Capture the initial state of the 3 firewall modes.
# Typical output:
#   "Firewall is enabled. (State = 1)"
#   "Firewall has block all state set to disabled."
#   "Stealth mode disabled"
# ---------------------------------------------------------------------------
state_was() {
    local query="$1"
    local pattern="$2"
    sudo "$FW_BIN" "$query" 2>/dev/null | grep -qiE "$pattern"
}

GLOBAL_WAS_ON=0
state_was --getglobalstate 'enabled' && GLOBAL_WAS_ON=1

BLOCKALL_WAS_ON=0
state_was --getblockall 'set to enabled' && BLOCKALL_WAS_ON=1

STEALTH_WAS_ON=0
state_was --getstealthmode '^stealth mode enabled' && STEALTH_WAS_ON=1

# ---------------------------------------------------------------------------
# Restoration via trap. Always best-effort: log but do not fail if a
# restore command fails (the user can always rerun it manually).
# ---------------------------------------------------------------------------
restore_firewall() {
    local exit_code=$?
    if [[ "$GLOBAL_WAS_ON" == "1" ]]; then
        echo "==> Restoring firewall global state (was: enabled)" >&2
        sudo "$FW_BIN" --setglobalstate on >/dev/null 2>&1 || true
    fi
    if [[ "$BLOCKALL_WAS_ON" == "1" ]]; then
        echo "==> Restoring firewall block-all (was: enabled)" >&2
        sudo "$FW_BIN" --setblockall on >/dev/null 2>&1 || true
    fi
    if [[ "$STEALTH_WAS_ON" == "1" ]]; then
        echo "==> Restoring firewall stealth mode (was: enabled)" >&2
        sudo "$FW_BIN" --setstealthmode on >/dev/null 2>&1 || true
    fi

    # Kill orphan test binaries: a UDP/TCP accept helper can hang forever
    # if no client ever connects, spinning at ~90% CPU. If this wrapper is
    # killed (Ctrl-C, timeout, parent shell) before cargo reaps its
    # children, clean them up best-effort so they do not linger for hours.
    local orphans
    orphans=$(pgrep -f "$REPO_ROOT/target/(debug|release|profiling)/deps/(regressions_|multi_conn|pump-|e2e_|exit_|coverage_)" 2>/dev/null || true)
    if [[ -n "$orphans" ]]; then
        echo "==> Killing orphan test binaries: $(echo "$orphans" | tr '\n' ' ')" >&2
        kill -9 $orphans 2>/dev/null || true
    fi

    exit $exit_code
}
trap restore_firewall EXIT INT TERM

# Capture the repo root for orphan cleanup (in case the cwd changes
# during execution or the wrapper is launched from a subdirectory).
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

# ---------------------------------------------------------------------------
# Disable the 3 modes during execution.
# ---------------------------------------------------------------------------
if [[ "$GLOBAL_WAS_ON" == "1" ]]; then
    echo "==> Disabling firewall global state" >&2
    sudo "$FW_BIN" --setglobalstate off >/dev/null
fi
if [[ "$BLOCKALL_WAS_ON" == "1" ]]; then
    echo "==> Disabling firewall block-all" >&2
    sudo "$FW_BIN" --setblockall off >/dev/null
fi
if [[ "$STEALTH_WAS_ON" == "1" ]]; then
    echo "==> Disabling firewall stealth mode" >&2
    sudo "$FW_BIN" --setstealthmode off >/dev/null
fi

# ---------------------------------------------------------------------------
# Run cargo with the passed args. `exec` is *not* used here because we
# need the `trap` to restore the firewall afterwards.
# ---------------------------------------------------------------------------
cargo "$@"
