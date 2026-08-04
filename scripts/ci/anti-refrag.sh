#!/usr/bin/env bash
#
# Anti-refragmentation gate for warrenguard (the generic VPN-over-QUIC engine).
#
# Runnable form of doc 47 section 5 invariants 1 ("dependency direction") and 6
# ("un seul foyer"), against the doc-94 single-home catalog
# (warren-core/docs/94-DEDUP-AUDIT-2026-07-16.md; doc 47 and doc 94 are design
# records in the private warren-core repo). The engine is generic and
# knows NOTHING of Warren (no account, no SS58, no signed directory, no product
# identity): a Warren-specific responsibility appearing here is a second home for
# something owned by warren-contract or the SDK/backend, and an upward dependency
# breaks the public/private layering.
#
# Cheap (grep + one offline `cargo metadata --no-deps`), offline, low-false-
# positive: it bans TWIN DEFINITIONS while allowing re-exports/calls, excludes
# tests, cites its doc-94 item, and honors an inline `anti-refrag:allow` hatch.

set -u

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2

VIOLATIONS=0

report() {
  VIOLATIONS=$((VIOLATIONS + 1))
  printf '\n[anti-refrag] VIOLATION (%s): %s\n' "$1" "$2"
  printf '%s\n' "$3" | sed 's/^/    /'
}

forbid_rs() {
  doc="$1"; msg="$2"; regex="$3"; shift 3
  out="$(grep -REn --include='*.rs' \
        --exclude-dir=target --exclude-dir=tests \
        --exclude='tests.rs' --exclude='*_test.rs' \
        "$regex" "$@" 2>/dev/null | grep -v 'anti-refrag:allow' || true)"
  [ -n "$out" ] && report "$doc" "$msg" "$out"
}

# Dependency direction via cargo metadata (doc 47 section 5 invariant 1): no
# dependency may resolve into a Warren client/backend/app repo. `--no-deps` is
# offline; grep the JSON so no JSON tooling is needed. Fail-open if cargo absent.
forbid_dep_direction() {
  doc="$1"; forbidden="$2"
  command -v cargo >/dev/null 2>&1 || { printf '[anti-refrag] cargo absent, skipping dep-direction\n'; return 0; }
  meta="$(cargo metadata --no-deps --format-version 1 2>/dev/null)" || {
    printf '[anti-refrag] cargo metadata failed, skipping dep-direction\n'; return 0; }
  hits="$(printf '%s' "$meta" | grep -oE '"(path|source)":[[:space:]]*"[^"]*"' \
          | grep -E "$forbidden" || true)"
  [ -n "$hits" ] && report "$doc" \
    "dependency direction: the generic engine must not depend on any Warren client/backend/app crate (doc 47 s5.1)" \
    "$hits"
}

printf '[anti-refrag] warrenguard: scanning for Warren-logic leaks into the generic engine...\n'

# ---- Rules (each cites its doc-94 item) --------------------------------------

# Direction: the engine depends only on the quinn fork + third-party crates,
# never on warren-core (backend), warren-sdk-rs, warren-contract, or warren-app.
forbid_dep_direction "doc47 s5.1" 'warren-core|warren-app|warren-sdk|warren-contract|[/+]mullvad-'

# Engine purity: the product-identity responsibilities are single-homed in
# warren-contract (SS58 codec, USER_AGENT, phase reduction). The generic engine
# must never grow its own copy (doc 47 s1/s4, doc 94 D4/A8).
forbid_rs "doc94 D4/A8" \
  "Warren product identity defined in the generic engine (home: warren-contract)" \
  'fn[[:space:]]+ss58_(encode|decode)|const[[:space:]]+USER_AGENT|fn[[:space:]]+reduce_phase' \
  "crates"

# -----------------------------------------------------------------------------

if [ "$VIOLATIONS" -gt 0 ]; then
  printf '\n[anti-refrag] FAILED: %d single-home violation(s). Keep the engine generic; the product home is warren-contract/SDK.\n' "$VIOLATIONS"
  exit 1
fi
printf '[anti-refrag] OK: engine stays generic, no regrown twins.\n'
