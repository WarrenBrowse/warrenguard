#!/usr/bin/env bash
#
# Hermetic fixture test for scripts/check-quinn-advisories.sh.
#
# Why: the advisory watch is the only guard that maps the RENAMED warren-quinn
# fork crates back to their upstream RustSec names, so it has to fail LOUDLY and
# it has to be exercisable without the network. This test drives it against a
# temporary fake advisory DB, a temporary fake Cargo.lock and a temporary ignore
# file (QUINN_ADVISORY_DB_DIR, QUINN_ADVISORY_LOCK, QUINN_ADVISORY_IGNORE_FILE),
# pinning the covered / not-covered / unparseable / ignored / invocation-error
# outcomes, the "expected upstream crate directory is missing" failure, and the
# loudly-reported advisory-free upstream crate (upstream quinn-udp has no
# advisory directory at all in the live DB).
#
# No network, no root, no cargo resolver, no real advisory DB.
#
# Exit codes: 0 all assertions pass, 1 at least one assertion failed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/check-quinn-advisories.sh"

if [ ! -f "$SCRIPT" ]; then
    printf 'FATAL: %s not found\n' "$SCRIPT" >&2
    exit 2
fi

TMP="$(mktemp -d -t quinn-advisory-fixture.XXXXXX)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

PASSED=0
FAILED=0
OUT=""
RC=0

pass() { PASSED=$((PASSED + 1)); printf 'PASS %s\n' "$1"; }

fail() {
    FAILED=$((FAILED + 1))
    printf 'FAIL %s\n' "$1"
    if [ -n "$OUT" ]; then
        printf '%s\n' "$OUT" | sed 's/^/     | /'
    fi
}

# --- fixture writers ---------------------------------------------------------

# write_advisory <db> <crate> <id> <versions-table-body>
# Same ```toml front matter shape the real RustSec DB uses.
write_advisory() {
    local db="$1" crate="$2" id="$3" versions="$4"
    local dir="$db/crates/$crate"
    mkdir -p "$dir"
    {
        printf '```toml\n'
        printf '[advisory]\n'
        printf 'id = "%s"\n' "$id"
        printf 'package = "%s"\n' "$crate"
        printf 'date = "2026-01-01"\n'
        printf 'url = "https://example.invalid/advisories/%s"\n' "$id"
        printf '\n[versions]\n'
        printf '%s\n' "$versions"
        printf '```\n'
    } >"$dir/$id.md"
}

# write_raw_advisory <db> <crate> <id> <raw body>
write_raw_advisory() {
    local db="$1" crate="$2" id="$3" body="$4"
    mkdir -p "$db/crates/$crate"
    printf '%s\n' "$body" >"$db/crates/$crate/$id.md"
}

# write_lock <path> <warren-quinn> <warren-quinn-proto> <warren-quinn-udp>
write_lock() {
    local path="$1" quinn="$2" proto="$3" udp="$4"
    {
        printf 'version = 4\n\n'
        printf '[[package]]\nname = "warren-quinn"\nversion = "%s"\n\n' "$quinn"
        printf '[[package]]\nname = "warren-quinn-proto"\nversion = "%s"\n\n' "$proto"
        printf '[[package]]\nname = "warren-quinn-udp"\nversion = "%s"\n' "$udp"
    } >"$path"
}

# --- driver ------------------------------------------------------------------

# run_script <lock> <db> <ignore>
run_script() {
    local lock="$1" db="$2" ignore="$3"
    set +e
    OUT="$(QUINN_ADVISORY_DB_DIR="$db" \
        QUINN_ADVISORY_LOCK="$lock" \
        QUINN_ADVISORY_IGNORE_FILE="$ignore" \
        bash "$SCRIPT" 2>&1)"
    RC=$?
    set -e
}

expect_rc() {
    local name="$1" want="$2"
    if [ "$RC" -eq "$want" ]; then
        pass "$name (exit $RC)"
    else
        fail "$name (want exit $want, got $RC)"
    fi
}

expect_mentions() {
    local name="$1" needle="$2"
    if printf '%s' "$OUT" | grep -qF -- "$needle"; then
        pass "$name"
    else
        fail "$name (no '$needle' in output)"
    fi
}

expect_not_mentions() {
    local name="$1" needle="$2"
    if printf '%s' "$OUT" | grep -qF -- "$needle"; then
        fail "$name (unexpected '$needle' in output)"
    else
        pass "$name"
    fi
}

# --- fixtures ----------------------------------------------------------------

# Canonical DB: one advisory per upstream crate. RUSTSEC-2026-0001 leaves
# 0.11.9 affected and accepts 0.11.10, so the SAME DB yields either outcome
# depending only on the fork base version in the lockfile.
DB="$TMP/db"
write_advisory "$DB" quinn RUSTSEC-2026-0001 'patched = [">=0.11.10"]'
write_advisory "$DB" quinn-proto RUSTSEC-2026-0002 'patched = [">=0.11.9"]'
write_advisory "$DB" quinn-udp RUSTSEC-2026-0003 'unaffected = [">=0.5.0"]'

LOCK_AFFECTED="$TMP/Cargo.lock.affected"
write_lock "$LOCK_AFFECTED" 0.11.9 0.11.9 0.5.13

LOCK_COVERED="$TMP/Cargo.lock.covered"
write_lock "$LOCK_COVERED" 0.11.10 0.11.9 0.5.13

LOCK_NONE="$TMP/Cargo.lock.none"
{
    printf 'version = 4\n\n'
    printf '[[package]]\nname = "serde"\nversion = "1.0.203"\n'
} >"$LOCK_NONE"

IGNORE_EMPTY="$TMP/ignore-empty.txt"
{
    printf '# no accepted advisories\n'
} >"$IGNORE_EMPTY"

IGNORE_ONE="$TMP/ignore-one.txt"
{
    printf '# accepted: fixture rationale\n'
    printf 'RUSTSEC-2026-0001\n'
} >"$IGNORE_ONE"

# Expected upstream crate directory deliberately absent. quinn-proto carries
# advisories in the real DB, so its absence means the DB is incomplete.
DB_MISSING="$TMP/db-missing-proto"
write_advisory "$DB_MISSING" quinn RUSTSEC-2026-0001 'patched = [">=0.11.10"]'
write_advisory "$DB_MISSING" quinn-udp RUSTSEC-2026-0003 'unaffected = [">=0.5.0"]'

# Upstream RustSec has never filed an advisory against quinn-udp, so the real DB
# carries no crates/quinn-udp at all. That absence is the real state of the DB,
# not an incomplete DB, and must be reported loudly rather than failing.
DB_MISSING_UDP="$TMP/db-missing-udp"
write_advisory "$DB_MISSING_UDP" quinn RUSTSEC-2026-0001 'patched = [">=0.11.10"]'
write_advisory "$DB_MISSING_UDP" quinn-proto RUSTSEC-2026-0002 'patched = [">=0.11.9"]'

# Not a RustSec advisory DB at all.
DB_NOT_A_DB="$TMP/not-a-db"
mkdir -p "$DB_NOT_A_DB"

printf '[test-check-quinn-advisories] driving %s\n' "$SCRIPT"

# 1. Affected fork base version -> exit 1, and the failing advisory is named.
run_script "$LOCK_AFFECTED" "$DB" "$IGNORE_EMPTY"
expect_rc "affected base version fails" 1
expect_mentions "affected base version names RUSTSEC-2026-0001" "RUSTSEC-2026-0001"

# 2. Base version covered by `patched` (quinn) and `unaffected` (quinn-udp).
run_script "$LOCK_COVERED" "$DB" "$IGNORE_EMPTY"
expect_rc "covered base version passes" 0

# 3. Missing expected upstream crate directory is a failure, not a skip.
run_script "$LOCK_COVERED" "$DB_MISSING" "$IGNORE_EMPTY"
expect_rc "missing expected crate directory fails" 1
expect_mentions "missing crate directory is named" "quinn-proto"
expect_not_mentions "missing crate directory is not reported as all clear" "all clear"

# 3b. The one legitimate absence: an upstream crate with no advisory on record.
run_script "$LOCK_COVERED" "$DB_MISSING_UDP" "$IGNORE_EMPTY"
expect_rc "advisory-free upstream crate passes" 0
expect_mentions "advisory-free upstream crate is reported, not skipped" "NO-ADVISORIES quinn-udp"

# 4. Advisory with no fenced toml front matter -> conservative failure.
DB_NO_FENCE="$TMP/db-no-fence"
write_advisory "$DB_NO_FENCE" quinn RUSTSEC-2026-0001 'patched = [">=0.11.10"]'
write_advisory "$DB_NO_FENCE" quinn-proto RUSTSEC-2026-0002 'patched = [">=0.11.9"]'
write_raw_advisory "$DB_NO_FENCE" quinn-udp RUSTSEC-2026-0003 \
    'This advisory carries no fenced toml front matter.'
run_script "$LOCK_COVERED" "$DB_NO_FENCE" "$IGNORE_EMPTY"
expect_rc "advisory without front matter fails" 1
expect_mentions "unparseable advisory is named" "RUSTSEC-2026-0003"

# 5. [versions] present but with neither patched nor unaffected -> failure.
DB_NO_VERSIONS="$TMP/db-no-versions"
write_advisory "$DB_NO_VERSIONS" quinn RUSTSEC-2026-0001 'patched = [">=0.11.10"]'
write_advisory "$DB_NO_VERSIONS" quinn-proto RUSTSEC-2026-0002 'patched = [">=0.11.9"]'
write_advisory "$DB_NO_VERSIONS" quinn-udp RUSTSEC-2026-0003 ''
run_script "$LOCK_COVERED" "$DB_NO_VERSIONS" "$IGNORE_EMPTY"
expect_rc "advisory with no patched/unaffected fails" 1
expect_mentions "empty-versions advisory is named" "RUSTSEC-2026-0003"

# 6. Lockfile without warren-quinn packages -> invocation error.
run_script "$LOCK_NONE" "$DB" "$IGNORE_EMPTY"
expect_rc "lockfile without fork packages is an invocation error" 2

# 7. Advisory listed in the ignore file -> accepted.
run_script "$LOCK_AFFECTED" "$DB" "$IGNORE_ONE"
expect_rc "ignored advisory passes" 0
expect_mentions "ignored advisory is reported" "RUSTSEC-2026-0001"

# 8. QUINN_ADVISORY_DB_DIR that is not a RustSec advisory DB -> invocation error.
run_script "$LOCK_COVERED" "$DB_NOT_A_DB" "$IGNORE_EMPTY"
expect_rc "non-DB directory is an invocation error" 2

# 9. QUINN_ADVISORY_LOCK pointing at a missing file -> invocation error.
run_script "$TMP/absent.lock" "$DB" "$IGNORE_EMPTY"
expect_rc "missing lockfile is an invocation error" 2

# --- summary -----------------------------------------------------------------

printf '\n[test-check-quinn-advisories] %d passed, %d failed\n' "$PASSED" "$FAILED"
if [ "$FAILED" -gt 0 ]; then
    printf '[test-check-quinn-advisories] FAILED\n'
    exit 1
fi
printf '[test-check-quinn-advisories] OK\n'
