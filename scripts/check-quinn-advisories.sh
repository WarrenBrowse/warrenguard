#!/usr/bin/env bash
# RUSTSEC advisory watch for the warren-quinn fork.
#
# Why: cargo-audit and cargo-deny match advisories by (crate name, version)
# against Cargo.lock. The fork ships RENAMED crates (warren-quinn /
# warren-quinn-proto / warren-quinn-udp) at a fork version, so an advisory filed
# against upstream quinn / quinn-proto / quinn-udp never matches the lockfile
# entries, and a future QUIC-stack CVE would be silently invisible to both
# tools. This script recovers each fork crate's UPSTREAM BASE version from
# Cargo.lock, maps it back to the upstream crate name, and evaluates every
# advisory filed against those crates. It fails loudly when a base version is
# inside an affected range, or when an advisory cannot be parsed (conservative:
# unparseable is a failure, never a silent skip).
#
# Two sources are evaluated. The RustSec DB, and the GitHub repository
# advisories of quinn-rs/quinn: upstream files some advisories there only, and
# GHSA-6pp4-4cxf-xf88 (quinn-udp < 0.6.3) sat 25 days unseen by this watch
# because RustSec never imported it. A repository advisory's vulnerable range is
# maintainer free text (`< 0.5.16, >= 0.6.0 < 0.6.3`, `> 0.7.0` with no upper
# bound), so it is not trusted: a base version is covered only when it reaches
# the patched version listed for its own release line, or every listed one.
#
# Reviewed-and-accepted advisories can be ignored via the ignore file (one
# RUSTSEC or GHSA id per line, rationale mandatory as a comment). A RustSec
# advisory whose aliases name an ignored GHSA id is accepted with it, so a
# GitHub-only advisory accepted today stays accepted once RustSec imports it.
#
# Environment overrides (they let scripts/ci/test-check-quinn-advisories.sh drive
# this script hermetically, without network access):
#   QUINN_ADVISORY_DB_DIR       already-checked-out RustSec advisory DB; used
#                               as-is and the clone is skipped. Must contain a
#                               `crates` directory, else exit 2.
#   QUINN_ADVISORY_LOCK         Cargo.lock to read the fork base versions from
#                               (default: $REPO_ROOT/Cargo.lock, exit 2 when the
#                               file does not exist).
#   QUINN_ADVISORY_IGNORE_FILE  ignore file (default:
#                               scripts/quinn-advisories-ignore.txt).
#   QUINN_GHSA_JSON             file holding the GitHub repository advisories
#                               as the REST API returns them; the fetch is
#                               skipped (exit 2 when the file does not exist).
#                               Otherwise they are fetched from api.github.com,
#                               authenticated with GITHUB_TOKEN or GH_TOKEN when
#                               set.
#
# An expected upstream crate with NO `crates/<name>` directory in the DB is a
# FAILURE (exit 1), never a skip: a crate silently dropped from the evaluation is
# exactly the blind spot this script exists to close. The single exception is an
# upstream crate the RustSec DB has never filed an advisory against (upstream
# quinn-udp today): there the absent directory is the real state of the DB, so it
# is reported explicitly instead of failing. Filing an advisory creates the
# directory, which is then evaluated like any other, so the exception cannot hide
# one. See FORK_UPSTREAM_WITHOUT_ADVISORIES below.
#
# Requirements: git (only when QUINN_ADVISORY_DB_DIR is unset), curl (only when
# QUINN_GHSA_JSON is unset), python3 with tomllib (3.11+) or the `tomli`
# backport.
#
# Exit codes:
#   0  every advisory against the fork crates is covered (or explicitly ignored)
#   1  at least one advisory is NOT covered (or could not be parsed)
#   2  invocation error (no Cargo.lock, no git, no TOML parser, the GitHub
#      advisories unreachable or not an advisory list, ...)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOCK="${QUINN_ADVISORY_LOCK:-$REPO_ROOT/Cargo.lock}"
IGNORE_FILE="${QUINN_ADVISORY_IGNORE_FILE:-$SCRIPT_DIR/quinn-advisories-ignore.txt}"
ADVISORY_DB_URL="https://github.com/rustsec/advisory-db.git"
GHSA_URL="https://api.github.com/repos/quinn-rs/quinn/security-advisories?per_page=100"

if [[ ! -f "$LOCK" ]]; then
    echo "ERROR: $LOCK not found (run from a resolved warrenguard workspace, or set QUINN_ADVISORY_LOCK)" >&2
    exit 2
fi

if [[ -n "${QUINN_ADVISORY_DB_DIR:-}" ]]; then
    DB_DIR="$QUINN_ADVISORY_DB_DIR"
    if [[ ! -d "$DB_DIR/crates" ]]; then
        echo "ERROR: QUINN_ADVISORY_DB_DIR=$DB_DIR is not a RustSec advisory DB (no crates/ directory)" >&2
        exit 2
    fi
    echo "==> Using pre-checked-out advisory DB at $DB_DIR (QUINN_ADVISORY_DB_DIR)"
    CLEANUP_DB_DIR=""
else
    DB_DIR="$(mktemp -d -t rustsec-advisory-db.XXXXXX)"
    CLEANUP_DB_DIR="$DB_DIR"
    echo "==> Cloning rustsec/advisory-db (shallow) into $DB_DIR"
fi
CLEANUP_GHSA=""
trap 'if [[ -n "$CLEANUP_DB_DIR" ]]; then rm -rf "$CLEANUP_DB_DIR"; fi; if [[ -n "$CLEANUP_GHSA" ]]; then rm -f "$CLEANUP_GHSA"; fi' EXIT INT TERM

if [[ -n "$CLEANUP_DB_DIR" ]]; then
    git clone --quiet --depth 1 "$ADVISORY_DB_URL" "$DB_DIR"
fi

if [[ -n "${QUINN_GHSA_JSON:-}" ]]; then
    GHSA_JSON="$QUINN_GHSA_JSON"
    if [[ ! -f "$GHSA_JSON" ]]; then
        echo "ERROR: QUINN_GHSA_JSON=$GHSA_JSON does not exist" >&2
        exit 2
    fi
    echo "==> Using GitHub repository advisories from $GHSA_JSON (QUINN_GHSA_JSON)"
else
    GHSA_JSON="$(mktemp -t quinn-ghsa.XXXXXX)"
    CLEANUP_GHSA="$GHSA_JSON"
    echo "==> Fetching the GitHub repository advisories of quinn-rs/quinn"
    auth=()
    token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
    if [[ -n "$token" ]]; then
        auth=(-H "Authorization: Bearer $token")
    fi
    if ! curl -fsSL --retry 3 --max-time 60 -H "Accept: application/vnd.github+json" \
        "${auth[@]}" -o "$GHSA_JSON" "$GHSA_URL"; then
        echo "ERROR: could not fetch $GHSA_URL" >&2
        exit 2
    fi
fi

DB_DIR="$DB_DIR" LOCK="$LOCK" IGNORE_FILE="$IGNORE_FILE" GHSA_JSON="$GHSA_JSON" python3 - <<'PYEOF'
import json
import os
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib  # backport for python < 3.11
    except ModuleNotFoundError:
        print(
            "ERROR: need python 3.11+ (tomllib) or the `tomli` backport",
            file=sys.stderr,
        )
        sys.exit(2)

LOCK = Path(os.environ["LOCK"])
DB = Path(os.environ["DB_DIR"])
IGNORE_FILE = Path(os.environ["IGNORE_FILE"])
GHSA_JSON = Path(os.environ["GHSA_JSON"])
# The REST endpoint pages at 100; a full page means advisories may be missing.
GHSA_PAGE_SIZE = 100

# Fork package name in Cargo.lock -> upstream crate name in the advisory DB.
FORK_TO_UPSTREAM = {
    "warren-quinn": "quinn",
    "warren-quinn-proto": "quinn-proto",
    "warren-quinn-udp": "quinn-udp",
}

# Upstream crates the RustSec DB has never filed an advisory against, so the DB
# legitimately carries no crates/<name> directory for them. Verified against the
# live DB: it ships crates/quinn and crates/quinn-proto, and no quinn-udp entry
# anywhere. Without this, an absent directory would have to mean "the DB is
# incomplete" for every expected crate, and the watch would fail on every run,
# including on a pristine clone. The exemption cannot hide an advisory: filing
# one creates the directory, which the loop below then evaluates like any other.
FORK_UPSTREAM_WITHOUT_ADVISORIES = frozenset({"quinn-udp"})


def parse_version(s):
    """Parse 'X.Y.Z' (pre-release / build suffix dropped) into a tuple."""
    core = s.strip().split("-")[0].split("+")[0]
    parts = core.split(".")
    if not 1 <= len(parts) <= 3 or not all(p.isdigit() for p in parts):
        raise ValueError(f"unparseable version: {s!r}")
    return tuple(int(p) for p in parts) + (0,) * (3 - len(parts))


def satisfies(version, requirement):
    """True when `version` satisfies a comma-compound semver requirement."""
    for comparator in requirement.split(","):
        comparator = comparator.strip()
        m = re.fullmatch(r"(>=|<=|>|<|=|\^)?\s*([0-9][0-9A-Za-z.+-]*)", comparator)
        if not m:
            raise ValueError(f"unsupported comparator: {comparator!r}")
        op = m.group(1) or "="
        bound = parse_version(m.group(2))
        if op == ">=" and not version >= bound:
            return False
        if op == ">" and not version > bound:
            return False
        if op == "<=" and not version <= bound:
            return False
        if op == "<" and not version < bound:
            return False
        if op == "=" and version != bound:
            return False
        if op == "^":
            # ^x.y.z: >= x.y.z and < (x+1).0.0 (x > 0), the only caret form
            # rustsec uses in practice; for 0.y.z the compatible upper is 0.(y+1).0.
            upper = (bound[0] + 1, 0, 0)
            if bound[0] == 0:
                upper = (0, bound[1] + 1, 0)
            if not (bound <= version < upper):
                return False
    return True


def release_line(version):
    """The semver compatibility line: 0.y for 0.y.z, x for x.y.z."""
    return version[:2] if version[0] == 0 else version[:1]


def ghsa_patched_versions(text):
    """Parse a repository advisory's `patched_versions` free text.

    GitHub accepts `0.11.19`, `>= 0.11.19` and comma lists of one fix per
    release line (`>= 0.5.16, >= 0.6.3`, `0.9.5, 0.10.5`). Any other operator
    cannot be read as "fixed from" and is refused.
    """
    fixes = []
    for item in text.split(","):
        item = item.strip()
        if item.startswith(">="):
            item = item[2:].strip()
        if not item or not item[0].isdigit():
            raise ValueError(f"unsupported patched version: {item!r}")
        fixes.append(parse_version(item))
    return fixes


def ghsa_covered(base, fixes):
    """Covered at the fix of its own release line, or above every fix."""
    if base >= max(fixes):
        return True
    return any(release_line(fix) == release_line(base) and base >= fix for fix in fixes)


def front_matter(text):
    """Extract the ```toml fenced front matter of an advisory file."""
    m = re.search(r"```toml\n(.*?)```", text, re.DOTALL)
    if not m:
        raise ValueError("no ```toml front matter found")
    return tomllib.loads(m.group(1))


lock = tomllib.loads(LOCK.read_text())
crates = {}
for pkg in lock.get("package", []):
    upstream = FORK_TO_UPSTREAM.get(pkg.get("name"))
    if upstream:
        crates[upstream] = pkg["version"]
if not crates:
    print(
        "ERROR: no warren-quinn* packages found in Cargo.lock (fork de-patched?)",
        file=sys.stderr,
    )
    sys.exit(2)

print("==> Fork base versions: " + " ".join(f"{u}={v}" for u, v in crates.items()))

IGNORED = set()
if IGNORE_FILE.is_file():
    IGNORED = set(
        re.findall(
            r"RUSTSEC-\d{4}-\d{4}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}",
            IGNORE_FILE.read_text(),
        )
    )

try:
    ghsa_advisories = json.loads(GHSA_JSON.read_text())
except ValueError as exc:
    print(f"ERROR: {GHSA_JSON} is not JSON ({exc})", file=sys.stderr)
    sys.exit(2)
if not isinstance(ghsa_advisories, list):
    print(
        f"ERROR: {GHSA_JSON} is not a GitHub advisory list: {str(ghsa_advisories)[:200]}",
        file=sys.stderr,
    )
    sys.exit(2)

failures = []
checked = 0
for crate, base_str in crates.items():
    base = parse_version(base_str)
    crate_dir = DB / "crates" / crate
    if not crate_dir.is_dir():
        if crate in FORK_UPSTREAM_WITHOUT_ADVISORIES:
            print(
                f"NO-ADVISORIES {crate}: no crates/{crate} in the advisory DB "
                "(RustSec has filed none), nothing to evaluate"
            )
            continue
        failures.append(
            f"{crate} ({base_str}): no {crate_dir} in the advisory DB, so its "
            "advisories cannot be evaluated"
        )
        continue
    for adv_path in sorted(crate_dir.glob("RUSTSEC-*.md")):
        adv_id = adv_path.stem
        checked += 1
        if adv_id in IGNORED:
            print(f"IGNORED {adv_id} ({crate}) per quinn-advisories-ignore.txt")
            continue
        try:
            meta = front_matter(adv_path.read_text())
            aliases = IGNORED.intersection(meta.get("advisory", {}).get("aliases", []))
            if aliases:
                print(
                    f"IGNORED {adv_id} ({crate}) as alias of {', '.join(sorted(aliases))} "
                    "per quinn-advisories-ignore.txt"
                )
                continue
            versions = meta.get("versions", {})
            patched = versions.get("patched", [])
            unaffected = versions.get("unaffected", [])
            if not patched and not unaffected:
                failures.append(f"{adv_id} ({crate} {base_str}): no patched version exists")
                continue
            covered = any(satisfies(base, req) for req in (*patched, *unaffected))
            if covered:
                print(f"OK {adv_id} ({crate}): base {base_str} is patched/unaffected")
            else:
                failures.append(
                    f"{adv_id} ({crate} {base_str}): base version is AFFECTED "
                    f"(patched={patched} unaffected={unaffected})"
                )
        except Exception as exc:  # conservative: unparseable = failure
            failures.append(f"{adv_id} ({crate}): cannot evaluate ({exc})")

if len(ghsa_advisories) >= GHSA_PAGE_SIZE:
    failures.append(
        f"GitHub returned a full page of {len(ghsa_advisories)} advisories; "
        "pagination is not implemented, so some were not evaluated"
    )
for adv in ghsa_advisories:
    adv_id = adv.get("ghsa_id", "<no ghsa_id>")
    if adv.get("state") != "published" or adv.get("withdrawn_at"):
        continue
    for vuln in adv.get("vulnerabilities") or []:
        crate = (vuln.get("package") or {}).get("name")
        if crate not in crates:
            continue
        checked += 1
        base_str = crates[crate]
        if adv_id in IGNORED:
            print(f"IGNORED {adv_id} ({crate}) per quinn-advisories-ignore.txt")
            continue
        patched = vuln.get("patched_versions")
        if not patched:
            failures.append(f"{adv_id} ({crate} {base_str}): no patched version exists")
            continue
        try:
            if ghsa_covered(parse_version(base_str), ghsa_patched_versions(patched)):
                print(f"OK {adv_id} ({crate}): base {base_str} is patched ({patched})")
            else:
                failures.append(
                    f"{adv_id} ({crate} {base_str}): base version is AFFECTED "
                    f"(patched={patched!r})"
                )
        except Exception as exc:  # conservative: unparseable = failure
            failures.append(f"{adv_id} ({crate}): cannot evaluate ({exc})")

print(f"==> {checked} advisories checked across {', '.join(crates)}")
if failures:
    print("", file=sys.stderr)
    print("ERROR: quinn fork advisory watch failed:", file=sys.stderr)
    for f in failures:
        print(f"  - {f}", file=sys.stderr)
    print(
        "\nAction: rebase the fork on a patched upstream base and push a new "
        "warren-quinn tag (bump the tag in the root Cargo.toml), or document an "
        "accepted risk or a backported fix in scripts/quinn-advisories-ignore.txt.",
        file=sys.stderr,
    )
    sys.exit(1)
print("==> quinn fork advisory watch: all clear")
PYEOF
