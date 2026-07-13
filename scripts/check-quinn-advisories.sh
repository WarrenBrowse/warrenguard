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
# Reviewed-and-accepted advisories can be ignored via
# scripts/quinn-advisories-ignore.txt (one RUSTSEC id per line, rationale
# mandatory as a comment).
#
# Requirements: git, python3 with tomllib (3.11+) or the `tomli` backport.
#
# Exit codes:
#   0  every advisory against the fork crates is covered (or explicitly ignored)
#   1  at least one advisory is NOT covered (or could not be parsed)
#   2  invocation error (no Cargo.lock, no git, no TOML parser, ...)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
LOCK="$REPO_ROOT/Cargo.lock"
IGNORE_FILE="$SCRIPT_DIR/quinn-advisories-ignore.txt"
ADVISORY_DB_URL="https://github.com/rustsec/advisory-db.git"

if [[ ! -f "$LOCK" ]]; then
    echo "ERROR: $LOCK not found (run from a resolved warrenguard workspace)" >&2
    exit 2
fi

DB_DIR="$(mktemp -d -t rustsec-advisory-db.XXXXXX)"
trap 'rm -rf "$DB_DIR"' EXIT INT TERM

echo "==> Cloning rustsec/advisory-db (shallow) into $DB_DIR"
git clone --quiet --depth 1 "$ADVISORY_DB_URL" "$DB_DIR"

DB_DIR="$DB_DIR" LOCK="$LOCK" IGNORE_FILE="$IGNORE_FILE" python3 - <<'PYEOF'
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

# Fork package name in Cargo.lock -> upstream crate name in the advisory DB.
FORK_TO_UPSTREAM = {
    "warren-quinn": "quinn",
    "warren-quinn-proto": "quinn-proto",
    "warren-quinn-udp": "quinn-udp",
}


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
    IGNORED = set(re.findall(r"RUSTSEC-\d{4}-\d{4}", IGNORE_FILE.read_text()))

failures = []
checked = 0
for crate, base_str in crates.items():
    base = parse_version(base_str)
    crate_dir = DB / "crates" / crate
    if not crate_dir.is_dir():
        continue
    for adv_path in sorted(crate_dir.glob("RUSTSEC-*.md")):
        adv_id = adv_path.stem
        checked += 1
        if adv_id in IGNORED:
            print(f"IGNORED {adv_id} ({crate}) per quinn-advisories-ignore.txt")
            continue
        try:
            meta = front_matter(adv_path.read_text())
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

print(f"==> {checked} advisories checked across {', '.join(crates)}")
if failures:
    print("", file=sys.stderr)
    print("ERROR: quinn fork advisory watch failed:", file=sys.stderr)
    for f in failures:
        print(f"  - {f}", file=sys.stderr)
    print(
        "\nAction: rebase the fork on a patched upstream base and push a new "
        "warren-quinn tag (bump the tag in the root Cargo.toml), or document an "
        "accepted risk in scripts/quinn-advisories-ignore.txt.",
        file=sys.stderr,
    )
    sys.exit(1)
print("==> quinn fork advisory watch: all clear")
PYEOF
