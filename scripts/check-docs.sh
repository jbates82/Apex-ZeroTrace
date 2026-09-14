#!/bin/bash
# Checks that the documentation agrees with the binary.
#
# The capability table in README.md is a copy of what `zt security audit`
# prints. A copy drifts. This compares them and fails when they disagree,
# which is the difference between a table that is accurate and a table that
# was accurate once.
set -euo pipefail
cd "$(dirname "$0")/.."

ZT=target/release/zt
if [ ! -x "$ZT" ]; then
    echo "build first: cargo build --release" >&2
    exit 1
fi

fail=0

# Every capability the binary reports, as "name|assurance".
"$ZT" security audit | grep -E "^  [A-Z]" | sed -E 's/^  ([A-Za-z].*[^ ])  +([A-Z][A-Z ]*[A-Z])$/\1|\2/' \
    | grep '|' | sort > /tmp/zt-audit-actual.txt

# Every row of the README table.
grep -E '^\| [A-Za-z].*\|.*\|$' README.md \
    | sed -E 's/^\| (.*[^ ]) +\| (.*[^ ]) \|$/\1|\2/' \
    | grep -E '\|(VERIFIED|BEST EFFORT|NOT IMPLEMENTED|NOT SUPPORTED|ENFORCED)$' \
    | sort > /tmp/zt-audit-readme.txt

missing=$(comm -23 /tmp/zt-audit-actual.txt /tmp/zt-audit-readme.txt || true)
extra=$(comm -13 /tmp/zt-audit-actual.txt /tmp/zt-audit-readme.txt || true)

if [ -n "$missing" ]; then
    echo "The binary reports these, and README.md does not:"
    echo "$missing" | sed 's/^/  /'
    fail=1
fi
if [ -n "$extra" ]; then
    echo "README.md claims these, and the binary does not report them:"
    echo "$extra" | sed 's/^/  /'
    fail=1
fi

if [ "$fail" = "1" ]; then
    echo
    echo "A capability table that disagrees with the binary is worse than none."
    exit 1
fi
echo "README.md agrees with what the binary reports."
