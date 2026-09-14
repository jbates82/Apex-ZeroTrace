#!/bin/bash
# Stamps the workspace version into every document that carries one.
#
# Written because this went wrong three times. Each release used a `sed`
# pattern naming the version it expected to find, so the moment one bump was
# missed, every later bump silently missed too. The README sat at 0.13.0 for
# five releases; both manuals sat there for six.
#
# The fix is to derive the version rather than name it.
#
#   scripts/stamp-version.sh           update every document
#   scripts/stamp-version.sh --check   fail if any document has drifted
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2)
if [ -z "$VERSION" ]; then
    echo "could not read the version from Cargo.toml" >&2
    exit 1
fi

FILES="README.md TESTING.md docs/ABOUT-ZEROTRACE.txt docs/FORENSIC-TEST.txt
       docs/manuals/GUI-MANUAL.txt docs/manuals/CLI-MANUAL.txt
       SECURITY.md THREAT_MODEL.md ARCHITECTURE.md VAULT_FORMAT.md
       DESTRUCTION_MODEL.md SPLIT_KEY.md REMOTE_CUSTODY.md"

# Every phrase in the documentation that is followed by a version number.
LABELS='(Applies to version |End of manual\. Version |\*\*Version |Version |tests pass as of v)'

if [ "${1:-}" = "--check" ]; then
    fail=0
    for f in $FILES; do
        [ -e "$f" ] || continue
        # Anything matching a label but not carrying the current version.
        while IFS= read -r found; do
            case "$found" in
                *"$VERSION"*) ;;
                *) echo "STALE in $f: $found"; fail=1 ;;
            esac
        done < <(grep -hoE "${LABELS}v?[0-9]+\.[0-9]+\.[0-9]+" "$f" || true)
    done
    if [ "$fail" = "1" ]; then
        echo
        echo "Run scripts/stamp-version.sh to fix."
        exit 1
    fi
    echo "All documentation is stamped $VERSION."
    exit 0
fi

for f in $FILES; do
    [ -e "$f" ] || continue
    sed -i -E "s/(Applies to version )[0-9]+\.[0-9]+\.[0-9]+/\1$VERSION/g;
               s/(End of manual\. Version )[0-9]+\.[0-9]+\.[0-9]+/\1$VERSION/g;
               s/(\*\*Version )[0-9]+\.[0-9]+\.[0-9]+/\1$VERSION/g;
               s/(^Version )[0-9]+\.[0-9]+\.[0-9]+/\1$VERSION/g;
               s/(tests pass as of v)[0-9]+\.[0-9]+\.[0-9]+/\1$VERSION/g" "$f"
done
echo "Stamped documentation to $VERSION."
