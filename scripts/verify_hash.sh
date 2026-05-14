#!/usr/bin/env bash
# Verify that a received file matches the original by SHA-256.
# Usage: ./scripts/verify_hash.sh [original] [received]
set -euo pipefail

ORIGINAL="${1:-test_4gb.bin}"
RECEIVED="${2:-received_mtls.bin}"

for f in "$ORIGINAL" "$RECEIVED"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: file not found: $f" >&2
        exit 1
    fi
done

echo "Computing SHA-256..."
if command -v sha256sum &>/dev/null; then
    sha256sum "$ORIGINAL" "$RECEIVED"
elif command -v shasum &>/dev/null; then
    shasum -a 256 "$ORIGINAL" "$RECEIVED"
else
    python3 -c "
import hashlib, sys
for p in sys.argv[1:]:
    h = hashlib.sha256()
    with open(p,'rb') as f:
        while chunk := f.read(1048576):
            h.update(chunk)
    print(h.hexdigest(), p)
" "$ORIGINAL" "$RECEIVED"
fi

echo ""
echo "If the two hashes above match, the transfer is verified."
