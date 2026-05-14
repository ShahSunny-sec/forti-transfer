#!/usr/bin/env bash
# Generate a 4 GB test file filled with zeros.
# Zeros are used because they are faster to generate than random bytes
# and still produce a valid, consistent SHA-256 for verification.
set -euo pipefail

OUT="${1:-test_4gb.bin}"
SIZE_GIB="${2:-4}"
SIZE_BYTES=$(( SIZE_GIB * 1024 * 1024 * 1024 ))

if command -v python3 &>/dev/null; then
    echo "Creating ${SIZE_GIB} GiB sparse file: ${OUT}"
    python3 -c "
with open('${OUT}', 'wb') as f:
    f.truncate(${SIZE_BYTES})
"
elif command -v dd &>/dev/null; then
    echo "Creating ${SIZE_GIB} GiB file with dd: ${OUT}"
    dd if=/dev/zero of="${OUT}" bs=1M count=$(( SIZE_GIB * 1024 )) status=progress
else
    echo "ERROR: neither python3 nor dd found." >&2
    exit 1
fi

echo "Done. File size: $(du -h "${OUT}" | cut -f1)"
