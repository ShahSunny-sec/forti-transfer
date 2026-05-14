"""Cross-platform test-file generator (Windows / macOS / Linux)."""
import sys

size_gib = int(sys.argv[1]) if len(sys.argv) > 1 else 4
out      = sys.argv[2] if len(sys.argv) > 2 else "test_4gb.bin"
size     = size_gib * 1024 * 1024 * 1024

print(f"Creating {size_gib} GiB sparse file: {out}")
with open(out, "wb") as f:
    f.truncate(size)
print(f"Done. ({size:,} bytes)")
