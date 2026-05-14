"""Cross-platform SHA-256 verification (Windows / macOS / Linux)."""
import hashlib
import sys

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1_048_576):
            h.update(chunk)
    return h.hexdigest()

files = sys.argv[1:] if len(sys.argv) > 1 else ["test_4gb.bin", "received_mtls.bin"]
hashes = {}
for p in files:
    print(f"Hashing {p} ...", flush=True)
    hashes[p] = sha256(p)
    print(f"  {hashes[p]}  {p}")

values = list(hashes.values())
if len(set(values)) == 1:
    print("\n[PASS] All hashes match.")
else:
    print("\n[FAIL] Hash mismatch!")
    sys.exit(1)
