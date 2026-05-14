"""Streaming SHA-256 — never loads the entire file into memory."""
import hashlib

CHUNK_SIZE = 1024 * 1024  # 1 MiB


def sha256_file(path: str) -> str:
    """Return the lowercase hex SHA-256 digest of the file at *path*."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            block = f.read(CHUNK_SIZE)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def new_hasher():
    """Return a fresh hashlib SHA-256 object for incremental hashing."""
    return hashlib.sha256()
