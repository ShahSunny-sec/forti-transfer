"""
Approach B: Application-Layer Encrypted Envelope — Receiver

Accepts a plain TCP connection, performs an authenticated ECDH handshake,
decrypts and authenticates every chunk individually, verifies the signed
manifest, checks the final SHA-256, and only then commits the output file.

Security properties enforced here (not by TLS):
  - Chunk authenticity  : AEAD tag per chunk
  - Chunk ordering      : chunk_number & offset in authenticated AAD
  - Session binding     : session_id in AAD prevents cross-session replay
  - Identity            : Ed25519 signatures over handshake and manifest
  - File integrity      : SHA-256 plaintext hash in signed manifest

Usage:
    python approach-b-envelope/receiver.py \\
        --host 127.0.0.1 --port 9443 \\
        --receiver-private-key approach-b-envelope/keys/receiver_ed25519_private.key \\
        --sender-public-key    approach-b-envelope/keys/sender_ed25519_public.key \\
        --out received_envelope.bin
"""
import argparse
import hashlib
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

sys.path.insert(0, str(Path(__file__).parent.parent))
from common.framing import send_frame, recv_frame
from common.hash_file import CHUNK_SIZE

NONCE_SIZE    = 12
TAG_SIZE      = 16
CHUNK_TYPE    = 0x01
MANIFEST_TYPE = 0x02
_CHUNK_HDR    = struct.Struct(">BQQI")  # type(1) chunk_num(8) offset(8) plen(4)


# ── Key helpers ────────────────────────────────────────────────────────────────

def _load_ed25519_private(path: str) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def _load_ed25519_public(path: str) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(Path(path).read_bytes())


def _x25519_pub_raw(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _derive_session_key(shared_secret: bytes, session_id: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=session_id,
        info=b"secure-transfer-chacha20-session-key-v1",
    ).derive(shared_secret)


def _make_nonce(chunk_number: int) -> bytes:
    return chunk_number.to_bytes(NONCE_SIZE, "big")


def _make_aad(
    session_id: bytes,
    chunk_number: int,
    offset: int,
    plaintext_len: int,
    is_final: bool,
) -> bytes:
    return session_id + struct.pack(">QQI?", chunk_number, offset, plaintext_len, is_final)


# ── Handshake ──────────────────────────────────────────────────────────────────

def do_handshake(
    sock,
    receiver_priv: Ed25519PrivateKey,
    sender_pub: Ed25519PublicKey,
):
    """
    Mirror of sender.do_handshake.  Returns (session_id, session_key).
    """
    # Step 1 — generate ephemeral key pair and send receiver_hello
    recv_eph_priv    = X25519PrivateKey.generate()
    recv_eph_pub_raw = _x25519_pub_raw(recv_eph_priv)

    sig = receiver_priv.sign(b"RECV_HELLO:" + recv_eph_pub_raw)
    hello = {
        "type": "receiver_hello",
        "ephemeral_pubkey": recv_eph_pub_raw.hex(),
        "signature": sig.hex(),
    }
    send_frame(sock, json.dumps(hello).encode())
    print("[*] Sent receiver_hello.")

    # Step 2 — receive sender_hello
    sender_hello = json.loads(recv_frame(sock))
    if sender_hello.get("type") != "sender_hello":
        raise ValueError(f"Expected sender_hello, got: {sender_hello.get('type')}")

    send_eph_pub_raw = bytes.fromhex(sender_hello["ephemeral_pubkey"])
    session_id       = bytes.fromhex(sender_hello["session_id"])
    sender_sig       = bytes.fromhex(sender_hello["signature"])

    # Verify sender's identity signature
    msg = b"SEND_HELLO:" + send_eph_pub_raw + recv_eph_pub_raw + session_id
    try:
        sender_pub.verify(sender_sig, msg)
    except InvalidSignature:
        raise ValueError("[SECURITY] Sender handshake signature invalid — aborting")
    print("[+] Sender identity verified via Ed25519.")

    # Derive shared secret → session key
    send_eph_pub  = X25519PublicKey.from_public_bytes(send_eph_pub_raw)
    shared_secret = recv_eph_priv.exchange(send_eph_pub)
    session_key   = _derive_session_key(shared_secret, session_id)
    print(f"[*] Session ID : {session_id.hex()[:16]}...")
    print("[*] Session key derived via X25519 + HKDF-SHA256.")

    # Step 3 — send receiver_ready
    ready_sig = receiver_priv.sign(b"RECV_READY:" + session_id)
    ready = {
        "type": "receiver_ready",
        "signature": ready_sig.hex(),
    }
    send_frame(sock, json.dumps(ready).encode())
    print("[+] Handshake complete.")

    return session_id, session_key


# ── Transfer ───────────────────────────────────────────────────────────────────

def handle_transfer(
    conn,
    receiver_priv: Ed25519PrivateKey,
    sender_pub: Ed25519PublicKey,
    out_path: str,
) -> None:
    # Receive metadata (sent before handshake)
    meta = json.loads(recv_frame(conn))
    if meta.get("type") != "metadata":
        raise ValueError("First frame must be metadata")

    filename     = meta["filename"]
    filesize     = meta["filesize"]
    expected_sha = meta["sha256"]
    total_chunks = meta["total_chunks"]

    print(f"[*] Filename         : {filename}")
    print(f"[*] File size        : {filesize:,} bytes  ({total_chunks} chunks)")
    print(f"[*] Expected SHA-256 : {expected_sha}")

    print("[*] Starting handshake...")
    session_id, session_key = do_handshake(conn, receiver_priv, sender_pub)
    aead = ChaCha20Poly1305(session_key)

    part_path   = out_path + ".part"
    failed_path = out_path + ".failed"
    h = hashlib.sha256()
    bytes_recv       = 0
    expected_chunk   = 0
    expected_offset  = 0
    start            = time.monotonic()

    try:
        with open(part_path, "wb") as f:
            while True:
                frame      = recv_frame(conn)
                frame_type = frame[0]

                # ── Encrypted chunk ────────────────────────────────────────
                if frame_type == CHUNK_TYPE:
                    hdr_size = _CHUNK_HDR.size  # 21 bytes
                    if len(frame) < hdr_size + NONCE_SIZE:
                        raise ValueError(f"Chunk frame too short ({len(frame)} bytes)")

                    _, chunk_number, offset, plaintext_len = _CHUNK_HDR.unpack(
                        frame[:hdr_size]
                    )
                    nonce      = frame[hdr_size : hdr_size + NONCE_SIZE]
                    ciphertext = frame[hdr_size + NONCE_SIZE :]

                    # Enforce ordering (prevents reorder / truncation attacks)
                    if chunk_number != expected_chunk:
                        raise ValueError(
                            f"Out-of-order chunk: expected {expected_chunk}, got {chunk_number}"
                        )
                    if offset != expected_offset:
                        raise ValueError(
                            f"Offset mismatch: expected {expected_offset}, got {offset}"
                        )

                    is_final = (offset + plaintext_len) >= filesize
                    aad      = _make_aad(session_id, chunk_number, offset,
                                         plaintext_len, is_final)

                    # Authenticate + decrypt — any modification raises InvalidTag
                    try:
                        plaintext = aead.decrypt(nonce, ciphertext, aad)
                    except InvalidTag:
                        raise ValueError(
                            f"[SECURITY] AEAD authentication FAILED for chunk "
                            f"{chunk_number} — data integrity compromised, aborting!"
                        )

                    if len(plaintext) != plaintext_len:
                        raise ValueError(
                            f"Plaintext length mismatch in chunk {chunk_number}"
                        )

                    # Only write to disk after successful authentication
                    f.write(plaintext)
                    h.update(plaintext)
                    bytes_recv      += len(plaintext)
                    expected_chunk  += 1
                    expected_offset += len(plaintext)

                    elapsed = time.monotonic() - start
                    pct = bytes_recv / filesize * 100
                    mbs = bytes_recv / elapsed / 1_048_576 if elapsed else 0
                    print(
                        f"\r    {pct:5.1f}%  chunk {expected_chunk}/{total_chunks}"
                        f"  {mbs:.1f} MB/s",
                        end="",
                        flush=True,
                    )

                # ── Manifest ───────────────────────────────────────────────
                elif frame_type == MANIFEST_TYPE:
                    print()
                    # Parse: type(1) manifest_len(4) manifest sig_len(2) sig
                    pos = 1
                    manifest_len = struct.unpack(">I", frame[pos : pos + 4])[0]
                    pos += 4
                    manifest_bytes = frame[pos : pos + manifest_len]
                    pos += manifest_len
                    sig_len = struct.unpack(">H", frame[pos : pos + 2])[0]
                    pos += 2
                    manifest_sig = frame[pos : pos + sig_len]

                    # Verify sender signed the manifest
                    try:
                        sender_pub.verify(manifest_sig, b"MANIFEST:" + manifest_bytes)
                    except InvalidSignature:
                        raise ValueError(
                            "[SECURITY] Manifest Ed25519 signature INVALID — aborting!"
                        )
                    print("[+] Manifest signature verified.")

                    manifest = json.loads(manifest_bytes)
                    if manifest["session_id"] != session_id.hex():
                        raise ValueError("[SECURITY] Manifest session_id mismatch!")
                    if manifest["total_chunks"] != total_chunks:
                        raise ValueError("Manifest chunk count mismatch!")
                    break

                else:
                    raise ValueError(f"Unknown frame type: {frame_type:#04x}")

        # ── Final hash verification ────────────────────────────────────────
        actual_sha = h.hexdigest()
        if actual_sha != expected_sha:
            os.rename(part_path, failed_path)
            send_frame(
                conn,
                json.dumps({"status": "error",
                            "error": f"SHA-256 mismatch: got {actual_sha}"}).encode(),
            )
            raise ValueError(
                f"[SECURITY] SHA-256 MISMATCH!\n"
                f"  Expected : {expected_sha}\n"
                f"  Got      : {actual_sha}\n"
                f"  Quarantined: {failed_path}"
            )

        # ── Commit ────────────────────────────────────────────────────────
        os.rename(part_path, out_path)
        elapsed = time.monotonic() - start
        mbs = filesize / elapsed / 1_048_576

        print(f"[+] SHA-256 verified : {actual_sha}")
        print(f"[+] File saved       : {out_path}")
        print(f"[+] Throughput       : {mbs:.1f} MB/s")

        send_frame(conn, json.dumps({"status": "ok"}).encode())

    except Exception:
        # Quarantine on any unexpected error
        if os.path.exists(part_path):
            os.rename(part_path, failed_path)
            print(f"[!] Partial file quarantined as {failed_path}", file=sys.stderr)
        raise


def main() -> None:
    p = argparse.ArgumentParser(description="Approach B: encrypted envelope receiver")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9443)
    p.add_argument("--receiver-private-key", required=True)
    p.add_argument("--sender-public-key",    required=True)
    p.add_argument("--out", default="received_envelope.bin", help="Output file path")
    args = p.parse_args()

    receiver_priv = _load_ed25519_private(args.receiver_private_key)
    sender_pub    = _load_ed25519_public(args.sender_public_key)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.host, args.port))
        srv.listen(1)
        print(f"[*] Listening on {args.host}:{args.port}  (plain TCP + application-layer encryption)")

        conn, addr = srv.accept()
        print(f"[*] Accepted connection from {addr}")

        with conn:
            try:
                handle_transfer(conn, receiver_priv, sender_pub, args.out)
            except Exception as exc:
                print(f"\n[ERROR] {exc}", file=sys.stderr)
                try:
                    send_frame(
                        conn,
                        json.dumps({"status": "error", "error": str(exc)}).encode(),
                    )
                except Exception:
                    pass
                sys.exit(1)


if __name__ == "__main__":
    main()
