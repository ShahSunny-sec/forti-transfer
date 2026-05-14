"""
Approach B: Application-Layer Encrypted Envelope — Sender

Transfers a file over plain TCP using a per-session application-layer
security envelope:

  Key exchange  : X25519 ephemeral ECDH  →  forward secrecy
  Authentication: Ed25519 signatures over handshake messages
  KDF           : HKDF-SHA256 to derive ChaCha20-Poly1305 session key
  AEAD          : ChaCha20-Poly1305 per 1 MiB chunk
  Integrity     : AEAD tag per chunk + SHA-256 plaintext hash in manifest
  Binding       : chunk_number, offset, session_id in AEAD associated data

Usage:
    python approach-b-envelope/sender.py \\
        --host 127.0.0.1 --port 9443 \\
        --sender-private-key approach-b-envelope/keys/sender_ed25519_private.key \\
        --receiver-public-key approach-b-envelope/keys/receiver_ed25519_public.key \\
        --file test_4gb.bin

Optional flag for demonstrating failure:
    --tamper-chunk N    Corrupt chunk N before sending (AEAD will reject it)
"""
import argparse
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
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
from common.hash_file import sha256_file, CHUNK_SIZE

# Wire constants
NONCE_SIZE  = 12
TAG_SIZE    = 16
CHUNK_TYPE  = 0x01
MANIFEST_TYPE = 0x02
# Chunk frame layout after the 4-byte framing length:
#   type(1) chunk_num(8) offset(8) plaintext_len(4) nonce(12) ciphertext(plaintext_len+16)
_CHUNK_HDR = struct.Struct(">BQQI")


# ── Key helpers ────────────────────────────────────────────────────────────────

def _load_ed25519_private(path: str) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def _load_ed25519_public(path: str) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(Path(path).read_bytes())


def _x25519_pub_raw(priv: X25519PrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def _ed25519_pub_raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
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
    sender_priv: Ed25519PrivateKey,
    receiver_pub: Ed25519PublicKey,
):
    """
    3-message authenticated ECDH:
      Receiver → Sender : receiver_hello   (recv_eph_pub + Ed25519 sig)
      Sender   → Receiver: sender_hello    (send_eph_pub + session_id + Ed25519 sig)
      Receiver → Sender : receiver_ready  (Ed25519 sig over session_id)

    Returns (session_id: bytes, session_key: bytes).
    """
    # Step 1 — receive receiver_hello
    hello = json.loads(recv_frame(sock))
    if hello.get("type") != "receiver_hello":
        raise ValueError(f"Expected receiver_hello, got: {hello.get('type')}")

    recv_eph_pub_raw = bytes.fromhex(hello["ephemeral_pubkey"])
    recv_sig = bytes.fromhex(hello["signature"])

    try:
        receiver_pub.verify(recv_sig, b"RECV_HELLO:" + recv_eph_pub_raw)
    except InvalidSignature:
        raise ValueError("[SECURITY] Receiver handshake signature invalid — aborting")
    print("[+] Receiver identity verified via Ed25519.")

    # Step 2 — generate our ephemeral key pair and send sender_hello
    send_eph_priv = X25519PrivateKey.generate()
    send_eph_pub_raw = _x25519_pub_raw(send_eph_priv)
    session_id = os.urandom(32)

    msg = b"SEND_HELLO:" + send_eph_pub_raw + recv_eph_pub_raw + session_id
    sig = sender_priv.sign(msg)

    our_hello = {
        "type": "sender_hello",
        "ephemeral_pubkey": send_eph_pub_raw.hex(),
        "session_id": session_id.hex(),
        "signature": sig.hex(),
    }
    send_frame(sock, json.dumps(our_hello).encode())
    print(f"[*] Session ID : {session_id.hex()[:16]}...")

    # Derive shared secret → session key
    recv_eph_pub = X25519PublicKey.from_public_bytes(recv_eph_pub_raw)
    shared_secret = send_eph_priv.exchange(recv_eph_pub)
    session_key = _derive_session_key(shared_secret, session_id)
    print("[*] Session key derived via X25519 + HKDF-SHA256.")

    # Step 3 — wait for receiver_ready
    ready = json.loads(recv_frame(sock))
    if ready.get("type") != "receiver_ready":
        raise ValueError(f"Expected receiver_ready, got: {ready.get('type')}")
    ready_sig = bytes.fromhex(ready["signature"])
    try:
        receiver_pub.verify(ready_sig, b"RECV_READY:" + session_id)
    except InvalidSignature:
        raise ValueError("[SECURITY] Receiver ready signature invalid — aborting")
    print("[+] Receiver ready — handshake complete.")

    return session_id, session_key


# ── Transfer ───────────────────────────────────────────────────────────────────

def run(args: argparse.Namespace) -> None:
    file_path = Path(args.file)
    if not file_path.exists():
        sys.exit(f"[ERROR] File not found: {args.file}")

    sender_priv  = _load_ed25519_private(args.sender_private_key)
    receiver_pub = _load_ed25519_public(args.receiver_public_key)

    file_size    = file_path.stat().st_size
    total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE

    print(f"[*] File         : {file_path.name}  ({file_size:,} bytes, {total_chunks} chunks)")
    print("[*] Computing SHA-256 of source file...")
    t0 = time.monotonic()
    file_hash = sha256_file(str(file_path))
    print(f"[*] SHA-256      : {file_hash}  ({time.monotonic() - t0:.2f}s)")

    print(f"[*] Connecting to {args.host}:{args.port} (plain TCP)...")
    with socket.create_connection((args.host, args.port), timeout=30) as sock:
        # Send metadata first so receiver knows what's coming before handshake
        meta = {
            "type": "metadata",
            "filename": file_path.name,
            "filesize": file_size,
            "sha256": file_hash,
            "chunk_size": CHUNK_SIZE,
            "total_chunks": total_chunks,
        }
        send_frame(sock, json.dumps(meta).encode())

        print("[*] Starting handshake...")
        session_id, session_key = do_handshake(sock, sender_priv, receiver_pub)
        aead = ChaCha20Poly1305(session_key)

        # ── Stream encrypted chunks ───────────────────────────────────────
        print("[*] Transferring encrypted chunks...")
        start        = time.monotonic()
        bytes_sent   = 0
        chunk_number = 0
        offset       = 0

        tamper_at = args.tamper_chunk  # None means no tampering

        with open(file_path, "rb") as f:
            while True:
                plaintext = f.read(CHUNK_SIZE)
                if not plaintext:
                    break

                is_final = (offset + len(plaintext)) >= file_size
                nonce    = _make_nonce(chunk_number)
                aad      = _make_aad(session_id, chunk_number, offset,
                                     len(plaintext), is_final)
                ciphertext = aead.encrypt(nonce, plaintext, aad)

                # Optional tampering for failure demonstration
                if tamper_at is not None and chunk_number == tamper_at:
                    print(f"\n[!] TAMPER MODE: flipping byte in chunk {chunk_number}")
                    ct_list = bytearray(ciphertext)
                    ct_list[0] ^= 0xFF
                    ciphertext = bytes(ct_list)

                frame = _CHUNK_HDR.pack(
                    CHUNK_TYPE, chunk_number, offset, len(plaintext)
                ) + nonce + ciphertext

                send_frame(sock, frame)
                bytes_sent   += len(plaintext)
                chunk_number += 1
                offset       += len(plaintext)

                elapsed = time.monotonic() - start
                pct = bytes_sent / file_size * 100
                mbs = bytes_sent / elapsed / 1_048_576 if elapsed else 0
                print(
                    f"\r    {pct:5.1f}%  chunk {chunk_number}/{total_chunks}"
                    f"  {mbs:.1f} MB/s",
                    end="",
                    flush=True,
                )

        print()

        # ── Send signed manifest ──────────────────────────────────────────
        manifest_obj = {
            "file_size": file_size,
            "total_chunks": total_chunks,
            "sha256": file_hash,
            "session_id": session_id.hex(),
        }
        manifest_bytes = json.dumps(manifest_obj, sort_keys=True).encode()
        manifest_sig   = sender_priv.sign(b"MANIFEST:" + manifest_bytes)

        # Manifest frame: type(1) manifest_len(4) manifest sig_len(2) sig
        manifest_frame = (
            struct.pack(">BI", MANIFEST_TYPE, len(manifest_bytes))
            + manifest_bytes
            + struct.pack(">H", len(manifest_sig))
            + manifest_sig
        )
        send_frame(sock, manifest_frame)

        # ── Wait for final ACK ────────────────────────────────────────────
        ack = json.loads(recv_frame(sock))
        elapsed = time.monotonic() - start
        mbs = file_size / elapsed / 1_048_576

        if ack.get("status") == "ok":
            print(f"[+] Transfer complete.")
            print(f"    Bytes transferred : {bytes_sent:,}")
            print(f"    SHA-256 verified  : {file_hash}")
            print(f"    Throughput        : {mbs:.1f} MB/s")
        else:
            sys.exit(f"[ERROR] Receiver: {ack.get('error', 'unknown')}")


def main() -> None:
    p = argparse.ArgumentParser(description="Approach B: encrypted envelope sender")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9443)
    p.add_argument("--sender-private-key",  required=True)
    p.add_argument("--receiver-public-key", required=True)
    p.add_argument("--file", required=True, help="Path to file to send")
    p.add_argument(
        "--tamper-chunk", type=int, default=None, metavar="N",
        help="Flip a byte in chunk N before sending (failure test)",
    )
    run(p.parse_args())


if __name__ == "__main__":
    main()
