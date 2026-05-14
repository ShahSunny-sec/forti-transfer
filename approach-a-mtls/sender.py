"""
Approach A: Mutual TLS File Sender

Establishes a mutually-authenticated TLS connection to the receiver, sends
file metadata, then streams the file in 1 MiB chunks.  Security entirely
provided by TLS: encryption, per-record integrity, and mutual X.509
certificate authentication.

Usage:
    python approach-a-mtls/sender.py \\
        --host 127.0.0.1 --port 8443 \\
        --cert approach-a-mtls/certs/sender-cert.pem \\
        --key  approach-a-mtls/certs/sender-key.pem \\
        --ca   approach-a-mtls/certs/ca.pem \\
        --file test_4gb.bin
"""
import argparse
import json
import os
import socket
import ssl
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from common.framing import send_frame, recv_frame
from common.hash_file import sha256_file, CHUNK_SIZE


def build_ssl_context(cert: str, key: str, ca: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Connecting by IP; disable hostname checking but still require a valid cert
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)   # our identity
    ctx.load_verify_locations(ca)    # trust anchor for receiver cert
    return ctx


def run(args: argparse.Namespace) -> None:
    file_path = Path(args.file)
    if not file_path.exists():
        sys.exit(f"[ERROR] File not found: {args.file}")

    file_size = file_path.stat().st_size
    print(f"[*] File      : {file_path.name}  ({file_size:,} bytes)")
    print("[*] Computing SHA-256 of source file...")
    t0 = time.monotonic()
    file_hash = sha256_file(str(file_path))
    print(f"[*] SHA-256   : {file_hash}  ({time.monotonic() - t0:.2f}s)")

    ctx = build_ssl_context(args.cert, args.key, args.ca)
    print(f"[*] Connecting to {args.host}:{args.port} ...")

    with socket.create_connection((args.host, args.port), timeout=30) as raw_sock:
        with ctx.wrap_socket(raw_sock, server_hostname=args.host) as tls:
            cipher, proto, bits = tls.cipher()
            peer = tls.getpeercert()
            peer_cn = dict(s for t in peer.get("subject", ()) for s in t).get("commonName", "?")
            print(f"[+] TLS established  proto={proto}  cipher={cipher}  bits={bits}")
            print(f"[+] Peer cert CN     : {peer_cn}")

            # --- Send metadata ---
            meta = {
                "filename": file_path.name,
                "filesize": file_size,
                "sha256": file_hash,
                "chunk_size": CHUNK_SIZE,
            }
            send_frame(tls, json.dumps(meta).encode())

            # --- Stream file in chunks ---
            start = time.monotonic()
            bytes_sent = 0

            with open(file_path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    # 4-byte length prefix + raw chunk bytes over the TLS stream
                    tls.sendall(len(chunk).to_bytes(4, "big") + chunk)
                    bytes_sent += len(chunk)
                    elapsed = time.monotonic() - start
                    pct = bytes_sent / file_size * 100
                    mbs = bytes_sent / elapsed / 1_048_576 if elapsed else 0
                    print(
                        f"\r    {pct:5.1f}%  {bytes_sent:,}/{file_size:,} bytes"
                        f"  {mbs:.1f} MB/s",
                        end="",
                        flush=True,
                    )

            print()

            # --- Wait for receiver acknowledgement ---
            ack = json.loads(recv_frame(tls))
            elapsed = time.monotonic() - start
            mbs = file_size / elapsed / 1_048_576

            if ack.get("status") == "ok":
                print(f"\n[+] Transfer complete.")
                print(f"    Bytes transferred : {bytes_sent:,}")
                print(f"    SHA-256 verified  : {file_hash}")
                print(f"    Throughput        : {mbs:.1f} MB/s")
            else:
                sys.exit(f"\n[ERROR] Receiver reported: {ack.get('error', 'unknown')}")


def main() -> None:
    p = argparse.ArgumentParser(description="Approach A: mTLS file sender")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--cert", required=True, help="Sender TLS certificate (PEM)")
    p.add_argument("--key",  required=True, help="Sender TLS private key (PEM)")
    p.add_argument("--ca",   required=True, help="CA certificate to verify receiver (PEM)")
    p.add_argument("--file", required=True, help="Path to file to send")
    run(p.parse_args())


if __name__ == "__main__":
    main()
