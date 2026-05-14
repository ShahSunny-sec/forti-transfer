"""
Approach A: Mutual TLS File Receiver

Listens for a mutually-authenticated TLS connection, receives file metadata,
streams incoming bytes to a .part file while computing SHA-256 on the fly,
and renames to the final path only if the hash matches.  Any partial or
corrupt transfer is quarantined as .failed.

Usage:
    python approach-a-mtls/receiver.py \\
        --host 127.0.0.1 --port 8443 \\
        --cert approach-a-mtls/certs/receiver-cert.pem \\
        --key  approach-a-mtls/certs/receiver-key.pem \\
        --ca   approach-a-mtls/certs/ca.pem \\
        --out  received_mtls.bin
"""
import argparse
import hashlib
import json
import os
import socket
import ssl
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from common.framing import send_frame, recv_frame


def build_ssl_context(cert: str, key: str, ca: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)   # our identity
    ctx.load_verify_locations(ca)    # trust anchor for client cert
    ctx.verify_mode = ssl.CERT_REQUIRED  # require and validate sender certificate
    return ctx


def _recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            raise ConnectionError(f"Connection closed after {len(buf)}/{n} bytes")
        buf.extend(chunk)
    return bytes(buf)


def handle_transfer(tls_conn, out_path: str) -> None:
    # --- Receive metadata ---
    meta = json.loads(recv_frame(tls_conn))
    filename     = meta["filename"]
    filesize     = meta["filesize"]
    expected_sha = meta["sha256"]

    print(f"[*] Filename         : {filename}")
    print(f"[*] File size        : {filesize:,} bytes")
    print(f"[*] Expected SHA-256 : {expected_sha}")

    part_path   = out_path + ".part"
    failed_path = out_path + ".failed"
    h = hashlib.sha256()
    bytes_recv  = 0
    start       = time.monotonic()

    try:
        with open(part_path, "wb") as f:
            while bytes_recv < filesize:
                # 4-byte length prefix
                raw_len = _recv_exact(tls_conn, 4)
                chunk_len = int.from_bytes(raw_len, "big")
                if chunk_len == 0 or chunk_len > 16 * 1024 * 1024:
                    raise ValueError(f"Unexpected chunk length: {chunk_len}")

                chunk = _recv_exact(tls_conn, chunk_len)
                f.write(chunk)
                h.update(chunk)
                bytes_recv += len(chunk)

                elapsed = time.monotonic() - start
                pct = bytes_recv / filesize * 100
                mbs = bytes_recv / elapsed / 1_048_576 if elapsed else 0
                print(
                    f"\r    {pct:5.1f}%  {bytes_recv:,}/{filesize:,} bytes"
                    f"  {mbs:.1f} MB/s",
                    end="",
                    flush=True,
                )

        print()

        # --- Verify integrity ---
        actual_sha = h.hexdigest()
        if actual_sha != expected_sha:
            os.rename(part_path, failed_path)
            send_frame(
                tls_conn,
                json.dumps({"status": "error",
                            "error": f"SHA-256 mismatch: got {actual_sha}"}).encode(),
            )
            raise ValueError(
                f"[ERROR] Hash mismatch!\n"
                f"  Expected : {expected_sha}\n"
                f"  Got      : {actual_sha}\n"
                f"  Bad file quarantined as: {failed_path}"
            )

        # --- Commit final file ---
        os.rename(part_path, out_path)
        elapsed = time.monotonic() - start
        mbs = filesize / elapsed / 1_048_576

        print(f"[+] SHA-256 verified : {actual_sha}")
        print(f"[+] File saved       : {out_path}")
        print(f"[+] Throughput       : {mbs:.1f} MB/s")

        send_frame(tls_conn, json.dumps({"status": "ok"}).encode())

    except Exception:
        # Quarantine any partial output on unexpected error
        if os.path.exists(part_path):
            os.rename(part_path, failed_path)
            print(f"[!] Partial file quarantined as {failed_path}", file=sys.stderr)
        raise


def main() -> None:
    p = argparse.ArgumentParser(description="Approach A: mTLS file receiver")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8443)
    p.add_argument("--cert", required=True, help="Receiver TLS certificate (PEM)")
    p.add_argument("--key",  required=True, help="Receiver TLS private key (PEM)")
    p.add_argument("--ca",   required=True, help="CA certificate to verify sender (PEM)")
    p.add_argument("--out",  default="received_mtls.bin", help="Output file path")
    args = p.parse_args()

    ctx = build_ssl_context(args.cert, args.key, args.ca)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((args.host, args.port))
        srv.listen(1)
        print(f"[*] Listening on {args.host}:{args.port}  (mutual TLS required)")

        conn, addr = srv.accept()
        print(f"[*] Accepted connection from {addr}")

        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                cipher, proto, bits = tls.cipher()
                peer = tls.getpeercert()
                peer_cn = dict(s for t in peer.get("subject", ()) for s in t).get("commonName", "?")
                print(f"[+] TLS established  proto={proto}  cipher={cipher}  bits={bits}")
                print(f"[+] Client cert CN   : {peer_cn}")
                handle_transfer(tls, args.out)
        except ssl.SSLError as exc:
            print(f"[ERROR] TLS handshake failed: {exc}", file=sys.stderr)
            sys.exit(1)
        except Exception as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
