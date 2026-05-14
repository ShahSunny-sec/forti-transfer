# Secure File Transfer Assessment

Two meaningfully different implementations for securely transferring large files
(tested with 4 GiB) over an untrusted network, with full CIAA analysis.

| | Approach A | Approach B |
|---|---|---|
| **Name** | Mutual TLS streaming | App-layer encrypted envelope |
| **Where security lives** | Transport layer (TLS) | Application layer (your code) |
| **Key exchange** | TLS handshake | X25519 ephemeral ECDH |
| **Authentication** | X.509 mutual certificates | Ed25519 signatures |
| **Encryption** | TLS-negotiated AEAD | ChaCha20-Poly1305 per chunk |
| **Integrity** | TLS record MAC + SHA-256 | AEAD tag per chunk + SHA-256 |

---

## Requirements

- Python 3.10 or later
- `cryptography` library

## Install

```bash
python -m venv .venv

# Linux / macOS
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

---

## One-time setup

### Generate a 4 GiB test file

```bash
# Linux / macOS
bash scripts/make_test_file.sh

# Windows
python scripts/make_test_file.py
```

### Approach A — generate mTLS certificates

```bash
python approach-a-mtls/make_certs.py
```

Produces `approach-a-mtls/certs/`:  `ca.pem`, `sender-cert.pem`,
`sender-key.pem`, `receiver-cert.pem`, `receiver-key.pem`.

### Approach B — generate Ed25519 signing keys

```bash
python approach-b-envelope/make_keys.py
```

Produces `approach-b-envelope/keys/`:  four `.key` files (two private, two public).

---

## Running Approach A: Mutual TLS streaming

Open two terminals (start the receiver first):

**Terminal 1 — receiver**
```bash
python approach-a-mtls/receiver.py \
  --host 127.0.0.1 --port 8443 \
  --cert approach-a-mtls/certs/receiver-cert.pem \
  --key  approach-a-mtls/certs/receiver-key.pem \
  --ca   approach-a-mtls/certs/ca.pem \
  --out  received_mtls.bin
```

**Terminal 2 — sender**
```bash
python approach-a-mtls/sender.py \
  --host 127.0.0.1 --port 8443 \
  --cert approach-a-mtls/certs/sender-cert.pem \
  --key  approach-a-mtls/certs/sender-key.pem \
  --ca   approach-a-mtls/certs/ca.pem \
  --file test_4gb.bin
```

Expected output (sender):
```
[*] File      : test_4gb.bin  (4,294,967,296 bytes)
[*] Computing SHA-256 of source file...
[*] SHA-256   : <hash>  (3.41s)
[*] Connecting to 127.0.0.1:8443 ...
[+] TLS established  proto=TLSv1.3  cipher=TLS_AES_256_GCM_SHA384  bits=256
[+] Peer cert CN     : receiver
  100.0%  4,294,967,296/4,294,967,296 bytes  310.2 MB/s

[+] Transfer complete.
    Bytes transferred : 4,294,967,296
    SHA-256 verified  : <hash>
    Throughput        : 310.2 MB/s
```

---

## Running Approach B: Application-layer encrypted envelope

**Terminal 1 — receiver**
```bash
python approach-b-envelope/receiver.py \
  --host 127.0.0.1 --port 9443 \
  --receiver-private-key approach-b-envelope/keys/receiver_ed25519_private.key \
  --sender-public-key    approach-b-envelope/keys/sender_ed25519_public.key \
  --out received_envelope.bin
```

**Terminal 2 — sender**
```bash
python approach-b-envelope/sender.py \
  --host 127.0.0.1 --port 9443 \
  --sender-private-key  approach-b-envelope/keys/sender_ed25519_private.key \
  --receiver-public-key approach-b-envelope/keys/receiver_ed25519_public.key \
  --file test_4gb.bin
```

---

## Verify hashes

```bash
# Linux / macOS
bash scripts/verify_hash.sh test_4gb.bin received_mtls.bin
bash scripts/verify_hash.sh test_4gb.bin received_envelope.bin

# Windows
python scripts/verify_hash.py test_4gb.bin received_mtls.bin
python scripts/verify_hash.py test_4gb.bin received_envelope.bin
```

Both pairs must produce identical SHA-256 values.

---

## Failure / attack tests

### Test 1 — Wrong certificate (Approach A)

Run the sender using the receiver's cert instead of the sender's cert:

```bash
python approach-a-mtls/sender.py \
  --cert approach-a-mtls/certs/receiver-cert.pem \
  --key  approach-a-mtls/certs/receiver-key.pem \
  --ca   approach-a-mtls/certs/ca.pem \
  --host 127.0.0.1 --port 8443 --file test_4gb.bin
```

Expected: TLS handshake completes (cert is still CA-signed) but the CN will
be "receiver" instead of "sender".  To demonstrate strict CN pinning, run
the receiver with a CA that does not include the sender cert at all — generate
a second, independent CA and re-sign only one side.

Alternatively, use a self-signed cert not signed by the shared CA:

```bash
# one-liner: generate a rogue cert
python -c "
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509; from cryptography.x509.oid import NameOID
import datetime, pathlib
k = rsa.generate_private_key(65537, 2048)
n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'rogue')])
now = datetime.datetime.now(datetime.timezone.utc)
c = (x509.CertificateBuilder().subject_name(n).issuer_name(n)
     .public_key(k.public_key()).serial_number(x509.random_serial_number())
     .not_valid_before(now).not_valid_after(now+datetime.timedelta(days=1))
     .add_extension(x509.BasicConstraints(False,None),True)
     .sign(k,hashes.SHA256()))
pathlib.Path('rogue-cert.pem').write_bytes(c.public_bytes(serialization.Encoding.PEM))
pathlib.Path('rogue-key.pem').write_bytes(k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.TraditionalOpenSSL,serialization.NoEncryption()))
print('rogue cert written')
"
python approach-a-mtls/sender.py \
  --cert rogue-cert.pem --key rogue-key.pem \
  --ca   approach-a-mtls/certs/ca.pem \
  --host 127.0.0.1 --port 8443 --file test_4gb.bin
```

Expected result: **TLS handshake fails — `[SSL: CERTIFICATE_VERIFY_FAILED]`**.
No file is written.

---

### Test 2 — Wrong signing key (Approach B)

Generate a second receiver key pair and give the sender the wrong public key:

```bash
python -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
k = Ed25519PrivateKey.generate()
open('wrong_pub.key','wb').write(k.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
print('wrong_pub.key written')
"
python approach-b-envelope/sender.py \
  --sender-private-key  approach-b-envelope/keys/sender_ed25519_private.key \
  --receiver-public-key wrong_pub.key \
  --host 127.0.0.1 --port 9443 --file test_4gb.bin
```

Expected result: **Receiver handshake signature invalid — process exits**.
No file is written or committed.

---

### Test 3 — Connection drop at 80%

Start the receiver, start the sender, then kill the sender mid-transfer
(Ctrl-C or `kill`).

Expected result:
- Receiver raises `ConnectionError` and quarantines the partial write as
  `received_*.failed` (or `received_*.part` on abrupt kill).
- **No final output file** (`received_envelope.bin`) is created.
- Restarting both programs from scratch is safe.

---

### Test 4 — Tampered chunk (Approach B)

Use the built-in `--tamper-chunk` flag to flip a byte in chunk 5 before it is
sent:

```bash
python approach-b-envelope/sender.py \
  --sender-private-key  approach-b-envelope/keys/sender_ed25519_private.key \
  --receiver-public-key approach-b-envelope/keys/receiver_ed25519_public.key \
  --host 127.0.0.1 --port 9443 \
  --file test_4gb.bin \
  --tamper-chunk 5
```

Expected result: receiver prints
`[SECURITY] AEAD authentication FAILED for chunk 5 — data integrity compromised, aborting!`,
quarantines the partial file, and exits.  **No output file is committed.**

---

## Repository layout

```
secure-file-transfer-assessment/
├── README.md
├── DESIGN.md
├── AI_NOTES.md
├── requirements.txt
├── .gitignore
├── common/
│   ├── hash_file.py        streaming SHA-256 helper
│   └── framing.py          4-byte length-prefixed frame I/O
├── approach-a-mtls/
│   ├── make_certs.py       one-time cert generation
│   ├── sender.py
│   ├── receiver.py
│   └── certs/              (generated, not committed)
├── approach-b-envelope/
│   ├── make_keys.py        one-time key generation
│   ├── sender.py
│   ├── receiver.py
│   └── keys/               (generated, not committed)
└── scripts/
    ├── make_test_file.sh
    ├── make_test_file.py
    ├── verify_hash.sh
    └── verify_hash.py
```
