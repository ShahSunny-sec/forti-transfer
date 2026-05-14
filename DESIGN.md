# Design

---

## Approach A: Mutual TLS Streaming

### Architecture

```
 SENDER                                    RECEIVER
 ──────                                    ────────
 load sender-cert.pem + sender-key.pem     load receiver-cert.pem + receiver-key.pem
 load ca.pem (trust anchor)                load ca.pem (trust anchor)
         │                                         │
         │  TCP SYN ──────────────────────────►    │
         │  TLS ClientHello ──────────────────►    │
         │  ◄──────────────────── TLS ServerHello  │
         │  ◄──────────── receiver-cert.pem (chain)│
         │  sender-cert.pem (chain) ──────────►    │
         │  ◄── both sides verify CA signature ─── │
         │  TLS Finished (mutual) ────────────►    │
         │                                         │
         │  [frame] JSON metadata ────────────►    │  parse filename, filesize, SHA-256
         │                                         │
         │  loop: 4-byte len + chunk ─────────►    │  write to received.bin.part
         │  ... (streaming, 1 MiB chunks) ...       │  update running SHA-256
         │                                         │
         │  ◄───────────────────────── [frame] ACK │  rename .part → received.bin
         │                                         │  (only if hash matches)
```

### Key management

- A local CA signs both the sender and receiver certificates.
- Neither endpoint is its own CA: all trust is rooted in the shared CA.
- Both sides configure `verify_mode = CERT_REQUIRED` and load the CA.
  - **Sender**: `ssl.PROTOCOL_TLS_CLIENT`, `check_hostname=False`,
    `verify_mode=CERT_REQUIRED`.
  - **Receiver**: `ssl.PROTOCOL_TLS_SERVER`, `verify_mode=CERT_REQUIRED`.
- Private keys (`*-key.pem`) are never transmitted and are excluded from the
  repository via `.gitignore`.
- For production: rotate certificates before expiry, use an HSM for the CA.

### Algorithms and parameters

| Parameter | Value |
|---|---|
| Transport | TCP |
| TLS minimum version | TLS 1.2 (TLS 1.3 preferred when available) |
| Sender/receiver auth | X.509 certificate, RSA-2048, signed by local CA |
| Encryption | TLS-negotiated AEAD (typically AES-256-GCM or ChaCha20-Poly1305) |
| File hash | SHA-256 (streamed, never full file in memory) |
| Chunk size | 1 MiB (1,048,576 bytes) |
| Output file pattern | `<name>.part` during transfer; renamed on success |
| Failure pattern | `<name>.failed` on hash mismatch or exception |

### Framing

```
 ┌─────────────────────────────────────────────┐
 │ Control messages (metadata, ACK)            │
 │  [4 bytes: payload length, big-endian]      │
 │  [N bytes: JSON payload]                    │
 └─────────────────────────────────────────────┘

 ┌─────────────────────────────────────────────┐
 │ File chunks (raw bytes over TLS stream)     │
 │  [4 bytes: chunk length, big-endian]        │
 │  [N bytes: plaintext file bytes]            │
 │  (TLS provides confidentiality + integrity) │
 └─────────────────────────────────────────────┘
```

The metadata frame carries: `filename`, `filesize`, `sha256`, `chunk_size`.
The receiver uses `filesize` to know when to stop reading and then re-verifies
the SHA-256 against the value sent inside the authenticated TLS session.

### CIAA analysis

| CIAA property | Mechanism | Where enforced |
|---|---|---|
| **Confidentiality** | TLS AEAD cipher suite encrypts every record | TLS layer |
| **Integrity** | TLS record MAC authenticates every record; final SHA-256 confirms file-level correctness | TLS layer + application |
| **Authenticity** | Mutual X.509: both sides verify the peer's certificate chain against the shared CA | TLS handshake |
| **Availability** | Chunked streaming (never full file in RAM); `.part` → `.failed` ensures no corrupt file is exposed; receiver can be restarted safely | Application layer |

### Threat model

| Threat | CIAA bucket | Response |
|---|---|---|
| Passive eavesdropper records TCP stream | Confidentiality | File bytes travel inside TLS records; an attacker observing the wire sees only encrypted ciphertext. |
| MITM modifies bytes in flight | Integrity | TLS record authentication detects any modification; the altered record is rejected before the application reads it. |
| Attacker presents a forged or wrong certificate | Authenticity | `verify_mode=CERT_REQUIRED` plus CA verification ensures only certs signed by the trusted CA are accepted; the handshake fails closed. |
| Replay of an earlier transfer session | Integrity / Authenticity | TLS generates fresh session keys per connection. The SHA-256 metadata is sent inside the authenticated TLS session and the receiver re-derives it from the arriving bytes. |
| Connection drops at 80% | Availability | Receiver writes only to `.part`; the final file is committed only after the SHA-256 matches. A dropped connection leaves only the quarantined `.part` file; restarting is safe. |
| Untrusted network relay / proxy | Confidentiality / Integrity | Any intermediary that terminates TLS must present a CA-signed certificate (which it cannot forge); end-to-end mTLS prevents transparent proxying. |
| Truncated transfer accepted as complete | Integrity | The receiver tracks `bytes_recv` vs `filesize` from metadata, and the final SHA-256 check catches any shortfall. |

---

## Approach B: Application-Layer Encrypted Envelope

### Architecture

```
 SENDER                                         RECEIVER
 ──────                                         ────────
 load sender Ed25519 private key                load receiver Ed25519 private key
 load receiver Ed25519 public key               load sender Ed25519 public key
         │                                              │
         │  TCP connect ────────────────────────►       │
         │                                              │
         │  [frame] METADATA (JSON) ───────────►        │  filename, filesize, sha256
         │                                              │
         │  ◄──── [frame] receiver_hello ────────       │  recv_eph_X25519_pub
         │                Ed25519_sig(recv_eph_pub)     │
         │                                              │
         │  [frame] sender_hello ──────────────►        │  send_eph_X25519_pub
         │          session_id                          │  verify Ed25519 sig
         │          Ed25519_sig(send_eph+recv_eph+sid)  │
         │                                              │
         │  ◄──── [frame] receiver_ready ────────       │  Ed25519_sig(session_id)
         │                                              │
         │  Both derive:                                │
         │  shared = X25519(my_eph_priv, their_eph_pub) │
         │  key    = HKDF-SHA256(shared, salt=session_id│
         │               info="…session-key-v1")        │
         │                                              │
         │  loop per 1 MiB chunk:                       │
         │  nonce  = chunk_number (12 bytes, BE)        │
         │  aad    = session_id ‖ chunk_num ‖ offset    │
         │           ‖ plaintext_len ‖ is_final         │
         │  ct     = ChaCha20-Poly1305(key, nonce,      │
         │               plaintext, aad)                │
         │  [frame] type=0x01 + header + nonce + ct ─► │  verify AEAD tag
         │                                              │  write to .part only on success
         │                                              │
         │  [frame] type=0x02 MANIFEST ──────────►      │  verify Ed25519 sig
         │          {sha256, total_chunks, session_id}  │  verify session_id
         │          Ed25519_sig("MANIFEST:"+json)       │  verify SHA-256
         │                                              │
         │  ◄──────────────────── [frame] ACK ────      │  rename .part → final
```

### Key management

- **Long-term identity keys (Ed25519)**: Each endpoint is provisioned with its
  own private Ed25519 signing key and the other endpoint's public Ed25519 key
  *before* the transfer.  These public keys are not secret but must be authentic
  (distributed out-of-band, e.g. via a configuration management system or
  pre-shared securely).  They are the root of trust for mutual identity.

- **Ephemeral session keys (X25519)**: Fresh X25519 key pairs are generated for
  every transfer.  The long-term Ed25519 keys sign the ephemeral public keys,
  binding identity to the session.  Compromise of the static Ed25519 keys does
  **not** expose past session content (forward secrecy from ephemeral ECDH).

- **Session key derivation**: `session_key = HKDF(shared_secret, salt=session_id,
  info="secure-transfer-chacha20-session-key-v1", length=32)`.  The random
  `session_id` chosen by the sender is included in the sender's signed hello,
  so it is authenticated.

- Private keys are excluded from the repository.

### Algorithms and parameters

| Parameter | Value |
|---|---|
| Transport | Plain TCP (no TLS) |
| Key exchange | X25519 ephemeral ECDH |
| Authentication | Ed25519 (long-term identity signatures) |
| KDF | HKDF-SHA256 |
| AEAD | ChaCha20-Poly1305 (32-byte key, 12-byte nonce, 16-byte tag) |
| Nonce construction | `chunk_number` as 12-byte big-endian integer (unique per chunk per session key) |
| Authenticated associated data | `session_id (32B) ‖ chunk_number (8B) ‖ offset (8B) ‖ plaintext_len (4B) ‖ is_final (1B)` |
| File hash | SHA-256 in signed manifest |
| Chunk size | 1 MiB (1,048,576 bytes) |

### Chunk frame layout

```
 ┌────────────────────────────────────────────────────────────────┐
 │ 4 bytes : frame length (big-endian, from framing.py)          │
 │ 1 byte  : type = 0x01 (CHUNK)                                  │
 │ 8 bytes : chunk_number (big-endian uint64)                     │
 │ 8 bytes : byte offset in file (big-endian uint64)              │
 │ 4 bytes : plaintext_len (big-endian uint32)                    │
 │12 bytes : nonce                                                │
 │ N bytes : ciphertext  (plaintext_len + 16 bytes for AEAD tag)  │
 └────────────────────────────────────────────────────────────────┘
```

Including `chunk_number` and `offset` in both the frame header and the
authenticated AAD means:
- A truncated stream is detected (expected chunk number increments monotonically).
- Reordered chunks are rejected (offset mismatch).
- Chunks from another session cannot be spliced in (session_id mismatch).
- The final-chunk flag prevents stream truncation without detection.

### CIAA analysis

| CIAA property | Mechanism | Where enforced |
|---|---|---|
| **Confidentiality** | ChaCha20-Poly1305 AEAD encrypts every chunk; the session key is only computable by the two endpoints who hold the Ed25519-authenticated X25519 ephemeral keys | Application layer |
| **Integrity** | AEAD tag authenticates each chunk individually; chunk_number, offset, and session_id are in the AAD preventing reorder/splice; final SHA-256 in signed manifest provides file-level integrity | Application layer |
| **Authenticity** | Ed25519 signatures over handshake messages and final manifest prove each endpoint holds the expected private key; the session_id is bound into signatures preventing cross-session replay | Application layer |
| **Availability** | Chunked streaming; AEAD failure aborts immediately; `.part` → rename only after all checks pass; `.failed` quarantine on error | Application layer |

### Threat model

| Threat | CIAA bucket | Response |
|---|---|---|
| Passive eavesdropper records TCP stream | Confidentiality | Every byte of file data travels inside ChaCha20-Poly1305 ciphertext. The session key is derived from a fresh X25519 exchange and is not present in the wire transcript. |
| MITM modifies a byte in a chunk | Integrity | The Poly1305 tag covers the entire ciphertext + AAD. A single flipped bit fails the tag check; `InvalidTag` is raised and the receiver aborts immediately. |
| Attacker replays a chunk from a previous session | Integrity / Authenticity | The session_id (random 32 bytes per session) is part of the AAD. A chunk encrypted under a different session_id/key produces an invalid tag. |
| Attacker reorders chunks within a session | Integrity | `chunk_number` and `offset` are in the AAD. If chunk 7 arrives where chunk 5 is expected, the ordering check fails before decryption is attempted. |
| Attacker spoofs sender or receiver identity | Authenticity | Both handshake messages are signed with Ed25519 private keys whose public keys are provisioned out-of-band. An attacker without the private key cannot produce a valid signature; verification fails and the session is torn down. |
| Attacker forges the manifest (claiming wrong hash) | Authenticity / Integrity | The manifest is signed with the sender's Ed25519 private key. Signature verification on the receiver rejects any unsigned or incorrectly signed manifest. |
| Connection drops at 80% | Availability | The receiver writes only verified plaintext (post-AEAD) to `.part`. No rename occurs until the manifest verifies and the SHA-256 matches. The `.part` file is quarantined as `.failed` on any exception. |
| Untrusted relay stores and re-injects traffic | Confidentiality / Integrity | The relay sees only ciphertext + AEAD tags. It cannot decrypt (no session key) and cannot modify any chunk or manifest without breaking the tag or signature. |

---

## Chunk size rationale

Both implementations use 1 MiB (1,048,576 byte) chunks because:

- **Memory**: a 4 GiB file becomes 4,096 chunks; at any moment only one chunk
  is held in RAM on each side.
- **Overhead**: at 1 MiB, per-chunk overhead (framing header + nonce + tag) is
  less than 0.003% of payload.
- **Progress granularity**: progress is updated every 1 MiB, giving
  sub-second feedback on a fast loopback transfer.
- **AEAD nonce space**: ChaCha20-Poly1305 requires nonce uniqueness per key.
  Using `chunk_number` as the nonce is safe as long as fewer than 2^96 chunks
  are sent under one key — for 1 MiB chunks that is 10^22 EiB, far beyond any
  practical file size.

## Why the two approaches are meaningfully different

| Dimension | Approach A | Approach B |
|---|---|---|
| Security layer | Transport (TLS handles everything) | Application (your code handles everything) |
| Cipher agility | TLS negotiates; depends on library/OS | Fixed: ChaCha20-Poly1305 |
| Authentication mechanism | PKI: CA-signed X.509 certificates | Pre-shared public keys: Ed25519 |
| Forward secrecy | TLS 1.3 (ephemeral key exchange inside TLS) | Explicit X25519 ephemeral + HKDF |
| Chunk-level auth | No — TLS stream auth only | Yes — AEAD tag per chunk |
| TCP dependency | Full TLS termination required | Plain TCP; security survives any TCP relay |
| Trust model | Both endpoints trust a common CA | Each endpoint trusts the other's public key directly |
