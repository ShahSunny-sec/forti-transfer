# AI Usage Notes

I used Claude (claude-sonnet-4-6) to help design and build both transfer
implementations in this project.  This note describes what AI contributed,
where I had to intervene, and one case each where AI exceeded and fell short
of expectations.

## What AI helped plan

For **Approach A**, AI outlined the structure of the Python `ssl` module setup
for mutual TLS, including the correct combination of `ssl.PROTOCOL_TLS_CLIENT`,
`check_hostname=False`, and `verify_mode=ssl.CERT_REQUIRED` needed to verify
the peer certificate against a CA without relying on hostname matching.  It
also suggested using the `cryptography` library's `x509.CertificateBuilder` to
generate a local CA and leaf certificates entirely in Python rather than
shelling out to OpenSSL, which made the setup reproducible and cross-platform.

For **Approach B**, AI laid out the full handshake protocol: X25519 for
ephemeral key exchange, Ed25519 to sign handshake messages, HKDF-SHA256 to
derive the session key, and ChaCha20-Poly1305 to encrypt each chunk.  It
suggested including `session_id`, `chunk_number`, `offset`, `plaintext_len`,
and `is_final` as authenticated associated data (AAD) on each chunk, which I
kept because it directly prevents chunk reordering, truncation, and
cross-session replay.

AI also generated the initial structure for the binary chunk frame format
(`_CHUNK_HDR = struct.Struct(">BQQI")`), the manifest signing flow, and the
`.part` → `.failed` quarantine pattern for partial files.

## One insecure / wrong suggestion I caught

When drafting the AEAD nonce construction for Approach B, AI's first sketch
used `os.urandom(12)` (a random 12-byte nonce per chunk).  I rejected this
because a random nonce has a non-negligible birthday probability of collision
once the number of chunks exceeds roughly 2^32 — for a large file transferred
many times under the same session key this becomes a real risk.  Nonce reuse
under ChaCha20-Poly1305 completely breaks confidentiality and allows an
attacker to recover the plaintext XOR.

I replaced this with a deterministic nonce derived from the chunk number
(`chunk_number.to_bytes(12, "big")`).  Since the session key is fresh per
session (via ephemeral X25519 + HKDF), the nonce space resets with every
transfer, so `chunk_number` is always unique under any given key.  The chunk
number is also authenticated in the AAD, closing the door on splicing or
reordering.

## One thing AI did better than expected

Explaining and populating the threat model tables.  When I asked AI to map each
attack category to a CIAA property and describe which specific code mechanism
defeats it, the results were precise and directly tied to implementation
details — for example, citing `chunk_number` and `offset` in the AAD as the
specific mechanism that defeats chunk-reorder attacks.  This saved substantial
time compared to writing the threat model manually from scratch.

## One thing AI did worse than expected

Handling the receiver-side error paths for abrupt connection drops.  AI's
initial draft of the receiver would leave a `.part` file on disk after a
`ConnectionError` — there was no `try/finally` block to quarantine it.  The
code reached the `os.rename(.part → final)` only in the success path, but the
`ConnectionError` propagated up and the `.part` file was silently abandoned
without any cleanup or rename to `.failed`.  I had to add an explicit
`try/except` wrapper around the entire transfer loop that renames `.part` to
`.failed` on any exception, which also prevents a subsequent run from
accidentally picking up the stale partial file.

## Review statement

I read every line of crypto-relevant code before submitting — specifically the
SSL context construction, the X25519/HKDF key derivation, the nonce
construction, the AAD composition, and the AEAD encrypt/decrypt calls.  I
verified that:

- `verify_mode = ssl.CERT_REQUIRED` is set on **both** sides in Approach A.
- The HKDF `info` string in Approach B matches between sender and receiver
  (a mismatch would produce different session keys and all AEAD decryptions
  would fail).
- The AAD struct format (`">QQI?"`) is identical in both `sender.py` and
  `receiver.py`.
- The receiver only calls `f.write(plaintext)` **after** `aead.decrypt()`
  succeeds — it never writes unauthenticated data to disk.
