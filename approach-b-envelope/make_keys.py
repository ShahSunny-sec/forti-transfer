"""
Generate long-term Ed25519 signing key pairs for Approach B.

Run once before using Approach B:
    python approach-b-envelope/make_keys.py

Produces in approach-b-envelope/keys/:
    sender_ed25519_private.key    (keep secret — not committed)
    sender_ed25519_public.key     (distribute to receiver out-of-band)
    receiver_ed25519_private.key  (keep secret — not committed)
    receiver_ed25519_public.key   (distribute to sender out-of-band)

The public keys are not secret but must be authentic — they are the
out-of-band trust anchors for mutual identity verification.
"""
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

KEYS_DIR = Path(__file__).parent / "keys"


def gen_keypair(name: str) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()

    priv_path = KEYS_DIR / f"{name}_ed25519_private.key"
    pub_path  = KEYS_DIR / f"{name}_ed25519_public.key"

    priv_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub_path.write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    print(f"  {priv_path}")
    print(f"  {pub_path}")


def main() -> None:
    KEYS_DIR.mkdir(exist_ok=True)
    print("Generating sender Ed25519 key pair...")
    gen_keypair("sender")
    print("Generating receiver Ed25519 key pair...")
    gen_keypair("receiver")
    print(f"\nKeys written to {KEYS_DIR}")
    print("IMPORTANT: Keep *_private.key files secret — do not commit them.")


if __name__ == "__main__":
    main()
