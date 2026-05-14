"""
Generate a local CA and leaf certificates for mTLS testing.

Run once before using Approach A:
    python approach-a-mtls/make_certs.py

Produces in approach-a-mtls/certs/:
    ca.pem              CA certificate (trusted by both sides)
    ca-key.pem          CA private key  (keep secret, not committed)
    sender-cert.pem     Sender TLS certificate
    sender-key.pem      Sender TLS private key
    receiver-cert.pem   Receiver TLS certificate
    receiver-key.pem    Receiver TLS private key
"""
import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERTS_DIR = Path(__file__).parent / "certs"
VALIDITY_DAYS = 3650


def _now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def _gen_rsa_key(bits: int = 2048):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def _save_pem_key(key, path: Path) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    print(f"  {path}")


def _save_pem_cert(cert, path: Path) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"  {path}")


def make_ca():
    key = _gen_rsa_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureTransfer-CA")])
    now = _now_utc()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_leaf(common_name: str, ca_key, ca_cert):
    key = _gen_rsa_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = _now_utc()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def main():
    CERTS_DIR.mkdir(exist_ok=True)

    print("Generating CA key and certificate...")
    ca_key, ca_cert = make_ca()
    _save_pem_key(ca_key, CERTS_DIR / "ca-key.pem")
    _save_pem_cert(ca_cert, CERTS_DIR / "ca.pem")

    print("Generating sender key and certificate...")
    sender_key, sender_cert = make_leaf("sender", ca_key, ca_cert)
    _save_pem_key(sender_key, CERTS_DIR / "sender-key.pem")
    _save_pem_cert(sender_cert, CERTS_DIR / "sender-cert.pem")

    print("Generating receiver key and certificate...")
    recv_key, recv_cert = make_leaf("receiver", ca_key, ca_cert)
    _save_pem_key(recv_key, CERTS_DIR / "receiver-key.pem")
    _save_pem_cert(recv_cert, CERTS_DIR / "receiver-cert.pem")

    print(f"\nAll certificates written to {CERTS_DIR}")
    print("Keep *-key.pem files secret — do not commit them.")


if __name__ == "__main__":
    main()
