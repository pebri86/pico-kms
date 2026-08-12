from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

from asn1crypto import x509 as asn1_x509
from asn1crypto import core

from app.hsm import hsm


OBJECT_ID = "TEST-EC-CSCA-02"
CERT_ID = "TEST-CSCA-EC-02-HSM"
OUTPUT = Path("test-csca-ec-02-hsm-selfsigned.der")


# ---------------------------------------------------------------------------
# 1. Get ONLY the public key from the HSM.
# ---------------------------------------------------------------------------

key_info = hsm.key(OBJECT_ID)

if key_info["algorithm"] != "EC":
    raise ValueError("expected EC HSM key")

if key_info["curve"] != "secp256r1":
    raise ValueError("expected secp256r1 HSM key")

public_key = serialization.load_der_public_key(
    key_info["public_key_der"]
)

if not isinstance(public_key, ec.EllipticCurvePublicKey):
    raise ValueError("HSM key is not an EC public key")


# ---------------------------------------------------------------------------
# 2. Build the certificate structure.
#
# We use an ephemeral EC private key ONLY so cryptography can construct
# a standards-compliant TBSCertificate.
#
# The ephemeral key is NOT the CSCA key and its signature is discarded.
# ---------------------------------------------------------------------------

dummy_signing_key = ec.generate_private_key(ec.SECP256R1())

name = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
        x509.NameAttribute(
            NameOID.ORGANIZATION_NAME,
            "PicoKMS Test CSCA",
        ),
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            CERT_ID,
        ),
    ]
)

now = datetime.now(timezone.utc)

builder = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(public_key)
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(minutes=1))
    .not_valid_after(now + timedelta(days=366))
    .add_extension(
        x509.BasicConstraints(
            ca=True,
            path_length=0,
        ),
        critical=True,
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False,
    )
)

dummy_cert = builder.sign(
    private_key=dummy_signing_key,
    algorithm=hashes.SHA256(),
)

tbs = dummy_cert.tbs_certificate_bytes


# ---------------------------------------------------------------------------
# 3. Sign the exact TBSCertificate using the HSM.
# ---------------------------------------------------------------------------

raw_signature = hsm.sign(
    OBJECT_ID,
    "ECDSA-SHA256",
    tbs,
)

if len(raw_signature) != 64:
    raise ValueError(
        f"expected 64-byte P-256 signature, got {len(raw_signature)}"
    )

r = int.from_bytes(raw_signature[:32], "big")
s = int.from_bytes(raw_signature[32:], "big")

der_signature = encode_dss_signature(r, s)


# ---------------------------------------------------------------------------
# 4. Replace the dummy certificate signature with the HSM signature.
# ---------------------------------------------------------------------------

asn1_cert = asn1_x509.Certificate.load(
    dummy_cert.public_bytes(serialization.Encoding.DER)
)


asn1_cert["signature_value"] = core.OctetBitString(
    der_signature
)

# The Certificate.signature_algorithm was already ECDSA-SHA256 because
# dummy_cert was signed with an EC P-256 key using SHA-256.

certificate_der = asn1_cert.dump()

OUTPUT.write_bytes(certificate_der)

print("Created:", OUTPUT)
print("OBJECT:", OBJECT_ID)
print("PUBLIC KEY SOURCE: HSM")
print("PRIVATE KEY EXPORTED: NO")
print("TBS LENGTH:", len(tbs))
print("RAW SIGNATURE LENGTH:", len(raw_signature))
print("DER SIGNATURE LENGTH:", len(der_signature))
print("CERTIFICATE LENGTH:", len(certificate_der))
