python - <<'PY'
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

with open("test-ec-csca-02-public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

with open("test-ca-key.pem", "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None)

name = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PicoKMS Test CSCA"),
    x509.NameAttribute(NameOID.COMMON_NAME, "TEST-CSCA-EC-02"),
])

now = datetime.now(timezone.utc)

cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(public_key)
    .serial_number(x509.random_serial_number())
    .not_valid_before(now + timedelta(minutes=5))
    .not_valid_after(now + timedelta(days=366))
    .add_extension(
        x509.BasicConstraints(ca=True, path_length=0),
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
    .sign(ca_key, hashes.SHA256())
)

with open("test-csca-ec-02.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("Created test-csca-ec-02.pem")
PY