from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID


with open("test-ec-csca-02-public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

with open("test-ca-key.pem", "rb") as f:
    ca_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
    )

now = datetime.now(timezone.utc)

name_base = [
    x509.NameAttribute(NameOID.COUNTRY_NAME, "ID"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PicoKMS Negative Test"),
]


def build_cert(
    common_name,
    *,
    basic_constraints=True,
    ca=True,
    path_length=0,
    key_usage=True,
    digital_signature=True,
    key_cert_sign=True,
    crl_sign=True,
):
    name = x509.Name(
        name_base
        + [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    )

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=366))
    )

    if basic_constraints:
        builder = builder.add_extension(
            x509.BasicConstraints(
                ca=ca,
                path_length=path_length if ca else None,
            ),
            critical=True,
        )

    if key_usage:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=digital_signature,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=key_cert_sign,
                crl_sign=crl_sign,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False,
    )

    return builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
    )


tests = {
    "TEST-CSCA-NO-BC": dict(
        basic_constraints=False,
    ),
    "TEST-CSCA-CA-FALSE": dict(
        ca=False,
    ),
    "TEST-CSCA-NO-KU": dict(
        key_usage=False,
    ),
    "TEST-CSCA-NO-KEYCERTSIGN": dict(
        key_cert_sign=False,
    ),
    "TEST-CSCA-NO-CRLSIGN": dict(
        crl_sign=False,
    ),
}


for cert_id, options in tests.items():
    cert = build_cert(cert_id, **options)

    pem_path = Path(f"{cert_id}.pem")
    der_path = Path(f"{cert_id}.der")

    pem_path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )

    der_path.write_bytes(
        cert.public_bytes(serialization.Encoding.DER)
    )

    print(f"Created {pem_path}")
    print(f"Created {der_path}")
