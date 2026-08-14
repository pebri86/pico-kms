#!/usr/bin/env python3
"""Enroll production CSCA, DS and CVCA identities into the PicoHSM KMS.

Run against the running API server (scripts/run.sh). The script:

  1. Ensures the HSM key pairs exist (generates them if missing).
  2. Builds each certificate whose TBS is signed by the HSM private key
     (CSCA self-signed; DS and CVCA issued by the CSCA).
  3. Imports the certificates and registers the keys with role + binding.

Private keys never leave the HSM; a throwaway software key is used only
so `cryptography` can construct the TBSCertificate, and its signature is
discarded in favour of the HSM signature.

Idempotent: existing keys/certs/registrations are skipped.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from asn1crypto import core
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from app.config import settings
from app.hsm import hsm

API = f"http://{settings.kms_host}:{settings.kms_port}"
ADMIN = settings.pico_kms_admin_token

ENTITIES = [
    {
        "object_id": "CSCA-PRD-2026",
        "key_id": "CSCA-PRD-2026",
        "role": "CSCA",
        "label": "Republik Indonesia CSCA 2026",
        "cn": "Republik Indonesia CSCA 2026",
        "o": "Republik Indonesia",
        "c": "ID",
        "years": 10,
        "algorithm": "RSA",
        "bits": 3072,
        "is_ca": True,
        "key_usage": dict(
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
    },
    {
        "object_id": "DS-PRD-2026",
        "key_id": "DS-PRD-2026",
        "role": "DS",
        "label": "Kementerian Luar Negeri Republik Indonesia",
        "cn": "Kementerian Luar Negeri Republik Indonesia",
        "o": "Kementerian Luar Negeri Republik Indonesia",
        "c": "ID",
        "years": 2,
        "algorithm": "EC",
        "curve": "secp256r1",
        "is_ca": False,
        "key_usage": dict(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
    },
    {
        "object_id": "CVCA-PRD-2026",
        "key_id": "CVCA-PRD-2026",
        "role": "CVCA",
        "label": "Republik Indonesia CVCA 2026",
        "cn": "Republik Indonesia CVCA 2026",
        "o": "Republik Indonesia",
        "c": "ID",
        "years": 5,
        "algorithm": "EC",
        "curve": "secp256r1",
        "is_ca": True,
        "key_usage": dict(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
    },
]


def http(method: str, path: str, payload=None, timeout: int = 600):
    req = urllib.request.Request(
        API + path,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={
            "Authorization": "Bearer " + ADMIN,
            "Content-Type": "application/json",
        },
        method=method,
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def ensure_key(spec):
    try:
        return hsm.key(spec["object_id"])
    except KeyError:
        pass

    print(f"generating {spec['role']} {spec['algorithm']} key "
          f"({spec['object_id']})...")
    if spec["algorithm"] == "RSA":
        return http(
            "POST",
            "/v1/keys/generate/rsa",
            {
                "object_id": spec["object_id"],
                "label": spec["label"],
                "bits": spec["bits"],
            },
            timeout=1200,
        )
    return http(
        "POST",
        "/v1/keys/generate/ec",
        {
            "object_id": spec["object_id"],
            "label": spec["label"],
            "curve": spec["curve"],
        },
        timeout=600,
    )


def name_for(spec):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, spec["c"]),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, spec["o"]),
            x509.NameAttribute(NameOID.COMMON_NAME, spec["cn"]),
        ]
    )


def build_cert(
    spec,
    public_key_der,
    issuer_name,
    subject_name,
    signer_object_id,
):
    public_key = serialization.load_der_public_key(public_key_der)

    # Throwaway key: only used to let cryptography emit a compliant
    # TBSCertificate. Its signature is replaced by the HSM signature.
    dummy = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    dummy_cert = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(issuer_name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365 * spec["years"]))
        .add_extension(
            x509.BasicConstraints(
                ca=spec["is_ca"],
                path_length=0 if spec["is_ca"] else None,
            ),
            critical=True,
        )
        .add_extension(x509.KeyUsage(**spec["key_usage"]), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        .sign(private_key=dummy, algorithm=hashes.SHA256())
    )

    signature = hsm.sign(
        signer_object_id,
        "RSA-SHA256",
        dummy_cert.tbs_certificate_bytes,
    )

    asn1_cert = asn1_x509.Certificate.load(
        dummy_cert.public_bytes(serialization.Encoding.DER)
    )
    asn1_cert["signature_value"] = core.OctetBitString(signature)
    der = asn1_cert.dump()

    cert = x509.load_der_x509_certificate(der)
    signer_key = hsm.key(signer_object_id)["public_key"]
    signer_key.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
    return der


def import_cert(spec, der):
    try:
        http("GET", f"/v1/certificates/{spec['object_id']}")
        print(f"  cert {spec['object_id']} already on HSM, skipping import")
        return
    except Exception:
        pass

    pem = x509.load_der_x509_certificate(der).public_bytes(
        serialization.Encoding.PEM
    ).decode()
    print("  importing certificate:", http(
        "POST",
        "/v1/certificates/import",
        {"object_id": spec["object_id"], "label": spec["label"], "certificate": pem},
    ))


def register(spec):
    try:
        http("GET", f"/v1/keys/{spec['key_id']}")
        print(f"  key {spec['key_id']} already registered, skipping")
        return
    except Exception:
        pass

    print("  registering key:", http(
        "POST",
        "/v1/keys/register",
        {
            "key_id": spec["key_id"],
            "role": spec["role"],
            "object_id": spec["object_id"],
            "label": spec["label"],
            "certificate_id": spec["object_id"],
        },
    ))


def main():
    if not ADMIN:
        raise SystemExit("PICO_KMS_ADMIN_TOKEN is not configured")

    keys = {spec["object_id"]: ensure_key(spec) for spec in ENTITIES}
    csca_name = name_for(ENTITIES[0])

    for spec in ENTITIES:
        issuer = csca_name if spec["role"] != "CSCA" else name_for(spec)
        subject = name_for(spec)
        der = build_cert(
            spec,
            keys[spec["object_id"]]["public_key_der"],
            issuer,
            subject,
            signer_object_id=ENTITIES[0]["object_id"],
        )
        print(f"{spec['role']} certificate built and HSM-signed")
        import_cert(spec, der)
        register(spec)

    print("\nAll production CSCA/DS/CVCA enrolled.")


if __name__ == "__main__":
    main()
