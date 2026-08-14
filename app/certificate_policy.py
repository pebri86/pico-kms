from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from .clock import system_clock, Clock


class CertificatePolicyError(ValueError):
    """Raised when a certificate fails role-specific validation."""


class CertificatePolicy:
    """Explicit role-based certificate validation layer.

    Imported certificates are parsed, validated, then stored and bound.
    An invalid certificate must never become a trusted registered one.
    """

    def __init__(
        self,
        clock: Clock = system_clock,
    ):
        self.clock = clock

    def validate(
        self,
        certificate,
        *,
        role: str,
        public_key_der: bytes | None = None,
    ):
        if role not in ("CSCA", "DS", "CVCA"):
            raise CertificatePolicyError(f"unsupported role: {role}")

        self._validate_validity(certificate)
        self._validate_algorithm(certificate)

        if role == "CSCA":
            self._validate_csca(certificate)
        elif role == "DS":
            self._validate_ds(certificate)
        elif role == "CVCA":
            self._validate_cvca(certificate)

        if public_key_der is not None:
            self._validate_public_key_match(certificate, public_key_der)

        return certificate

    def _validate_validity(self, certificate):
        now = self.clock.now()

        if now < certificate.not_valid_before_utc:
            raise CertificatePolicyError("certificate is not yet valid")

        if now > certificate.not_valid_after_utc:
            raise CertificatePolicyError("certificate has expired")

    def _validate_algorithm(self, certificate):
        public_key = certificate.public_key()

        if not isinstance(
            public_key,
            (ec.EllipticCurvePublicKey, rsa.RSAPublicKey),
        ):
            raise CertificatePolicyError(
                "unsupported certificate public key type"
            )

    def _validate_public_key_match(
        self,
        certificate,
        public_key_der: bytes,
    ):
        cert_public_der = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        if public_key_der != cert_public_der:
            raise CertificatePolicyError(
                "certificate public key does not match HSM key"
            )

    def _validate_csca(self, certificate):
        if certificate.subject != certificate.issuer:
            raise CertificatePolicyError("CSCA certificate must be self-issued")

        public_key = certificate.public_key()

        try:
            if isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    ec.ECDSA(certificate.signature_hash_algorithm),
                )

            elif isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    certificate.signature_hash_algorithm,
                )

        except ValueError:
            raise
        except Exception as e:
            raise CertificatePolicyError(
                "CSCA certificate signature verification failed"
            ) from e

        try:
            basic_constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound:
            raise CertificatePolicyError(
                "CSCA certificate missing BasicConstraints"
            )

        if not basic_constraints.ca:
            raise CertificatePolicyError(
                "CSCA certificate must have CA=TRUE"
            )

        if basic_constraints.path_length != 0:
            raise CertificatePolicyError(
                "CSCA certificate must have pathLenConstraint=0"
            )

        try:
            key_usage = certificate.extensions.get_extension_for_class(
                x509.KeyUsage
            ).value
        except x509.ExtensionNotFound:
            raise CertificatePolicyError("CSCA certificate missing KeyUsage")

        if not key_usage.key_cert_sign:
            raise CertificatePolicyError(
                "CSCA certificate must allow keyCertSign"
            )

        if not key_usage.crl_sign:
            raise CertificatePolicyError("CSCA certificate must allow cRLSign")

    def _validate_ds(self, certificate):
        self._reject_ca_certificate(certificate, "DS")
        self._require_key_usage(
            certificate,
            "DS",
            lambda key_usage: key_usage.digital_signature,
            "digitalSignature",
        )

    def _validate_cvca(self, certificate):
        self._require_ca_certificate(certificate, "CVCA")
        self._require_key_usage(
            certificate,
            "CVCA",
            lambda key_usage: key_usage.key_cert_sign,
            "keyCertSign",
        )

    def _reject_ca_certificate(self, certificate, role: str):
        try:
            basic_constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound:
            return

        if basic_constraints.ca:
            raise CertificatePolicyError(
                f"{role} certificate must not be a CA"
            )

    def _require_ca_certificate(self, certificate, role: str):
        try:
            basic_constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound:
            raise CertificatePolicyError(
                f"{role} certificate missing BasicConstraints"
            )

        if not basic_constraints.ca:
            raise CertificatePolicyError(
                f"{role} certificate must have CA=TRUE"
            )

    def _require_key_usage(self, certificate, role: str, check, flag: str):
        try:
            key_usage = certificate.extensions.get_extension_for_class(
                x509.KeyUsage
            ).value
        except x509.ExtensionNotFound:
            return

        if not check(key_usage):
            raise CertificatePolicyError(
                f"{role} certificate must allow {flag}"
            )
