from __future__ import annotations

from .hsm import hsm
from .registry import Registry
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from .clock import system_clock, Clock
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding


class AuthorizationError(ValueError):
    """Raised when a registered key is not authorized for an operation."""


class RegistryService:
    ALLOWED_ALGORITHMS = {
        "RSA": frozenset(
            {
                "RSA-SHA256",
            }
        ),
        "EC": frozenset(
            {
                "ECDSA-SHA256",
            }
        ),
    }

    ALLOWED_OPERATIONS = {
        "CSCA": frozenset(
            {
                "CERTIFICATE_SIGN",
                "CRL_SIGN",
            }
        ),
        "DS": frozenset(
            {
                "DOCUMENT_SIGN",
            }
        ),
        "CVCA": frozenset(
            {
                "CV_CERTIFICATE_SIGN",
            }
        ),
    }

    def __init__(
        self,
        registry: Registry | None = None,
        clock: Clock = system_clock,
    ):
        self.registry = registry or Registry()
        self.clock = clock

    def validate_key(self, key_id: str):
        entry = self.registry.get_key(key_id)

        if entry is None:
            raise KeyError("key not registered")

        if entry["status"] != "ACTIVE":
            raise ValueError(f"key is not active: {entry['status']}")

        key = hsm.key(entry["object_id"])

        if key["algorithm"] != entry["algorithm"]:
            raise ValueError("registered algorithm does not match HSM key")

        if entry["algorithm"] == "RSA":
            if str(key["bits"]) != entry["key_parameters"]:
                raise ValueError("registered RSA size does not match HSM key")

        elif entry["algorithm"] == "EC":
            if key["curve"] != entry["key_parameters"]:
                raise ValueError("registered EC curve does not match HSM key")

        if not key["private_present"]:
            raise ValueError("registered HSM key has no private key")

        if entry["certificate_id"]:
            try:
                cert_der = hsm.cert(entry["certificate_id"])
            except KeyError:
                raise ValueError("registered certificate not found")

            certificate = x509.load_der_x509_certificate(cert_der)
            now = self.clock.now()

            if now < certificate.not_valid_before_utc:
                raise ValueError("certificate is not yet valid")

            if now > certificate.not_valid_after_utc:
                raise ValueError("certificate has expired")

            hsm_public_der = key["public_key_der"]

            cert_public_der = certificate.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            if hsm_public_der != cert_public_der:
                raise ValueError(
                    "registered certificate public key does not match HSM key"
                )

            if entry["role"] == "CSCA":
                self._validate_csca_certificate(certificate)
                self._verify_self_signed_certificate(certificate)
                try:
                    basic_constraints = certificate.extensions.get_extension_for_class(
                        x509.BasicConstraints
                    ).value
                except x509.ExtensionNotFound:
                    raise ValueError("CSCA certificate missing BasicConstraints")

                if not basic_constraints.ca:
                    raise ValueError("CSCA certificate must have CA=TRUE")

                if basic_constraints.path_length != 0:
                    raise ValueError("CSCA certificate must have pathLenConstraint=0")

                try:
                    key_usage = certificate.extensions.get_extension_for_class(
                        x509.KeyUsage
                    ).value
                except x509.ExtensionNotFound:
                    raise ValueError("CSCA certificate missing KeyUsage")

                if not key_usage.key_cert_sign:
                    raise ValueError("CSCA certificate must allow keyCertSign")

                if not key_usage.crl_sign:
                    raise ValueError("CSCA certificate must allow cRLSign")

        return entry

    def validate_object(self, object_id: str):
        entry = self.registry.get_key_by_object_id(object_id)

        if entry is None:
            raise KeyError("key not registered")

        return self.validate_key(entry["key_id"])

    def validate_signing_algorithm(self, entry: dict, algorithm: str):
        allowed = self.ALLOWED_ALGORITHMS.get(entry["algorithm"], set())

        if algorithm not in allowed:
            raise AuthorizationError(
                f"signing algorithm {algorithm} is not allowed "
                f"for {entry['algorithm']} key"
            )

    def validate_signing_key(
        self,
        object_id: str,
        algorithm: str,
        operation: str,
    ):
        entry = self.validate_object(object_id)
        self.validate_signing_algorithm(entry, algorithm)
        self.validate_operation(entry, operation)
        return entry

    def validate_operation(self, entry: dict, operation: str):
        allowed = self.ALLOWED_OPERATIONS.get(entry["role"], set())

        if operation not in allowed:
            raise AuthorizationError(
                f"operation {operation} is not allowed for " f"{entry['role']} key"
            )

    def _verify_self_signed_certificate(self, certificate):
        if certificate.subject != certificate.issuer:
            raise ValueError("CSCA certificate must be self-issued")

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

            else:
                raise ValueError("unsupported CSCA certificate public key type")

        except ValueError:
            raise
        except Exception as e:
            raise ValueError("CSCA certificate signature verification failed") from e

    def update_certificate(self, key_id: str, certificate_id: str):
        entry = self.registry.get_key(key_id)

        if entry is None:
            raise KeyError("key not registered")

        if entry["status"] != "ACTIVE":
            raise ValueError(f"key is not active: {entry['status']}")

        if not certificate_id:
            raise ValueError("certificate_id is required")

        # Resolve the HSM key associated with the registered identity.
        key = hsm.key(entry["object_id"])

        # Certificate must exist.
        try:
            cert_der = hsm.cert(certificate_id)
        except KeyError:
            raise ValueError("certificate not found")

        certificate = x509.load_der_x509_certificate(cert_der)

        # Certificate public key must remain cryptographically bound
        # to the registered HSM key.
        hsm_public_der = key["public_key_der"]

        cert_public_der = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        if hsm_public_der != cert_public_der:
            raise ValueError("certificate public key does not match HSM key")

        # Certificate must currently be valid.
        now = self.clock.now()

        if now < certificate.not_valid_before_utc:
            raise ValueError("certificate is not yet valid")

        if now > certificate.not_valid_after_utc:
            raise ValueError("certificate has expired")

        # CSCA certificates have additional policy requirements.
        if entry["role"] == "CSCA":
            self._validate_csca_certificate(certificate)

        # Only modify the registry after every validation succeeds.
        self.registry.update_certificate(
            key_id,
            certificate_id,
        )

    def get_key(self, key_id: str):
        return self.validate_key(key_id)

    def register_hsm_key(
        self,
        *,
        key_id: str,
        role: str,
        object_id: str,
        label: str,
        certificate_id: str | None = None,
    ):
        if role not in self.ALLOWED_OPERATIONS:
            raise ValueError("invalid role")

        if not key_id:
            raise ValueError("key_id is required")

        if not object_id:
            raise ValueError("object_id is required")

        if not label:
            raise ValueError("label is required")

        # Verify the HSM object first.
        key = hsm.key(object_id)

        if not key["private_present"]:
            raise ValueError("HSM object does not contain a private key")

        algorithm = key["algorithm"]

        if algorithm == "RSA":
            key_parameters = str(key["bits"])

        elif algorithm == "EC":
            key_parameters = key["curve"]

        else:
            raise ValueError(f"unsupported HSM key algorithm: {algorithm}")

        # If a certificate is supplied, verify that it exists and
        # is cryptographically bound to this HSM public key.
        if certificate_id:
            try:
                cert_der = hsm.cert(certificate_id)
            except KeyError:
                raise ValueError("certificate not found")

            certificate = x509.load_der_x509_certificate(cert_der)

            hsm_public_der = key["public_key_der"]

            cert_public_der = certificate.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            if hsm_public_der != cert_public_der:
                raise ValueError("certificate public key does not match HSM key")

            now = self.clock.now()

            if now < certificate.not_valid_before_utc:
                raise ValueError("certificate is not yet valid")

            if now > certificate.not_valid_after_utc:
                raise ValueError("certificate has expired")

        # CSCA has additional certificate requirements.
        if role == "CSCA":
            if not certificate_id:
                raise ValueError("CSCA registration requires certificate_id")

            self._validate_csca_certificate(certificate)

        self.registry.register_key(
            key_id=key_id,
            role=role,
            object_id=object_id,
            label=label,
            algorithm=algorithm,
            key_parameters=key_parameters,
            certificate_id=certificate_id,
            status="ACTIVE",
        )

        return self.registry.get_key(key_id)

    def _validate_csca_certificate(self, certificate):
        self._verify_self_signed_certificate(certificate)

        try:
            basic_constraints = certificate.extensions.get_extension_for_class(
                x509.BasicConstraints
            ).value
        except x509.ExtensionNotFound:
            raise ValueError("CSCA certificate missing BasicConstraints")

        if not basic_constraints.ca:
            raise ValueError("CSCA certificate must have CA=TRUE")

        if basic_constraints.path_length != 0:
            raise ValueError("CSCA certificate must have pathLenConstraint=0")

        try:
            key_usage = certificate.extensions.get_extension_for_class(
                x509.KeyUsage
            ).value
        except x509.ExtensionNotFound:
            raise ValueError("CSCA certificate missing KeyUsage")

        if not key_usage.key_cert_sign:
            raise ValueError("CSCA certificate must allow keyCertSign")

        if not key_usage.crl_sign:
            raise ValueError("CSCA certificate must allow cRLSign")

    def retire_key(self, key_id: str):
        entry = self.registry.get_key(key_id)

        if entry is None:
            raise KeyError("key not registered")

        if entry["status"] != "ACTIVE":
            raise ValueError(f"key is not active: {entry['status']}")

        self.registry.retire_key(key_id)

        return self.registry.get_key(key_id)
