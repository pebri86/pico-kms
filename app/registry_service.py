from __future__ import annotations

from .hsm import hsm
from .registry import Registry
from cryptography import x509
from .certificate_policy import CertificatePolicy, CertificatePolicyError
from .clock import system_clock, Clock


class AuthorizationError(ValueError):
    """Raised when a registered key is not authorized for an operation."""


class IntegrityError(RuntimeError):
    """Raised when a critical registry/HSM integrity violation is
    detected and cryptographic operations are failed closed."""


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
        certificate_policy: CertificatePolicy | None = None,
    ):
        self.registry = registry or Registry()
        self.clock = clock
        self.certificate_policy = certificate_policy or CertificatePolicy(
            clock=clock
        )
        self.fail_closed = False
        self.integrity_issues = []

    def run_startup_integrity_check(self):
        """Detect critical registry/HSM integrity violations at startup.

        On a critical violation (an ACTIVE registered key whose HSM
        object is missing) the service FAILS CLOSED: cryptographic
        operations are refused until the operator resolves the issue.
        """
        report = self.check_integrity()
        self.integrity_issues = report["issues"]

        critical = [
            i
            for i in report["issues"]
            if i["type"] == "MISSING_HSM_KEY"
            and i.get("status") == "ACTIVE"
        ]

        self.fail_closed = bool(critical)

        return {
            "fail_closed": self.fail_closed,
            "critical_issues": len(critical),
            "checked_at": report["checked_at"],
        }
    def validate_key(self, key_id: str):
        if self.fail_closed:
            raise IntegrityError(
                "service is failed closed: critical registry/HSM "
                "integrity violation detected"
            )

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

            self.certificate_policy.validate(
                certificate,
                role=entry["role"],
                public_key_der=key["public_key_der"],
            )

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

        # The full role-aware validation policy is applied before
        # any registry mutation. A failed validation leaves the
        # existing binding untouched.
        self.certificate_policy.validate(
            certificate,
            role=entry["role"],
            public_key_der=key["public_key_der"],
        )

        # Only modify the registry after every validation succeeds.
        self.registry.update_certificate(
            key_id,
            certificate_id,
        )

    def delete_certificate(self, certificate_id: str):
        if not certificate_id:
            raise ValueError("certificate_id is required")

        # Never delete a certificate that is referenced by a
        # registered key identity, including RETIRED keys.
        references = self.registry.find_keys_by_certificate_id(
            certificate_id
        )

        if references:
            key_ids = ", ".join(
                entry["key_id"] for entry in references
            )
            raise ValueError(
                f"certificate is referenced by registered key(s): {key_ids}"
            )

        try:
            hsm.cert(certificate_id)
        except KeyError:
            raise KeyError("certificate not found")

        try:
            hsm.delete_cert(certificate_id)
        except KeyError:
            raise KeyError("certificate not found")

    def get_key(self, key_id: str):
        return self.validate_key(key_id)

    def get_registered_key(self, key_id: str):
        """Return registry metadata without requiring the key to be ACTIVE.

        Management/read operations must be able to inspect RETIRED keys.
        Cryptographic operations must continue to use validate_key().
        """
        entry = self.registry.get_key(key_id)

        if entry is None:
            raise KeyError("key not registered")

        return entry

    def list_registered_keys(self):
        """Return all registered key metadata, including RETIRED keys."""
        return self.registry.list_keys()

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
        # is cryptographically bound to this HSM public key, then
        # apply the full role-aware validation policy.
        if certificate_id:
            try:
                cert_der = hsm.cert(certificate_id)
            except KeyError:
                raise ValueError("certificate not found")

            certificate = x509.load_der_x509_certificate(cert_der)

            self.certificate_policy.validate(
                certificate,
                role=role,
                public_key_der=key["public_key_der"],
            )

        # CSCA registration always requires a certificate.
        if role == "CSCA" and not certificate_id:
            raise ValueError("CSCA registration requires certificate_id")

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

    def retire_key(self, key_id: str):
        entry = self.registry.get_key(key_id)

        if entry is None:
            raise KeyError("key not registered")

        if entry["status"] != "ACTIVE":
            raise ValueError(f"key is not active: {entry['status']}")

        self.registry.retire_key(key_id)

        return self.registry.get_key(key_id)

    def check_integrity(self):
        """Read-only registry <-> HSM consistency report.

        Covers the key registry, HSM key inventory, HSM certificate
        inventory and key<->certificate bindings. Never mutates the
        registry or the HSM.
        """
        now = self.clock.now().isoformat()

        hsm_certs = {}
        for o in hsm.objects(1):
            cid = bytes.fromhex(o["id"]).decode()
            hsm_certs[cid] = o

        issues = []
        referenced = {}

        for entry in self.registry.list_keys():
            object_id = entry["object_id"]
            certificate_id = entry["certificate_id"]

            # Every registered key must resolve to an HSM object whose
            # metadata matches the immutable identity fields.
            try:
                key = hsm.key(object_id)
            except KeyError:
                issues.append(
                    {
                        "type": "MISSING_HSM_KEY",
                        "key_id": entry["key_id"],
                        "object_id": object_id,
                        "certificate_id": certificate_id,
                        "status": entry["status"],
                    }
                )
                continue

            if key["algorithm"] != entry["algorithm"]:
                issues.append(
                    {
                        "type": "KEY_ALGORITHM_MISMATCH",
                        "key_id": entry["key_id"],
                        "object_id": object_id,
                        "registered": entry["algorithm"],
                        "hsm": key["algorithm"],
                        "status": entry["status"],
                    }
                )

            if entry["algorithm"] == "RSA":
                registered_params = str(entry["key_parameters"])
                hsm_params = str(key["bits"])
            elif entry["algorithm"] == "EC":
                registered_params = entry["key_parameters"]
                hsm_params = key["curve"]
            else:
                registered_params = hsm_params = None

            if registered_params is not None and registered_params != hsm_params:
                issues.append(
                    {
                        "type": "KEY_PARAMETER_MISMATCH",
                        "key_id": entry["key_id"],
                        "object_id": object_id,
                        "registered": registered_params,
                        "hsm": hsm_params,
                        "status": entry["status"],
                    }
                )

            if not key["private_present"]:
                issues.append(
                    {
                        "type": "MISSING_PRIVATE_KEY",
                        "key_id": entry["key_id"],
                        "object_id": object_id,
                        "status": entry["status"],
                    }
                )

            if not certificate_id:
                continue

            referenced.setdefault(certificate_id, []).append(
                entry["key_id"]
            )

            # registry references a certificate that does not exist on
            # the HSM -> stale binding
            if certificate_id not in hsm_certs:
                issues.append(
                    {
                        "type": "MISSING_HSM_CERTIFICATE",
                        "key_id": entry["key_id"],
                        "object_id": object_id,
                        "certificate_id": certificate_id,
                        "status": entry["status"],
                    }
                )
                continue

            try:
                cert_der = hsm.cert(certificate_id)
                certificate = x509.load_der_x509_certificate(cert_der)
            except Exception as e:
                issues.append(
                    {
                        "type": "UNPARSEABLE_CERTIFICATE",
                        "key_id": entry["key_id"],
                        "object_id": object_id,
                        "certificate_id": certificate_id,
                        "status": entry["status"],
                        "reason": str(e),
                    }
                )
                continue

            try:
                self.certificate_policy.validate(
                    certificate,
                    role=entry["role"],
                    public_key_der=key["public_key_der"],
                )
            except CertificatePolicyError as e:
                issues.append(
                    {
                        "type": "CERTIFICATE_POLICY_VIOLATION",
                        "key_id": entry["key_id"],
                        "object_id": object_id,
                        "certificate_id": certificate_id,
                        "status": entry["status"],
                        "reason": str(e),
                    }
                )

        # HSM certificates with no registry reference -> orphaned.
        for certificate_id in hsm_certs:
            if certificate_id not in referenced:
                issues.append(
                    {
                        "type": "UNREFERENCED_CERTIFICATE",
                        "certificate_id": certificate_id,
                        "label": hsm_certs[certificate_id].get("label"),
                    }
                )

        # Duplicate logical references to the same certificate.
        for certificate_id, key_ids in referenced.items():
            if len(key_ids) > 1:
                issues.append(
                    {
                        "type": "DUPLICATE_REFERENCE",
                        "certificate_id": certificate_id,
                        "key_ids": key_ids,
                    }
                )

        return {
            "checked_at": now,
            "summary": {
                "hsm_certificates": len(hsm_certs),
                "registered_keys": len(self.registry.list_keys()),
                "bound_keys": len(referenced),
                "issues": len(issues),
            },
            "issues": issues,
        }

    def check_certificate_inventory(self):
        return self.check_integrity()
