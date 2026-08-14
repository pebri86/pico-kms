from __future__ import annotations
import base64, binascii, hashlib, logging
from contextlib import asynccontextmanager
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
)
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import secrets
from pydantic import BaseModel, Field
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from .hsm import hsm
from .registry_service import (
    RegistryService,
    AuthorizationError,
    IntegrityError,
)
from typing import Literal
from .audit import (
    audit_sign,
    audit_verify,
    audit_api_auth,
    audit_admin_auth,
    audit_key_event,
    audit_cert_event,
)
from .config import settings

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        registry_service.run_startup_integrity_check()
    except Exception:
        pass
    yield


app = FastAPI(
    title="PicoHSM ePassport KMS",
    version="1.0.0",
    lifespan=lifespan,
)
bearer_scheme = HTTPBearer(
    scheme_name="PicoKMSBearer",
)
def require_admin_auth(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    expected = settings.pico_kms_admin_token

    if not expected:
        audit_admin_auth(
            result="FAILURE",
            reason="admin authentication is not configured",
        )
        raise HTTPException(
            status_code=503,
            detail="Admin authentication is not configured",
        )

    if not secrets.compare_digest(
        credentials.credentials,
        expected,
    ):
        audit_admin_auth(
            result="DENIED",
            reason="invalid admin credentials",
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid admin credentials",
        )

    audit_admin_auth(result="SUCCESS")
    return True


def require_api_auth(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
):
    expected = settings.pico_kms_api_token

    if not expected:
        audit_api_auth(
            result="FAILURE",
            reason="API authentication is not configured",
        )
        raise HTTPException(
            status_code=503,
            detail="API authentication is not configured",
        )

    if not secrets.compare_digest(
        credentials.credentials,
        expected,
    ):
        audit_api_auth(
            result="DENIED",
            reason="invalid credentials",
        )
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication credentials",
        )

    audit_api_auth(result="SUCCESS")

    return True


registry_service = RegistryService()


class RSA(BaseModel):
    object_id: str
    label: str
    bits: int = 2048


class EC(BaseModel):
    object_id: str
    label: str
    curve: str = "secp256r1"


class Sign(BaseModel):
    algorithm: str
    operation: str
    data: str


class Verify(BaseModel):
    algorithm: str
    data: str
    signature: str


class Cert(BaseModel):
    object_id: str
    label: str
    certificate: str


class RegisterKey(BaseModel):
    key_id: str
    role: Literal[
        "CSCA",
        "DS",
        "CVCA",
    ]
    object_id: str
    label: str
    certificate_id: str | None = None


def b64(v, n):
    try:
        data = base64.b64decode(v, validate=True)
    except (ValueError, binascii.Error) as e:
        raise HTTPException(
            400,
            f"{n} is not valid Base64",
        ) from e

    if not data:
        raise HTTPException(
            400,
            f"{n} must not be empty",
        )

    return data


def _internal_error(e: Exception, detail: str = "internal error"):
    """Sanitize unexpected internal failures.

    PKCS#11 internals, filesystem paths, HSM session details and
    tracebacks must never reach the client. Log the real error and
    surface a generic message only.
    """
    logging.getLogger("picokms.api").exception("%s: %s", detail, e)
    raise HTTPException(503, detail) from e


@app.get("/health")
def health():
    try:
        return {
            "status": "ok",
            "hsm": "connected",
            "token": hsm.token(),
            "fail_closed": registry_service.fail_closed,
            "integrity_issues": len(registry_service.integrity_issues),
        }
    except Exception as e:
        logging.getLogger("picokms.api").exception("health check failed: %s", e)
        return {"status": "degraded", "hsm": "unavailable"}


@app.get(
    "/v1/hsm/token",
    dependencies=[Depends(require_admin_auth)],
)
def token():
    try:
        return hsm.token()
    except Exception as e:
        _internal_error(e)


@app.get(
    "/v1/hsm/mechanisms",
    dependencies=[Depends(require_admin_auth)],
)
def mechanisms():
    try:
        return {"mechanisms": hsm.mechanisms()}
    except Exception as e:
        _internal_error(e)


@app.get(
    "/v1/hsm/objects",
    dependencies=[Depends(require_admin_auth)],
)
def objects():
    try:
        return {"objects": hsm.objects()}
    except Exception as e:
        _internal_error(e)


@app.get(
    "/v1/keys",
    dependencies=[Depends(require_admin_auth)],
)
def list_registered_keys():
    try:
        entries = registry_service.list_registered_keys()

        return {
            "keys": [
                {
                    "key_id": entry["key_id"],
                    "role": entry["role"],
                    "object_id": entry["object_id"],
                    "label": entry["label"],
                    "algorithm": entry["algorithm"],
                    "key_parameters": entry["key_parameters"],
                    "certificate_id": entry["certificate_id"],
                    "status": entry["status"],
                    "created_at": entry["created_at"],
                    "updated_at": entry["updated_at"],
                }
                for entry in entries
            ]
        }

    except Exception as e:
        _internal_error(e)


@app.get(
    "/v1/keys/{i}",
    dependencies=[Depends(require_admin_auth)],
)
def get_registered_key(i: str):
    try:
        entry = registry_service.get_registered_key(i)

        return {
            "key_id": entry["key_id"],
            "role": entry["role"],
            "object_id": entry["object_id"],
            "label": entry["label"],
            "algorithm": entry["algorithm"],
            "key_parameters": entry["key_parameters"],
            "certificate_id": entry["certificate_id"],
            "status": entry["status"],
            "created_at": entry["created_at"],
            "updated_at": entry["updated_at"],
        }

    except KeyError:
        raise HTTPException(404, "key not registered")

    except Exception as e:
        _internal_error(e)


@app.post(
    "/v1/keys/register",
    dependencies=[Depends(require_admin_auth)],
)
def register_key(r: RegisterKey):
    try:
        entry = registry_service.register_hsm_key(
            key_id=r.key_id,
            role=r.role,
            object_id=r.object_id,
            label=r.label,
            certificate_id=r.certificate_id,
        )

        audit_ok = audit_key_event(
            event="KEY_REGISTER",
            result="SUCCESS",
            key_id=entry["key_id"],
            object_id=entry["object_id"],
            role=entry["role"],
            algorithm=entry["algorithm"],
        )

        if entry["certificate_id"]:
            audit_cert_event(
                event="CERT_BIND",
                result="SUCCESS",
                certificate_id=entry["certificate_id"],
                key_id=entry["key_id"],
                object_id=entry["object_id"],
                role=entry["role"],
                algorithm=entry["algorithm"],
            )

        return {
            "key_id": entry["key_id"],
            "role": entry["role"],
            "object_id": entry["object_id"],
            "label": entry["label"],
            "algorithm": entry["algorithm"],
            "key_parameters": entry["key_parameters"],
            "certificate_id": entry["certificate_id"],
            "status": entry["status"],
            "audit_status": "OK" if audit_ok else "DEGRADED",
        }

    except KeyError:
        raise HTTPException(
            status_code=404,
            detail="HSM object or certificate not found",
        )

    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e),
        )

    except Exception as e:
        _internal_error(e, "key registration failed")


@app.post(
    "/v1/keys/{i}/retire",
    dependencies=[Depends(require_admin_auth)],
)
def retire_key(i: str):
    try:
        entry = registry_service.retire_key(i)

        audit_key_event(
            event="KEY_RETIRE",
            result="SUCCESS",
            key_id=entry["key_id"],
            object_id=entry["object_id"],
            role=entry["role"],
            algorithm=entry["algorithm"],
        )

        return {
            "key_id": entry["key_id"],
            "object_id": entry["object_id"],
            "status": entry["status"],
        }

    except KeyError:
        raise HTTPException(404, "key not registered")

    except ValueError as e:
        raise HTTPException(400, str(e))

    except Exception as e:
        _internal_error(e)


@app.post(
    "/v1/keys/generate/rsa",
    dependencies=[Depends(require_admin_auth)],
)
def gen_rsa(r: RSA):
    try:
        k = hsm.gen_rsa(r.object_id, r.label, r.bits)

        audit_key_event(
            event="KEY_GENERATE",
            result="SUCCESS",
            key_id=r.object_id,
            object_id=r.object_id,
            role="UNASSIGNED",
            algorithm="RSA",
            reason=f"bits={r.bits}",
        )

        return {
            "object_id": k["object_id"],
            "algorithm": k["algorithm"],
            "bits": k["bits"],
            "public_key_der": base64.b64encode(k["public_key_der"]).decode(),
            "private_present": k["private_present"],
        }

    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        _internal_error(e)


@app.post(
    "/v1/keys/generate/ec",
    dependencies=[Depends(require_admin_auth)],
)
def gen_ec(r: EC):
    try:
        k = hsm.gen_ec(r.object_id, r.label, r.curve)

        audit_key_event(
            event="KEY_GENERATE",
            result="SUCCESS",
            key_id=r.object_id,
            object_id=r.object_id,
            role="UNASSIGNED",
            algorithm="EC",
            reason=f"curve={r.curve}",
        )

        return {
            "object_id": k["object_id"],
            "algorithm": k["algorithm"],
            "curve": k["curve"],
            "public_key_der": base64.b64encode(k["public_key_der"]).decode(),
            "private_present": k["private_present"],
        }

    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        _internal_error(e)


@app.post(
    "/v1/keys/{i}/sign",
    dependencies=[Depends(require_api_auth)],
)
def sign(i: str, r: Sign):
    try:
        entry = registry_service.validate_signing_key(
            i,
            r.algorithm,
            r.operation,
        )

        data = b64(r.data, "data")

        signature = hsm.sign(
            i,
            r.algorithm,
            data,
        )

        audit_ok = audit_sign(
            key_id=entry["key_id"],
            object_id=entry["object_id"],
            role=entry["role"],
            algorithm=r.algorithm,
            operation=r.operation,
            result="SUCCESS",
        )

        return {
            "object_id": i,
            "algorithm": r.algorithm,
            "operation": r.operation,
            "signature": base64.b64encode(signature).decode(),
            "audit_status": "OK" if audit_ok else "DEGRADED",
        }

    except HTTPException:
        raise

    except IntegrityError as e:
        _internal_error(e)

    except AuthorizationError as e:
        entry = registry_service.registry.get_key_by_object_id(i)

        if entry:
            audit_sign(
                key_id=entry["key_id"],
                object_id=entry["object_id"],
                role=entry["role"],
                algorithm=r.algorithm,
                operation=r.operation,
                result="DENIED",
                reason=str(e),
            )

        raise HTTPException(400, str(e))

    except KeyError:
        raise HTTPException(404, "key not registered")

    except ValueError as e:
        entry = None

        try:
            entry = registry_service.registry.get_key_by_object_id(i)
        except Exception:
            pass

        if entry:
            audit_sign(
                key_id=entry["key_id"],
                object_id=entry["object_id"],
                role=entry["role"],
                algorithm=r.algorithm,
                operation=r.operation,
                result="DENIED",
                reason=str(e),
            )

        raise HTTPException(400, str(e))

    except Exception as e:
        entry = None

        try:
            entry = registry_service.registry.get_key_by_object_id(i)
        except Exception:
            pass

        if entry:
            audit_sign(
                key_id=entry["key_id"],
                object_id=entry["object_id"],
                role=entry["role"],
                algorithm=r.algorithm,
                operation=r.operation,
                result="FAILURE",
                reason=str(e),
            )

        _internal_error(e)


@app.post(
    "/v1/keys/{i}/verify",
    dependencies=[Depends(require_api_auth)],
)
def verify(i: str, r: Verify):
    entry = None

    try:
        entry = registry_service.validate_object(i)

        registry_service.validate_signing_algorithm(
            entry,
            r.algorithm,
        )

        data = b64(r.data, "data")
        signature = b64(r.signature, "signature")

        valid = hsm.verify(
            i,
            r.algorithm,
            data,
            signature,
        )

        audit_verify(
            key_id=entry["key_id"],
            object_id=entry["object_id"],
            role=entry["role"],
            algorithm=r.algorithm,
            result="SUCCESS" if valid else "INVALID",
            reason=None if valid else "signature verification failed",
        )

        return {
            "object_id": i,
            "algorithm": r.algorithm,
            "valid": valid,
        }

    except HTTPException:
        raise

    except AuthorizationError as e:
        if entry:
            audit_verify(
                key_id=entry["key_id"],
                object_id=entry["object_id"],
                role=entry["role"],
                algorithm=r.algorithm,
                result="DENIED",
                reason=str(e),
            )

        raise HTTPException(400, str(e))

    except KeyError:
        raise HTTPException(404, "key not registered")

    except ValueError as e:
        if entry:
            audit_verify(
                key_id=entry["key_id"],
                object_id=entry["object_id"],
                role=entry["role"],
                algorithm=r.algorithm,
                result="FAILURE",
                reason=str(e),
            )

        raise HTTPException(400, str(e))

    except Exception as e:
        if entry:
            audit_verify(
                key_id=entry["key_id"],
                object_id=entry["object_id"],
                role=entry["role"],
                algorithm=r.algorithm,
                result="FAILURE",
                reason=str(e),
            )

        _internal_error(e)



class CertificateUpdate(BaseModel):
    certificate_id: str


@app.put(
    "/v1/keys/{key_id}/certificate",
    dependencies=[Depends(require_admin_auth)],
)
def update_key_certificate(
    key_id: str,
    r: CertificateUpdate,
):
    try:
        registry_service.update_certificate(
            key_id,
            r.certificate_id,
        )

        entry = registry_service.get_registered_key(key_id)

        audit_cert_event(
            event="CERT_UPDATE",
            result="SUCCESS",
            certificate_id=r.certificate_id,
            key_id=entry["key_id"],
            object_id=entry["object_id"],
            role=entry["role"],
            algorithm=entry["algorithm"],
        )

        return {
            "key_id": entry["key_id"],
            "object_id": entry["object_id"],
            "certificate_id": entry["certificate_id"],
            "status": entry["status"],
        }

    except KeyError:
        audit_cert_event(
            event="CERT_UPDATE",
            result="DENIED",
            certificate_id=r.certificate_id,
            key_id=key_id,
            reason="key not registered",
        )
        raise HTTPException(404, "key not registered")

    except ValueError as e:
        entry = None

        try:
            entry = registry_service.get_registered_key(key_id)
        except Exception:
            pass

        audit_cert_event(
            event="CERT_UPDATE",
            result="DENIED",
            certificate_id=r.certificate_id,
            key_id=key_id,
            object_id=entry["object_id"] if entry else None,
            role=entry["role"] if entry else None,
            reason=str(e),
        )
        raise HTTPException(400, str(e))

    except Exception as e:
        audit_cert_event(
            event="CERT_UPDATE",
            result="FAILURE",
            certificate_id=r.certificate_id,
            key_id=key_id,
            reason=str(e),
        )
        _internal_error(e)


@app.get(
    "/v1/integrity/certificates",
    dependencies=[Depends(require_admin_auth)],
)
def certificate_integrity():
    try:
        return registry_service.check_certificate_inventory()
    except Exception as e:
        _internal_error(e)


@app.get(
    "/v1/integrity",
    dependencies=[Depends(require_admin_auth)],
)
def integrity_report():
    try:
        report = registry_service.check_integrity()
        report["fail_closed"] = registry_service.fail_closed
        report["startup_issues"] = len(registry_service.integrity_issues)
        return report
    except Exception as e:
        _internal_error(e)


@app.get(
    "/v1/certificates",
    dependencies=[Depends(require_admin_auth)],
)
def certs():
    try:
        out = []
        for o in hsm.objects(1):
            try:
                cert_id = bytes.fromhex(o["id"]).decode()
                der = hsm.cert(cert_id)
                c = x509.load_der_x509_certificate(der)
                out.append(
                    {
                        "id": cert_id,
                        "label": o["label"],
                        "subject": c.subject.rfc4514_string(),
                        "issuer": c.issuer.rfc4514_string(),
                        "serial_number": str(c.serial_number),
                        "sha256": hashlib.sha256(der).hexdigest(),
                    }
                )
            except Exception:
                out.append(o)
        return {"certificates": out}
    except Exception as e:
        _internal_error(e)


@app.get(
    "/v1/certificates/{i}",
    dependencies=[Depends(require_admin_auth)],
)
def cert(i: str):
    try:
        der = hsm.cert(i)
        c = x509.load_der_x509_certificate(der)
        return {
            "id": i,
            "subject": c.subject.rfc4514_string(),
            "issuer": c.issuer.rfc4514_string(),
            "serial_number": str(c.serial_number),
            "sha256": hashlib.sha256(der).hexdigest(),
            "certificate_pem": c.public_bytes(serialization.Encoding.PEM).decode(),
        }
    except KeyError:
        raise HTTPException(404, "certificate not found")
    except Exception as e:
        _internal_error(e, "certificate could not be parsed")


@app.post(
    "/v1/certificates/import",
    dependencies=[Depends(require_admin_auth)],
)
def import_cert(r: Cert):
    try:
        try:
            c = x509.load_pem_x509_certificate(r.certificate.encode())
        except ValueError:
            c = x509.load_der_x509_certificate(
                base64.b64decode(r.certificate, validate=True)
            )
        der = c.public_bytes(serialization.Encoding.DER)
        hsm.import_cert(r.object_id, r.label, der)

        audit_cert_event(
            event="CERT_IMPORT",
            result="SUCCESS",
            certificate_id=r.object_id,
            object_id=r.object_id,
            algorithm="RSA" if isinstance(c.public_key(), rsa.RSAPublicKey) else "EC",
        )

        return {
            "id": r.object_id,
            "label": r.label,
            "subject": c.subject.rfc4514_string(),
            "issuer": c.issuer.rfc4514_string(),
            "sha256": hashlib.sha256(der).hexdigest(),
        }
    except HTTPException:
        raise

    except (ValueError, binascii.Error) as e:
        raise HTTPException(400, str(e))

    except Exception as e:
        _internal_error(e, "certificate import failed")


@app.delete(
    "/v1/certificates/{i}",
    dependencies=[Depends(require_admin_auth)],
)
def delete_cert(i: str):
    try:
        registry_service.delete_certificate(i)

        audit_cert_event(
            event="CERT_DELETE",
            result="SUCCESS",
            certificate_id=i,
        )

        return {
            "deleted": True,
            "id": i,
        }

    except KeyError:
        audit_cert_event(
            event="CERT_DELETE",
            result="DENIED",
            certificate_id=i,
            reason="certificate not found",
        )
        raise HTTPException(404, "certificate not found")

    except ValueError as e:
        audit_cert_event(
            event="CERT_DELETE",
            result="DENIED",
            certificate_id=i,
            reason=str(e),
        )
        raise HTTPException(400, str(e))

    except Exception as e:
        audit_cert_event(
            event="CERT_DELETE",
            result="FAILURE",
            certificate_id=i,
            reason=str(e),
        )
        _internal_error(e)
