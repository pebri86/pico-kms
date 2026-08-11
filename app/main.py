from __future__ import annotations
import base64, binascii, hashlib
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from .hsm import hsm
from .registry_service import RegistryService

app = FastAPI(title="PicoHSM ePassport KMS Phase 1", version="1.0.0")
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
    data: str


class Verify(BaseModel):
    algorithm: str
    data: str
    signature: str


class Cert(BaseModel):
    object_id: str
    label: str
    certificate: str


def b64(v, n):
    try:
        return base64.b64decode(v, validate=True)
    except (ValueError, binascii.Error) as e:
        raise HTTPException(400, f"{n} is not valid Base64") from e


@app.get("/health")
def health():
    try:
        return {"status": "ok", "hsm": "connected", "token": hsm.token()}
    except Exception as e:
        return {"status": "degraded", "hsm": "unavailable", "error": str(e)}


@app.get("/v1/hsm/token")
def token():
    try:
        return hsm.token()
    except Exception as e:
        raise HTTPException(503, str(e))


@app.get("/v1/hsm/mechanisms")
def mechanisms():
    try:
        return {"mechanisms": hsm.mechanisms()}
    except Exception as e:
        raise HTTPException(503, str(e))


@app.get("/v1/hsm/objects")
def objects():
    try:
        return {"objects": hsm.objects()}
    except Exception as e:
        raise HTTPException(503, str(e))


@app.post("/v1/phase1/keys/generate/rsa")
def gen_rsa(r: RSA):
    try:
        k = hsm.gen_rsa(r.object_id, r.label, r.bits)
        k.pop("public_key", None)
        return {**k, "public_key_der": base64.b64encode(k["public_key_der"]).decode()}
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(503, str(e))


@app.post("/v1/phase1/keys/generate/ec")
def gen_ec(r: EC):
    try:
        k = hsm.gen_ec(r.object_id, r.label, r.curve)
        return {**k, "public_key_der": base64.b64encode(k["public_key_der"]).decode()}
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(503, str(e))


@app.post("/v1/phase1/keys/{i}/sign")
def sign(i: str, r: Sign):
    try:
        registry_service.validate_signing_key(
            i,
            r.algorithm,
        )

        return {
            "object_id": i,
            "algorithm": r.algorithm,
            "signature": base64.b64encode(
                hsm.sign(
                    i,
                    r.algorithm,
                    b64(r.data, "data"),
                )
            ).decode(),
        }

    except KeyError:
        raise HTTPException(404, "key not registered")

    except ValueError as e:
        raise HTTPException(400, str(e))

    except Exception as e:
        raise HTTPException(503, str(e))


@app.post("/v1/phase1/keys/{i}/verify")
def verify(i: str, r: Verify):
    try:
        return {
            "object_id": i,
            "algorithm": r.algorithm,
            "valid": hsm.verify(
                i, r.algorithm, b64(r.data, "data"), b64(r.signature, "signature")
            ),
        }
    except KeyError:
        raise HTTPException(404, "public key not found")
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(503, str(e))


@app.get("/v1/phase1/certificates")
def certs():
    try:
        out = []
        for o in hsm.objects(1):
            try:
                der = hsm.cert(o["id"])
                c = x509.load_der_x509_certificate(der)
                out.append(
                    {
                        "id": o["id"],
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
        raise HTTPException(503, str(e))


@app.get("/v1/phase1/certificates/{i}")
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
        raise HTTPException(422, str(e))


@app.post("/v1/phase1/certificates/import")
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
        return {
            "id": r.object_id,
            "label": r.label,
            "subject": c.subject.rfc4514_string(),
            "issuer": c.issuer.rfc4514_string(),
            "sha256": hashlib.sha256(der).hexdigest(),
        }
    except Exception as e:
        raise HTTPException(400, str(e))


@app.delete("/v1/phase1/certificates/{i}")
def delete_cert(i: str):
    try:
        hsm.delete_cert(i)
        return {"deleted": True, "id": i}
    except KeyError:
        raise HTTPException(404, "certificate not found")
    except Exception as e:
        raise HTTPException(503, str(e))
