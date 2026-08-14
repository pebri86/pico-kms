from __future__ import annotations
import threading
import pkcs11
from pkcs11 import (
    Attribute,
    CertificateType,
    KeyType,
    Mechanism,
    MechanismFlag,
    ObjectClass,
)
from pkcs11.exceptions import PKCS11Error
from pkcs11.util.ec import encode_named_curve_parameters
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from asn1crypto import keys as asn1keys, core as asn1core
from .config import settings


# The development token is a single-slot Pico HSM. Concurrent PKCS#11
# sessions over PC/SC contend for the one token and can deadlock, so all
# HSM access is serialized with a process-wide reentrant lock.
_hsm_lock = threading.RLock()


def _hsm_locked(func):
    def wrapper(*args, **kwargs):
        with _hsm_lock:
            return func(*args, **kwargs)

    wrapper.__name__ = func.__name__
    return wrapper


class HSM:
    def __init__(self):
        self._lib = None

    @property
    def lib(self):
        if self._lib is None:
            self._lib = pkcs11.lib(settings.pkcs11_module)
        return self._lib

    def slot(self):
        slots = self.lib.get_slots(token_present=True)
        if settings.pico_hsm_slot_id is not None:
            for s in slots:
                if int(s.slot_id) == settings.pico_hsm_slot_id:
                    return s
            raise RuntimeError("configured slot has no token")
        if settings.pico_hsm_token_label:
            m = [
                s
                for s in slots
                if s.get_token().label.strip() == settings.pico_hsm_token_label.strip()
            ]
            if len(m) != 1:
                raise RuntimeError("token label did not identify exactly one token")
            return m[0]
        if len(slots) != 1:
            raise RuntimeError(f"exactly one token required; found {len(slots)}")
        return slots[0]

    @_hsm_locked
    def token(self):
        s = self.slot()
        t = s.get_token()
        return {
            "slot_id": int(s.slot_id),
            "label": t.label.strip(),
            "manufacturer": t.manufacturer_id.strip(),
            "model": t.model.strip(),
            "serial": t.serial.strip(),
        }

    @_hsm_locked
    def mechanisms(self):
        return sorted(m.name for m in self.slot().get_mechanisms())

    def session(self, rw=False):
        if not settings.pico_hsm_pin:
            raise RuntimeError("PICO_HSM_PIN is not configured")
        return self.slot().get_token().open(rw=rw, user_pin=settings.pico_hsm_pin)

    @staticmethod
    def g(o, a, d=None):
        try:
            return o[a]
        except Exception:
            return d

    def pub(self, s, i):
        return next(
            iter(
                s.get_objects(
                    {Attribute.CLASS: ObjectClass.PUBLIC_KEY, Attribute.ID: i.encode()}
                )
            ),
            None,
        )

    def priv(self, s, i):
        return next(
            iter(
                s.get_objects(
                    {Attribute.CLASS: ObjectClass.PRIVATE_KEY, Attribute.ID: i.encode()}
                )
            ),
            None,
        )

    @_hsm_locked
    def key(self, i):
        with self.session() as s:
            p = self.pub(s, i)
            q = self.priv(s, i)
            if not p and not q:
                raise KeyError(i)
            o = p or q
            kt = self.g(o, Attribute.KEY_TYPE)
            if kt == KeyType.RSA:
                n = self.g(p or o, Attribute.MODULUS)
                e = self.g(p or o, Attribute.PUBLIC_EXPONENT)
                if n is None or e is None:
                    raise RuntimeError("RSA public attributes unavailable")
                n = int.from_bytes(n, "big") if isinstance(n, bytes) else int(n)
                e = int.from_bytes(e, "big") if isinstance(e, bytes) else int(e)
                k = rsa.RSAPublicNumbers(e, n).public_key()
                return {
                    "object_id": i,
                    "algorithm": "RSA",
                    "bits": k.key_size,
                    "public_key": k,
                    "public_key_der": k.public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    ),
                    "private_present": q is not None,
                }
            if kt == KeyType.EC:
                o = p or o
                point = self.g(o, Attribute.EC_POINT)
                params = self.g(o, Attribute.EC_PARAMS)
                if not point or not params:
                    raise RuntimeError("EC public attributes unavailable")
                d = asn1keys.ECDomainParameters.load(params)
                curves = {
                    "1.2.840.10045.3.1.7": ec.SECP256R1(),
                    "1.3.132.0.34": ec.SECP384R1(),
                    "1.3.132.0.35": ec.SECP521R1(),
                }
                curve = curves.get(d.chosen.dotted) if d.name == "named" else None
                if curve is None:
                    raise RuntimeError("unsupported EC curve")
                raw = asn1core.OctetString.load(point).native
                k = ec.EllipticCurvePublicKey.from_encoded_point(curve, raw)
                return {
                    "object_id": i,
                    "algorithm": "EC",
                    "curve": curve.name,
                    "public_key": k,
                    "public_key_der": k.public_bytes(
                        serialization.Encoding.DER,
                        serialization.PublicFormat.SubjectPublicKeyInfo,
                    ),
                    "private_present": q is not None,
                }
            raise RuntimeError("unsupported key type")

    @_hsm_locked
    def _assert_unique(self, i):
        with self.session() as s:
            existing = next(
                iter(s.get_objects({Attribute.ID: i.encode()})),
                None,
            )
        if existing is not None:
            raise ValueError(f"object_id already exists on HSM: {i}")

    @_hsm_locked
    def gen_rsa(self, i, label, bits):
        if bits not in (2048, 3072, 4096):
            raise ValueError("RSA bits must be 2048, 3072 or 4096")
        self._assert_unique(i)
        with self.session(True) as s:
            s.generate_keypair(
                KeyType.RSA,
                key_length=bits,
                id=i.encode(),
                label=label,
                store=True,
                capabilities=MechanismFlag.SIGN | MechanismFlag.VERIFY,
            )
        return self.key(i)

    @_hsm_locked
    def gen_ec(self, i, label, curve):
        aliases = {
            "P-256": "secp256r1",
            "prime256v1": "secp256r1",
            "P-384": "secp384r1",
            "P-521": "secp521r1",
        }
        curve = aliases.get(curve, curve)
        if curve not in ("secp256r1", "secp384r1", "secp521r1"):
            raise ValueError("unsupported EC curve")
        self._assert_unique(i)
        with self.session(True) as s:
            dp = s.create_domain_parameters(
                KeyType.EC,
                {Attribute.EC_PARAMS: encode_named_curve_parameters(curve)},
                local=True,
            )
            dp.generate_keypair(
                id=i.encode(),
                label=label,
                store=True,
                capabilities=MechanismFlag.SIGN | MechanismFlag.VERIFY,
            )
        return self.key(i)

    @_hsm_locked
    def sign(self, i, a, data):
        mm = {
            "RSA-SHA256": Mechanism.SHA256_RSA_PKCS,
            "ECDSA-SHA256": Mechanism.ECDSA_SHA256,
        }
        if a not in mm:
            raise ValueError("unsupported signing algorithm")
        with self.session() as s:
            k = self.priv(s, i)
            if not k:
                raise KeyError(i)
            return bytes(k.sign(data, mechanism=mm[a]))

    @_hsm_locked
    def verify(self, i, a, data, sig):
        mm = {
            "RSA-SHA256": Mechanism.SHA256_RSA_PKCS,
            "ECDSA-SHA256": Mechanism.ECDSA_SHA256,
        }
        if a not in mm:
            raise ValueError("unsupported verification algorithm")
        with self.session() as s:
            k = self.pub(s, i)
            if not k:
                raise KeyError(i)
            try:
                return bool(k.verify(data, sig, mechanism=mm[a]))
            except PKCS11Error:
                return False

    @_hsm_locked
    def objects(self, cls=None):
        with self.session() as s:
            it = s.get_objects({Attribute.CLASS: cls} if cls else {})
            out = []
            for o in it:
                x = self.g(o, Attribute.ID, b"")
                out.append(
                    {
                        "class": str(self.g(o, Attribute.CLASS)),
                        "id": x.hex() if isinstance(x, bytes) else x,
                        "label": self.g(o, Attribute.LABEL),
                        "private": self.g(o, Attribute.PRIVATE),
                        "token": self.g(o, Attribute.TOKEN),
                    }
                )
            return out

    @_hsm_locked
    def cert(self, i):
        with self.session() as s:
            o = next(
                iter(
                    s.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.CERTIFICATE,
                            Attribute.ID: i.encode(),
                        }
                    )
                ),
                None,
            )
            if not o:
                raise KeyError(i)
            return bytes(o[Attribute.VALUE])

    @_hsm_locked
    def import_cert(self, i, label, der):
        with self.session(True) as s:
            s.create_object(
                {
                    Attribute.CLASS: ObjectClass.CERTIFICATE,
                    Attribute.CERTIFICATE_TYPE: CertificateType.X_509,
                    Attribute.TOKEN: True,
                    Attribute.ID: i.encode(),
                    Attribute.LABEL: label,
                    Attribute.VALUE: der,
                }
            )
        return {"id": i, "label": label, "stored": True}

    @_hsm_locked
    def delete_cert(self, i):
        with self.session(True) as s:
            o = next(
                iter(
                    s.get_objects(
                        {
                            Attribute.CLASS: ObjectClass.CERTIFICATE,
                            Attribute.ID: i.encode(),
                        }
                    )
                ),
                None,
            )
            if not o:
                raise KeyError(i)
            o.destroy()


hsm = HSM()
