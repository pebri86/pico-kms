# PicoHSM ePassport KMS

Production KMS service backed by a Pico HSM.

## Features

- RSA 2048/3072/4096 and EC P-256/P-384/P-521 generation
- private keys never leave the HSM
- RSA-SHA256 / ECDSA-SHA256 sign/verify
- X.509 certificate import, listing, read and delete
- key registry (CSCA / DS / CVCA roles) with certificate binding
- role-aware certificate validation policy
- registry ↔ HSM integrity diagnostics with fail-closed startup check
- full audit trail (key and certificate events)
- admin vs API token authorization planes

## Install

```bash
sudo apt install pcscd pcsc-tools opensc openssl libpcsclite1
sudo systemctl enable --now pcscd
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
./scripts/run.sh
```

Keep the API on `127.0.0.1`. Do not put production CSCA/DS keys on a development service.

## Probe

```bash
./scripts/pkcs11_probe.sh
```

OpenSC supports listing PKCS#11 slots, mechanisms and objects, key-pair generation, certificate read/write and sign/verify testing. See the OpenSC PKCS#11 documentation for module-specific commands.

## API

```text
GET    /health
GET    /v1/hsm/token
GET    /v1/hsm/mechanisms
GET    /v1/hsm/objects

GET    /v1/keys
GET    /v1/keys/{key_id}
POST   /v1/keys/generate/rsa
POST   /v1/keys/generate/ec
POST   /v1/keys/register
POST   /v1/keys/{key_id}/retire
PUT    /v1/keys/{key_id}/certificate

POST   /v1/keys/{object_id}/sign
POST   /v1/keys/{object_id}/verify

GET    /v1/certificates
GET    /v1/certificates/{certificate_id}
POST   /v1/certificates/import
DELETE /v1/certificates/{certificate_id}

GET    /v1/integrity
GET    /v1/integrity/certificates
```

### Authorization

- **Admin plane** (`PICO_KMS_ADMIN_TOKEN`): key generation/registration/retirement, certificate import/update/delete/query, registry query, integrity diagnostics.
- **Cryptographic plane** (`PICO_KMS_API_TOKEN`): sign, verify.

## Certificate object model

Use the same CKA_ID for a key pair and its certificate when you want standard PKCS#11 object association:

```text
CKO_PUBLIC_KEY   CKA_ID = DS-DEV-01
CKO_PRIVATE_KEY  CKA_ID = DS-DEV-01
CKO_CERTIFICATE  CKA_ID = DS-DEV-01
```

The KMS only stores public certificate material. It never imports or exports private keys.
