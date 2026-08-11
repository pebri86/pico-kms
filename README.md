# PicoHSM ePassport KMS — Complete Phase 1

Completes Phase 1-A through 1-D and provides the PKCS#11 foundation used by Phase 2.

## Phase 1-A
- PC/SC/OpenSC probe
- token/slot selection
- token information
- mechanism inventory

## Phase 1-B
- RSA 2048/3072/4096 generation
- EC P-256/P-384/P-521 generation
- private keys remain on PicoHSM

## Phase 1-C
- RSA-SHA256 sign/verify
- ECDSA-SHA256 sign/verify

## Phase 1-D
- X.509 certificate object listing
- certificate DER read
- PEM/DER certificate import
- certificate metadata inspection
- certificate object deletion

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

Keep the API on `127.0.0.1` during development. Do not put production CSCA/DS keys on this development service.

## Probe

```bash
./scripts/pkcs11_probe.sh
```

OpenSC supports listing PKCS#11 slots, mechanisms and objects, key-pair generation, certificate read/write and sign/verify testing. See the OpenSC PKCS#11 documentation for module-specific commands. 

## API

```text
GET  /health
GET  /v1/hsm/token
GET  /v1/hsm/mechanisms
GET  /v1/hsm/objects
POST /v1/phase1/keys/generate/rsa
POST /v1/phase1/keys/generate/ec
POST /v1/phase1/keys/{id}/sign
POST /v1/phase1/keys/{id}/verify
GET  /v1/phase1/certificates
GET  /v1/phase1/certificates/{id}
POST /v1/phase1/certificates/import
DELETE /v1/phase1/certificates/{id}
```

## Certificate object model

Use the same CKA_ID for a key pair and its certificate when you want standard PKCS#11 object association:

```text
CKO_PUBLIC_KEY   CKA_ID = DS-DEV-01
CKO_PRIVATE_KEY  CKA_ID = DS-DEV-01
CKO_CERTIFICATE  CKA_ID = DS-DEV-01
```

Phase 1-D only stores public certificate material. It never imports or exports private keys.

## Phase 2 boundary

The next layer maps logical IDs such as `CSCA-DEV-01`, `DS-DEV-01`, and `CVCA-DEV-01` to the HSM object IDs and stores public certificate metadata in a database.

## Production hardening still required

mTLS, authorization, key ceremony/dual control, secure PIN handling, tamper-evident audit, rotation, HSM health monitoring, backup/recovery and operational controls are not part of Phase 1.
