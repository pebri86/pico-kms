# KMS API Interface — ePassport Personalization Agent

**Audience:** ePassport personalization agent (chip personalization / SOD
signing application). This document describes how the personalization
agent calls the PicoHSM KMS to obtain document-signer material and to
sign the Security Object Document (SOD) at issuance time.

**Service:** PicoHSM ePassport KMS — production.

---

## 1. Contact and connectivity

| Item | Value |
|------|-------|
| Base URL | `http://127.0.0.1:8000` (loopback; do not expose publicly) |
| Health | `GET /health` |
| API version prefix | `/v1` |
| Certificate export | `certs/` in the KMS host (PEM, gitignored) |

Keep the API bound to `127.0.0.1`. Production CSCA/DS keys must never be
served over an unauthenticated or externally reachable interface.

---

## 2. Enrolled production entities

| Role | key_id / object_id | Subject (CN) | Key | Certificate |
|------|--------------------|--------------|-----|-------------|
| CSCA | `CSCA-PRD-2026` | `CN=Republik Indonesia CSCA 2026, O=Republik Indonesia, C=ID` | RSA-3072 | self-signed root, CA=TRUE pathLen=0, keyCertSign+cRLSign |
| DS | `DS-PRD-2026` | `CN=Kementerian Luar Negeri Republik Indonesia, O=Kementerian Luar Negeri Republik Indonesia, C=ID` | EC P-256 (secp256r1) | issued by CSCA, digitalSignature |
| CVCA | `CVCA-PRD-2026` | `CN=Republik Indonesia CVCA 2026, O=Republik Indonesia, C=ID` | EC P-256 (secp256r1) | issued by CSCA, CA=TRUE, keyCertSign |

The **personalization agent uses the DS identity** (`DS-PRD-2026`) to
sign SODs. The CSCA identity is the trust anchor; the CVCA identity is
for the inspection-system PKI and is outside the personalization flow.

All private keys remain inside the HSM. The KMS never exports private
keys; only public certificate material is retrievable.

---

## 3. Authorization model

Every request carries an HTTP bearer token:

```
Authorization: Bearer <token>
```

| Plane | Token | Used for |
|-------|-------|----------|
| Cryptographic | `PICO_KMS_API_TOKEN` | sign, verify |
| Admin | `PICO_KMS_ADMIN_TOKEN` | certificate query/import, key registry, integrity |

The personalization agent authenticates with the **API token** for
sign/verify and, if it manages its own certificate cache, the **admin
token** for certificate queries. Crossing planes returns `401`.

| Code | Meaning |
|------|---------|
| 401 | Missing/invalid/wrong-plane token |
| 400 | Invalid operation, algorithm, data, or policy denial |
| 404 | Unknown object_id or certificate |
| 503 | HSM unavailable or service failed closed |

---

## 4. Personalization workflow

```text
 1. Fetch DS certificate           GET  /v1/certificates/DS-PRD-2026
 2. Prepare SOD payload            (agent computes digest over LDS)
 3. Sign SOD                       POST /v1/keys/DS-PRD-2026/sign
 4. Verify signature (optional)    POST /v1/keys/DS-PRD-2026/verify
 5. Write DS cert + SOD to chip    (agent)
```

---

## 5. Endpoints

### 5.1 Fetch the DS certificate

Used to obtain the document-signer certificate that must be written into
the ePassport LDS alongside the SOD.

```
GET /v1/certificates/DS-PRD-2026
Authorization: Bearer <admin-token>
```

Response `200`:

```json
{
  "id": "DS-PRD-2026",
  "subject": "CN=Kementerian Luar Negeri Republik Indonesia,O=Kementerian Luar Negeri Republik Indonesia,C=ID",
  "issuer": "CN=Republik Indonesia CSCA 2026,O=Republik Indonesia,C=ID",
  "serial_number": "438832061284601465529701483385864166104389352773",
  "sha256": "699fba5dd74e536fcad1d3d1ba4c796d40811ceede1c40db49eca878b310e59f",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
}
```

List all certificates on the HSM:

```
GET /v1/certificates
Authorization: Bearer <admin-token>
```

---

### 5.2 Sign the SOD (Document Signer)

Signs the SOD digest bytes with the DS private key.

```
POST /v1/keys/DS-PRD-2026/sign
Authorization: Bearer <api-token>
Content-Type: application/json
```

Request body:

| Field | Type | Value |
|-------|------|-------|
| `algorithm` | string | `ECDSA-SHA256` |
| `operation` | string | `DOCUMENT_SIGN` |
| `data` | string | base64-encoded SOD digest / payload to sign |

Example:

```json
{
  "algorithm": "ECDSA-SHA256",
  "operation": "DOCUMENT_SIGN",
  "data": "NDFhMjIxY2YwOTkzYzI0ZTI2OTQyYjdiM2U1MjJiMDY1ZTZkYjU4N2E="
}
```

Response `200`:

```json
{
  "object_id": "DS-PRD-2026",
  "algorithm": "ECDSA-SHA256",
  "operation": "DOCUMENT_SIGN",
  "signature": "lD4y/qNU3KPQ4fQ8DfqrBKH5RkB89WCRxin8GMbVSX5Ml32eaGdU4HXftBx2WUFfGbZ1HU6W9HsymAn0PRJejQ==",
  "audit_status": "OK"
}
```

`signature` is the base64-encoded DER ECDSA signature. Embed it in the
SOD per ICAO 9303.

---

### 5.3 Verify a signature

Optional integrity check; also usable to confirm a previously issued SOD.

```
POST /v1/keys/DS-PRD-2026/verify
Authorization: Bearer <api-token>
Content-Type: application/json
```

```json
{
  "algorithm": "ECDSA-SHA256",
  "data": "NDFhMjIxY2YwOTkzYzI0ZTI2OTQyYjdiM2U1MjJiMDY1ZTZkYjU4N2E=",
  "signature": "lD4y/qNU3KPQ4fQ8DfqrBKH5RkB89WCRxin8GMbVSX5Ml32eaGdU4HXftBx2WUFfGbZ1HU6W9HsymAn0PRJejQ=="
}
```

Response `200`:

```json
{
  "object_id": "DS-PRD-2026",
  "algorithm": "ECDSA-SHA256",
  "valid": true
}
```

A tampered signature returns `"valid": false` with HTTP `200`.

---

### 5.4 Health probe

```
GET /health
```

Response `200`:

```json
{
  "status": "ok",
  "hsm": "connected",
  "token": {"slot_id": 8, "label": "Pico-HSM (UserPIN)"},
  "fail_closed": false,
  "integrity_issues": 0
}
```

If `fail_closed` is `true`, the service refuses all cryptographic
operations (`503`) until an operator resolves the HSM/registry integrity
issue.

---

## 6. Operation policy

The KMS enforces role-bound operations. `DS-PRD-2026` is authorized for
`DOCUMENT_SIGN` only. For example:

- `CSCA-PRD-2026` accepts `CERTIFICATE_SIGN` and `CRL_SIGN` only.
- `CVCA-PRD-2026` accepts `CV_CERTIFICATE_SIGN` only.
- Attempting an operation outside the role returns `400` with a DENIED
  audit entry. Example:

```json
{"detail": "operation DOCUMENT_SIGN is not allowed for CSCA key"}
```

---

## 7. Data handling rules for the agent

- `data` for sign/verify is **base64** encoded; empty or invalid Base64
  is rejected with `400`.
- The KMS signs raw input bytes with the requested mechanism; the agent
  must pre-hash where the mechanism implies a digest (the HSM performs
  `ECDSA-SHA256`/`RSA-SHA256` internally on the supplied bytes).
- Never transmit the admin token or PIN over the wire beyond loopback.
- All operations are logged in the KMS audit trail
  (`KEY_SIGN`, `KEY_VERIFY`, `CERT_IMPORT`, `KEY_REGISTER`, ...).
- Private keys cannot be exported; certificate PEM files for all three
  enrolled identities are available on the KMS host under `certs/`.
