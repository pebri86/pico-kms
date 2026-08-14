# Pico-KMS KMS Function Roadmap

## Completed Foundation

| ID | Function | Status |
|----|----------|--------|
| C.23 | Client/error handling | ✅ |
| C.24 | API authentication | ✅ |
| C.25 | Audit integrity | ✅ |
| C.26 | RSA/EC algorithm enforcement | ✅ |
| C.27 | Key lifecycle / registry integrity | ✅ |
| KMS-01.4 | Key lifecycle API | ✅ |
| KMS-02.1 | Certificate import / query | ✅ |
| KMS-02.2 | Certificate ↔ HSM key binding | ✅ |
| KMS-02.3 | Certificate lifecycle | ✅ |
| KMS-02.4 | Certificate query access control | ✅ |
| KMS-02.5 | Certificate import access control | ✅ |
| KMS-02.6 | Certificate binding integrity | ✅ |
| KMS-02.7 | Certificate validation policy | ✅ |
| KMS-02.8 | Certificate inventory consistency | ✅ |
| KMS-03.1 | RSA generation | ✅ |
| KMS-03.2 | EC generation | ✅ |
| KMS-03.3 | Key registration | ✅ |
| KMS-04.1 | Signing | ✅ |
| KMS-04.2 | Verification | ✅ |
| KMS-04.3 | Operation policy | ✅ |
| KMS-05.1 | Management plane | ✅ |
| KMS-05.2 | Cryptographic plane | ✅ |
| KMS-05.3 | Authentication failure consistency | ✅ |
| KMS-06.1 | Key events audit | ✅ |
| KMS-06.2 | Certificate events audit | ✅ |

---

## KMS-02 — Certificate Management

We've now established the certificate management foundation.

### KMS-02.6 — Certificate Binding Integrity

**Goal:** make certificate/key relationships a first-class invariant.

**Status:** ✅ COMPLETE

**Completion gate:**

| # | Check | Result |
|---|-------|--------|
| 1 | matching certificate accepted | ✅ 200 verified |
| 2 | mismatched certificate rejected | ✅ 400 verified |
| 3 | unknown certificate rejected | ✅ 400 verified |
| 4 | certificate replacement works | ✅ 200 verified |
| 5 | failed replacement does not mutate registry | ✅ verified |
| 6 | retired key cannot update certificate | ✅ 400 verified |
| 7 | referenced certificate cannot be deleted | ✅ 400 verified |
| 8 | binding survives Registry reload | ✅ sqlite persistence |
| 9 | no private-key material exposed | ✅ metadata-only responses |
| 10 | audit event generated | ✅ CERT_UPDATE verified |
| 11 | API authentication boundary | ✅ admin plane verified |

**Result: PASS — KMS-02.6**

- **Endpoint:** `PUT /v1/phase1/keys/{key_id}/certificate`
- **Service:** `RegistryService.update_certificate()` / `delete_certificate()`
- **Guard:** certificate deletion blocked while referenced (incl. RETIRED keys)

### KMS-02.7 — Certificate Validation Policy

**Goal:** move certificate validation into an explicit policy layer.

**Status:** ✅ COMPLETE

**Design:**

```text
certificate imported
        ↓
certificate parsed
        ↓
certificate validated (CertificatePolicy.validate)
        ↓
certificate stored
        ↓
certificate bound to key
```

**Module:** `app/certificate_policy.py`

- `CertificatePolicy.validate(cert, role=..., public_key_der=...)`
- **Common:** validity period, public-key compatibility, algorithm support
- **CSCA:** self-issued + self-signature verified, `CA=TRUE pathLen=0`, `keyCertSign` + `cRLSign`
- **DS:** must not be a CA, must allow `digitalSignature`
- **CVCA:** `CA=TRUE`, `keyCertSign`
- `CertificatePolicyError` raised for every violation

**Verified against negative fixtures:**

- `TEST-CSCA-NO-BC` / `NO-KU` / `CA-FALSE` / `NO-KEYCERTSIGN` / `NO-CRLSIGN` all rejected; valid HSM self-signed CSCA accepted.

**Refactor:** inline CSCA checks removed from `RegistryService` and replaced by the policy layer in `validate_key` / `register_hsm_key` / `update_certificate`.

### KMS-02.8 — Certificate Inventory Consistency

**Goal:** read-only diagnostics between HSM inventory, registry and bindings.

**Status:** ✅ COMPLETE

**Design:** `GET /v1/phase1/integrity/certificates` (admin-only, read-only).
Implemented as `RegistryService.check_certificate_inventory()`. It never
mutates the registry or the HSM.

**Detected issue types:**

- `MISSING_HSM_CERTIFICATE` — registry references a certificate absent from the HSM
- `MISSING_HSM_KEY` — registered key object absent from the HSM
- `UNPARSEABLE_CERTIFICATE` — certificate exists but cannot be parsed
- `CERTIFICATE_POLICY_VIOLATION` — referenced certificate fails the role policy
- `UNREFERENCED_CERTIFICATE` — HSM certificate with no registry reference (orphaned)
- `DUPLICATE_REFERENCE` — multiple keys bound to the same certificate

**Verified on live HSM** — 4 issues correctly reported:

- `CSCA-TEST-001` → `TEST-CSCA-EC-01` missing from HSM (RETIRED)
- `CSCA-TEST-002` → `TEST-CSCA-EC-02-HSM` missing from HSM (ACTIVE, stale binding)
- `TEST-EC-CSCA-02` and `TEST-EC-01` unreferenced on the HSM

**Auth boundary verified:** no credentials → 401, API token (wrong domain) → 401.

---

## KMS-03 — Key Generation & Registration

### KMS-03.1 — RSA Key Generation

**Status:** ✅ COMPLETE

**Verified:**

- admin-only generation (API token / no-auth → 401)
- unique object ID enforced via HSM pre-check (`_assert_unique`)
- duplicate object ID → 400 (was previously an opaque 503)
- public metadata only: `object_id`, `algorithm`, `bits`, `public_key_der`, `private_present` — no private material
- audit `KEY_GENERATE` with `reason="bits=N"`
- registry registration remains a separate operation

**Endpoint:** `POST /v1/phase1/keys/generate/rsa` — 2048/3072/4096 bits.

### KMS-03.2 — EC Key Generation

**Status:** ✅ COMPLETE

Same security requirements as KMS-03.1, verified:

- EC P-256 / secp256r1 (also P-384/P-521, aliases accepted)
- duplicate object ID → 400
- unsupported curve → 400
- audit `KEY_GENERATE` with `reason="curve=..."`
- no private material in response

**Endpoint:** `POST /v1/phase1/keys/generate/ec`.

### KMS-03.3 — Key Registration

**Status:** ✅ COMPLETE

**Verified:**

- HSM object must exist → unknown object → 404
- private key must be present (public-only objects rejected)
- algorithm/parameters derived from the HSM object (RSA bits / EC curve)
- optional certificate validation via the policy layer
- immutable identity: `key_id`, `role`, `object_id`, `label`, `algorithm`, `key_parameters`, `created_at`
- duplicate `key_id` → 400, duplicate `object_id` → 400
- audit `KEY_REGISTER` (+ `CERT_BIND` when a certificate is supplied)

**Endpoint:** `POST /v1/phase1/keys/register`.

---

## KMS-04 — Cryptographic Operations

This becomes the main operational KMS layer.

### KMS-04.1 — Signing

**Status:** ✅ COMPLETE

**Verified:**

- API-token access only (admin token → 401)
- key must be ACTIVE (retired → 400)
- operation policy enforced (`CRL_SIGN`/`CERTIFICATE_SIGN` on DS → 400)
- algorithm/key compatibility enforced (RSA vs ECDSA mismatch → 400)
- Base64 validation → 400 on invalid input
- empty-data rejection → 400
- private key remains in HSM
- audit `KEY_SIGN` SUCCESS/DENIED
- cryptographic errors do not leak internals

**Endpoint:** `POST /v1/phase1/keys/{object_id}/sign` — RSA-SHA256, ECDSA-SHA256.

### KMS-04.2 — Verification

**Status:** ✅ COMPLETE

**Verified semantics:**

- valid signature → `{"valid": true}` (200)
- cryptographically invalid / tampered signature → `{"valid": false}` (200), audit `KEY_VERIFY` `INVALID`
- invalid input / unsupported operation → HTTP error

**Endpoint:** `POST /v1/phase1/keys/{object_id}/verify`.

### KMS-04.3 — Operation Policy

**Status:** ✅ COMPLETE

Centralized in `RegistryService.ALLOWED_OPERATIONS` (role → permitted operations) and enforced via `validate_operation()`. Signature/algorithm compatibility is enforced via `ALLOWED_ALGORITHMS` + `validate_signing_algorithm()`.

| Role | Operations |
|------|-----------|
| CSCA | `CERTIFICATE_SIGN`, `CRL_SIGN` |
| DS | `DOCUMENT_SIGN` (not CRL-signing) |
| CVCA | `CV_CERTIFICATE_SIGN` |

---

## KMS-05 — Authorization & Security Boundary

### KMS-05.1 — Management Plane

**Status:** ✅ COMPLETE

Admin-only (`require_admin_auth`): generate, register, retire, certificate import/update/delete/inventory/query, integrity diagnostics.

### KMS-05.2 — Cryptographic Plane

**Status:** ✅ COMPLETE

API-token access (`require_api_auth`): sign, verify. API token ≠ management authorization — crossing planes returns 401.

### KMS-05.3 — Authentication Failure Consistency

**Status:** ✅ COMPLETE

Standardized and verified:

| Case | Status | Verified |
|------|--------|----------|
| missing credentials | 401 | ✅ |
| invalid credentials | 401 | ✅ |
| wrong authorization domain | 401 | ✅ |
| unknown resource | 404 | ✅ |
| invalid operation | 400 | ✅ (moved out of pydantic `Literal`, enforced by service with audit) |
| cryptographically invalid signature | 200 `valid=false` | ✅ |

This prevents accidental information leaks through inconsistent errors.

---

## KMS-06 — Audit

### KMS-06.1 — Key Events

Audit:

- `KEY_GENERATE`
- `KEY_REGISTER`
- `KEY_RETIRE`
- `KEY_SIGN`
- `KEY_VERIFY`

### KMS-06.2 — Certificate Events

Add:

- `CERT_IMPORT`
- `CERT_UPDATE`
- `CERT_DELETE`
- `CERT_BIND`

Each event should contain metadata such as:

- `timestamp`
- `event`
- `key_id` / `certificate_id`
- `object_id`
- `role`
- `algorithm`
- `operation`
- `result`
- `reason`

**Never:**

- private key
- PIN
- API token
- secret
- signature material

---

## KMS-07 — Integrity & Recovery

### KMS-07.1 — Registry/HSM Consistency

**Status:** ✅ COMPLETE

Formal health check `GET /v1/phase1/integrity` (admin-only, read-only):

```text
registry ↔ HSM
```

Implemented as `RegistryService.check_integrity()` and covers keys and
certificates:

- `MISSING_HSM_KEY` — registered key object absent from the HSM
- `KEY_ALGORITHM_MISMATCH` — registered algorithm differs from the HSM object
- `KEY_PARAMETER_MISMATCH` — registered RSA bits / EC curve differ
- `MISSING_PRIVATE_KEY` — HSM object has no private key
- `MISSING_HSM_CERTIFICATE` / `UNREFERENCED_CERTIFICATE` / `DUPLICATE_REFERENCE`
- `CERTIFICATE_POLICY_VIOLATION` / `UNPARSEABLE_CERTIFICATE`

### KMS-07.2 — Startup Integrity Check

**Status:** ✅ COMPLETE

At application startup (`lifespan` → `run_startup_integrity_check()`):

- detects missing registered HSM keys, missing referenced certificates,
  mismatched key/certificate pairs, invalid registry records
- **FAIL CLOSED** for cryptographic operations when an ACTIVE registered
  key's HSM object is missing: `validate_key()` raises `IntegrityError`
  → 503 until the operator resolves the issue
- state exposed via `/health` (`fail_closed`, `integrity_issues`)

Verified: a synthetic ACTIVE key referencing a ghost HSM object triggers
fail-closed; every key (including healthy ones) is refused while failed
closed. Live HSM (no critical issue) runs normally.

### KMS-07.3 — Recovery Procedures

**Status:** ✅ COMPLETE (procedures defined; no automatic repair)

Safe recovery procedures — **no automatic deletion of HSM objects**:

- **Certificate loss** — re-import the certificate from a trusted backup
  under the same object ID, then re-run `check_integrity()`; binding is
  preserved because registry references survive.
- **Registry corruption** — restore the sqlite registry from backup;
  `check_integrity()` reconciles the restored metadata against the HSM.
  Never delete HSM objects to make the registry "match".
- **HSM restart / application restart** — both are idempotent; the
  startup integrity check re-evaluates and either clears or re-asserts
  fail-closed.
- **Retired keys** — remain in the registry with `RETIRED` status and
  their bindings intact; they cannot sign and their certificates cannot
  be deleted while referenced.
- **Orphaned certificates** — reported by the diagnostic (`UNREFERENCED_CERTIFICATE`);
  deletion is an operator decision, never automatic.

---

## KMS-08 — Production Hardening

### KMS-08.1 — Transaction / Mutation Safety

**Status:** ✅ COMPLETE

Every mutation follows the mandated order — validate → HSM op → verify → commit registry:

- **Key registration** (`register_hsm_key`): HSM object verified first (private key present, algorithm/params derived), certificate validated via policy, only then the registry row is inserted.
- **Certificate binding update** (`update_certificate`): certificate existence, public-key match, validity and role policy all validated before `registry.update_certificate()` runs. A failed validation leaves the existing binding untouched.
- **Certificate deletion** (`delete_certificate`): reference check before the HSM destroy; no registry mutation involved.

The forbidden order (registry mutation → HSM op → failure) never occurs.

### KMS-08.2 — Concurrency

**Status:** ✅ COMPLETE

**Problem found and fixed:** parallel HSM operations on the single-slot Pico HSM
contended for the one token over PC/SC, causing deadlocks (requests hung, opaque
503s). Added a process-wide reentrant lock (`_hsm_lock` + `@_hsm_locked`) around
every HSM access, serializing operations.

**Verified:**

- concurrent sign x4 / x8 / x12 → 100% success (12/12 with a 90s client timeout)
- concurrent verify, certificate update, registration, retirement all correct
- sign vs retire race: retired key correctly refused

Trade-off: on this development token, ~2.5s/op serialization is the safe bound.

### KMS-08.3 — Error Sanitization

**Status:** ✅ COMPLETE

Production API never exposes PKCS#11 internals, filesystem paths, Python
tracebacks, private-key attributes, HSM session details or credentials:

- unexpected internal failures raise a generic `503 {"detail":"internal error"}`
  via `_internal_error()` (real error logged server-side only)
- deliberate business errors (invalid input, policy violations) remain
  informative 400/404 messages
- audit `reason` fields may carry detail but are log-only, never in responses
- `/health` no longer echoes exception text on the degraded path

Verified: duplicate generation returns the clean `object_id already exists`
400; no raw PKCS#11 or traceback text appears in any response.

---

## KMS-09 — Final Production Readiness

**Status:** ✅ COMPLETE

Full regression suite executed against the live HSM — 31 checks across
C.23–C.27 and KMS-01–KMS-08:

- C.23 client/error handling: missing/invalid/wrong-domain credentials, unknown resources
- C.24 API authentication: admin vs API token plane separation
- C.26 RSA/EC algorithm enforcement: cross-algorithm and operation-policy denials
- C.27 / KMS-01 key lifecycle: generate → register → retire → sign-after-retire refused
- KMS-02 certificate management: query, bind, mismatch rejection, referenced-delete denial, inventory diagnostics
- KMS-03 generation: duplicate/bad-parameter rejection
- KMS-04 crypto: sign/verify, valid → `valid:true`, tampered → `valid:false`, bad Base64
- KMS-05 boundaries, KMS-07 integrity (not fail-closed on live), KMS-08 sanitization (no internals leaked)

End-to-end flow validated: fresh installation → HSM initialization → key
generation → registration → certificate import/binding → sign → verify →
retire → restart → integrity check → audit verification.

**Device note:** RSA-2048 generation takes ~51s on the Pico HSM and the
single-slot token can become unresponsive to PC/SC under sustained load;
a server restart recovers. The in-process lock serializes app-level HSM
access (KMS-08.2); the residual is device-level.

---

## Recommended Immediate Sequence

| ID | Item | Status |
|----|------|--------|
| KMS-02.6 | Certificate Binding Integrity | ✅ |
| KMS-02.7 | Certificate Validation Policy | ✅ |
| KMS-02.8 | Certificate Inventory Consistency | ✅ |
| KMS-03.1 | RSA Generation | ✅ |
| KMS-03.2 | EC Generation | ✅ |
| KMS-03.3 | Key Registration | ✅ |
| KMS-04.1 | Signing | ✅ |
| KMS-04.2 | Verification | ✅ |
| KMS-04.3 | Operation Policy | ✅ |
| KMS-05 | Authorization hardening | ✅ |
| KMS-06 | Audit expansion | ✅ |
| KMS-07 | Integrity/recovery | ✅ |
| KMS-08 | Production hardening | ✅ |
| KMS-09 | Final readiness | ✅ |

**The roadmap is fully executed.** KMS-02.6 → KMS-09 have all been
implemented and verified against the live HSM.

