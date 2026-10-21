# verifier-core _(@interop/verifier-core)_

[![Build status](https://img.shields.io/github/actions/workflow/status/interop-alliance/verifier-core/ci.yml?branch=main)](https://github.com/interop-alliance/verifier-core/actions?query=workflow%3ACI)
[![NPM Version](https://img.shields.io/npm/v/@interop/verifier-core.svg)](https://npm.im/@interop/verifier-core)

> Verifies W3C Verifiable Credentials in the browser, Node.js, and React Native.

## Table of Contents

- [Overview](#overview)
- [API](#api)
  - [verifyCredential](#verifycredential)
  - [verifyPresentation](#verifypresentation)
  - [createVerifier (batch / repeated verification)](#createverifier-batch--repeated-verification)
  - [Network policy of the built-in HTTP service](#network-policy-of-the-built-in-http-service)
- [Custom Suites](#custom-suites)
- [Per-suite summaries](#per-suite-summaries)
- [Capturing timing data](#capturing-timing-data)
- [Pluggable clock (TimeService)](#pluggable-clock-timeservice)
- [Open Badges 3.0 verification (opt-in submodule)](#open-badges-30-verification-opt-in-submodule)
- [Credential recognition + two-pass verification](#credential-recognition--two-pass-verification)
- [Architecture](#architecture)
- [Migration from earlier 1.0.0-beta.x](#migration-from-earlier-100-betax)
- [Install](#install)
- [Contribute](#contribute)
- [License](#license)

## Overview

Verifies the following versions of W3C Verifiable Credentials:

- [1.0](https://www.w3.org/TR/2019/REC-vc-data-model-20191119/)
- [1.1](https://www.w3.org/TR/2022/REC-vc-data-model-20220303/)
- [2.0](https://www.w3.org/TR/vc-data-model-2.0/)

Supports the
[eddsa-rdfc-2022](https://github.com/digitalbazaar/eddsa-rdfc-2022-cryptosuite)
and [ecdsa-rdfc-2019](https://www.w3.org/TR/vc-di-ecdsa/) (P-256/P-384 Multikey)
Data Integrity Proof cryptosuites, and the
[ed25519-signature-2020 Linked Data Proof](https://github.com/digitalbazaar/ed25519-signature-2020)
cryptosuites.

Verification runs an ordered pipeline of **suites**, each containing one or more
**checks**:

| Suite           | Phase           | What it checks                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Fatal? |
| --------------- | --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| **Core**        | `cryptographic` | `@context` exists, VC context URI present, credential ID valid, proof exists                                                                                                                                                                                                                                                                                                                                                                                        | Yes    |
| **Recognition** | `recognition`   | Pluggable credential-profile recognition; produces a normalized credential form (no-op when no recognizers configured)                                                                                                                                                                                                                                                                                                                                              | No     |
| **Proof**       | `cryptographic` | Cryptographic signature verification. Every proof of a proof set that a registered suite can check must verify. A non-fatal `proof.unsupported-proofs` check warns about proofs no suite could check. `proof.validity-period` judges the credential's validity dates; it is fatal but does not halt later checks.                                                                                                                                                   | Yes    |
| **Status**      | `cryptographic` | Revocation/suspension via BitstringStatusList -- sole owner of status verification. The list credential's proof is checked with the configured `cryptoServices`. A non-fatal `status.list-issuer` check then reports a list not issued by the credential's issuer; its skips carry a `code` from `STATUS_LIST_ISSUER_SKIP_CODES`. `status.bitstring` is fatal but does not halt, so the list issuer and any later suites are still reported after a status failure. | Yes    |
| **Registry**    | `trust`         | Issuer DID lookup in known trust registries                                                                                                                                                                                                                                                                                                                                                                                                                         | No     |

The **Phase** column drives the optional `phases:` filter on `VerifierConfig`
and per-call args, used for
[two-pass verification](#credential-recognition--two-pass-verification).

Open Badges 3.0 verification lives in the opt-in submodules
[`@interop/verifier-core/openbadges` and `@interop/verifier-core/openbadges/schema`](#open-badges-30-verification-opt-in-submodule)
and is not part of the default suite list.

The result doesn't make a single "valid/invalid" judgment. It returns the
outcome of every check, letting consumers decide what matters for their use
case. A credential with a revoked status will fail (`verified: false`) — that's
an issuer-asserted state we can't ignore — but other distinctions, like an
unregistered issuer (the registry might just not be up to date), are surfaced as
non-fatal results for the consumer to weigh.

### Trust Registries

Registry checks look up the credential's issuer DID in known registries. The DCC
publishes a list of known registries:

```
https://digitalcredentials.github.io/dcc-known-registries/known-did-registries.json
```

Fetch and pass it to verification:

```typescript
const response = await fetch(
  'https://digitalcredentials.github.io/dcc-known-registries/known-did-registries.json'
);
const registries = await response.json();

const result = await verifyCredential({ credential, registries });
```

For OpenID Federation (`oidf`) registries, both the trust anchor's entity
configuration and the issuer's subordinate statement are signature-verified
(ES256 or EdDSA), with their `iss`, `sub` and `exp` checked. Trust is rooted in
the HTTPS fetch of the configured `trustAnchorEC`; there are no pinned anchor
keys. A registry that cannot be checked, because it is unreachable or serves a
statement that does not verify, is reported as unchecked (`REGISTRY_UNCHECKED`)
rather than as "not registered", and a lookup that included one is retried after
a minute rather than cached for an hour. When some registries answered and
others could not be checked, `ISSUER_NOT_REGISTERED` says how many answered, and
a `REGISTRY_UNCHECKED` problem names the rest. The ES256 path verifies through
WebCrypto, so React Native needs a WebCrypto polyfill for it.

#### What the registry check returns

Whenever the lookup ran, the `registry.issuer` outcome carries a
`RegistryCheckPayload`, on success and on failure alike. Read that rather than
parsing the outcome's `message`, which is display text and will not survive a
registry name containing `, `.

```typescript
interface RegistryReference {
  name: string;
  type: 'oidf' | 'dcc-legacy' | 'vc-recognition';
  url: string;
}

interface RegistryCheckPayload {
  /** Registries that listed the issuer, in configured order. */
  matches: Array<{
    registry: RegistryReference;
    /** The registry's own record of the issuer, when it has one. */
    entity?: { name?: string; url?: string; raw?: unknown };
  }>;
  /** Registries that could not be reached or did not answer usefully. */
  uncheckedRegistries: RegistryReference[];
}
```

A lookup stops at the first registry that matches, so `matches` normally holds
at most one entry; only a lookup run with `exhaustive: true` returns more. A
registry's `url` is where it is read from: the list URL for `dcc-legacy` and
`vc-recognition`, and the trust anchor's entity configuration (`trustAnchorEC`)
for `oidf`.

`entity` is the registry's description of the issuer, not the credential's
description of itself, so it is the display name to prefer. The credential
cannot alter it. `dcc-legacy` and `vc-recognition` registries populate it;
`oidf` matches carry no `entity` yet. For `vc-recognition`, `name` and `url`
appear only when the matching `credentialSubject` entry holds them as strings,
and `raw` is that whole entry.

```typescript
const outcome = result.results.find(
  r => r.id === 'trust.registry.issuer'
)?.outcome;
const payload = outcome?.payload as RegistryCheckPayload | undefined;
const displayName = payload?.matches[0]?.entity?.name;
```

A custom handler passed via `registryHandlers` can supply an `entity` on its
`found` result (see `HandlerResult`), and the lookup passes it through.

> [!CAUTION] The DCC registry list does not make claims about the registries it
> contains. It is a list of registries that the DCC knows about — it says
> nothing about the quality, meaning, or value of credentials issued by anyone
> in those registries.

## API

### verifyCredential

```typescript
import { verifyCredential } from '@interop/verifier-core';

const result = await verifyCredential({
  credential, // The VC to verify (any version, passed as unknown)
  registries // Optional: issuer trust registries
});
```

#### Options

```typescript
interface VerifyCredentialOptions {
  credential: unknown;
  registries?: EntityIdentityRegistry[];
  additionalSuites?: VerificationSuite[];

  // Pipeline controls:
  recognizers?: RecognizerSpec[]; // See "Credential recognition + two-pass verification"
  phases?: SuitePhase[]; // See "Two-pass verification"
  timing?: boolean; // Per-check / per-suite timing instrumentation

  // Service overrides (otherwise sensible defaults are used):
  httpGetService?: HttpGetService; // See "Network policy of the built-in HTTP service"
  cacheService?: CacheService;
  cryptoServices?: CryptoService[];
  registryHandlers?: RegistryHandlerMap;
  documentLoader?: DocumentLoader;
  timeService?: TimeService; // See "Pluggable clock (TimeService)"
}
```

Only `credential` is required. All other fields override sensible defaults
(security-document-loader, Ed25519 + EdDSA + ECDSA crypto suites, in-memory
cache). The default document loader resolves `did:key`, `did:web` and
`did:webvh` DIDs, fetching `did:web` documents and `did:webvh` logs through
`httpGetService`. The configured `cryptoServices` verify presentation proofs,
credential proofs, and the proofs on BitstringStatusListCredentials fetched
during a status check. `VerifyCredentialOptions` is the type alias
`VerifierConfig & VerifyCredentialCall`, so callers building the options object
piece-by-piece can compose against either half.

#### Result

```typescript
interface CredentialVerificationResult {
  verified: boolean;
  verifiableCredential: VerifiableCredential;
  results: CheckResult[];
  summary: SuiteSummary[];
}
```

`verified` is `true` when no check marked `fatal` returned a failure. Non-fatal
failures (for example `recognition.profile` or `registry.issuer`) leave it
`true`. They still appear in `results[]` and in `summary[].status` and `counts`.
`results` carries every check: the ones that ran, the ones that were skipped
(with a reason), and the ones not run after a fatal failure. `summary` provides
the per-suite rollup (see [Per-suite summaries](#per-suite-summaries)). Each
`CheckResult` is identified by its namespaced `id`, populated by `runSuites`,
and carries its `suite` id.

Each `CheckResult` contains a discriminated `CheckOutcome`:

```typescript
type CheckOutcome =
  | { status: 'success'; message: string; payload?: unknown }
  | { status: 'failure'; problems: ProblemDetail[] }
  | { status: 'skipped'; reason: string };
```

Failures carry one or more `ProblemDetail` entries (inspired by
[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)):

```typescript
interface ProblemDetail {
  type: string; // URI identifying the problem
  title: string; // Short human-readable summary
  detail: string; // Specific explanation of this occurrence
}
```

#### Example: Successful verification

```json
{
  "verified": true,
  "verifiableCredential": { "...parsed credential..." },
  "results": [
    { "id": "cryptographic.core.context-exists", "suite": "core", "outcome": { "status": "success", "message": "Credential has a valid @context property." } },
    { "id": "cryptographic.core.vc-context", "suite": "core", "outcome": { "status": "success", "message": "..." } },
    { "id": "cryptographic.core.vc-structure", "suite": "core", "outcome": { "status": "success", "message": "..." } },
    { "id": "cryptographic.core.credential-id", "suite": "core", "outcome": { "status": "success", "message": "..." } },
    { "id": "cryptographic.core.proof-exists", "suite": "core", "outcome": { "status": "success", "message": "..." } },
    { "id": "recognition.profile", "suite": "recognition", "outcome": { "status": "skipped", "reason": "no recognizers configured" } },
    { "id": "cryptographic.proof.signature", "suite": "proof", "outcome": { "status": "success", "message": "Signature verified successfully." } },
    { "id": "cryptographic.proof.unsupported-proofs", "suite": "proof", "fatal": false, "outcome": { "status": "success", "message": "Every proof was checked." } },
    { "id": "cryptographic.proof.validity-period", "suite": "proof", "outcome": { "status": "success", "message": "The credential is within its validity period." } },
    { "id": "trust.registry.issuer", "suite": "registry", "outcome": { "status": "success", "message": "Issuer found in registry: DCC Sandbox Registry", "payload": { "matches": [ { "registry": { "name": "DCC Sandbox Registry", "type": "dcc-legacy", "url": "https://digitalcredentials.github.io/sandbox-registry/registry.json" }, "entity": { "name": "Example University", "url": "https://example.edu", "raw": { "name": "Example University", "url": "https://example.edu" } } } ], "uncheckedRegistries": [] } } },
    { "id": "cryptographic.status.bitstring", "suite": "status", "outcome": { "status": "success", "message": "Credential status is valid (not revoked or suspended)." } },
    { "id": "cryptographic.status.list-issuer", "suite": "status", "fatal": false, "outcome": { "status": "success", "message": "Every status list is issued by the credential's issuer." } }
  ]
}
```

#### Example: Invalid signature (fatal)

An invalid signature is fatal — it means any part of the credential could have
been tampered with, so every later check for the credential, in any suite, is
halted. Each check that would have run appears as `skipped` with code
`NOT_RUN_AFTER_FATAL`, `haltedBy` naming the failed check, and reason
`Not run: <check-id> failed`.

```json
{
  "verified": false,
  "results": [
    {
      "id": "cryptographic.core.context-exists",
      "suite": "core",
      "outcome": { "status": "success", "message": "..." }
    },
    {
      "id": "cryptographic.core.proof-exists",
      "suite": "core",
      "outcome": { "status": "success", "message": "..." }
    },
    {
      "id": "cryptographic.proof.signature",
      "suite": "proof",
      "outcome": {
        "status": "failure",
        "problems": [
          {
            "type": "https://www.w3.org/TR/vc-data-model#INVALID_SIGNATURE",
            "title": "Invalid Signature",
            "detail": "The signature is not valid."
          }
        ]
      }
    },
    {
      "id": "cryptographic.proof.unsupported-proofs",
      "suite": "proof",
      "fatal": false,
      "outcome": {
        "status": "skipped",
        "code": "NOT_RUN_AFTER_FATAL",
        "haltedBy": "proof.signature",
        "reason": "Not run: proof.signature failed"
      }
    },
    {
      "id": "cryptographic.proof.validity-period",
      "suite": "proof",
      "outcome": {
        "status": "skipped",
        "code": "NOT_RUN_AFTER_FATAL",
        "haltedBy": "proof.signature",
        "reason": "Not run: proof.signature failed"
      }
    },
    {
      "id": "trust.registry.issuer",
      "suite": "registry",
      "outcome": {
        "status": "skipped",
        "code": "NOT_RUN_AFTER_FATAL",
        "haltedBy": "proof.signature",
        "reason": "Not run: proof.signature failed"
      }
    },
    {
      "id": "cryptographic.status.bitstring",
      "suite": "status",
      "outcome": {
        "status": "skipped",
        "code": "NOT_RUN_AFTER_FATAL",
        "haltedBy": "proof.signature",
        "reason": "Not run: proof.signature failed"
      }
    }
  ]
}
```

#### Example: Revoked credential (fatal, sourced from status)

When a credential's status list marks it revoked or suspended (or the verifier
can't confidently evaluate the list (missing, expired, wrong type, signature
invalid), the status suite fails the credential. The proof and registry checks
still pass on their own merits. `status.bitstring` is fatal but does not halt
(`halts: false`). The credential is authentic by then, so `status.list-issuer`
still reports who signed the list, and caller-added suites still run.

```json
{
  "verified": false,
  "results": [
    {
      "id": "cryptographic.core.context-exists",
      "suite": "core",
      "outcome": { "status": "success", "message": "..." }
    },
    {
      "id": "cryptographic.proof.signature",
      "suite": "proof",
      "outcome": {
        "status": "success",
        "message": "Signature verified successfully."
      }
    },
    {
      "id": "trust.registry.issuer",
      "suite": "registry",
      "outcome": { "status": "success", "message": "..." }
    },
    {
      "id": "cryptographic.status.bitstring",
      "suite": "status",
      "outcome": {
        "status": "failure",
        "problems": [
          {
            "type": "https://www.w3.org/TR/vc-data-model#CREDENTIAL_REVOKED",
            "title": "Credential Revoked",
            "detail": "The status list https://example.edu/status/3 marks the credential revoked (index 94567)."
          }
        ]
      }
    },
    {
      "id": "cryptographic.status.list-issuer",
      "suite": "status",
      "fatal": false,
      "outcome": {
        "status": "success",
        "message": "Every status list is issued by the credential's issuer."
      }
    }
  ]
}
```

#### Example: Expired credential (fatal, does not halt)

An authentic credential outside its validity period passes `proof.signature` and
fails `proof.validity-period` with `CREDENTIAL_EXPIRED` or
`CREDENTIAL_NOT_YET_VALID`. The check is fatal, so `verified` is false. It does
not halt, so the registry, status and caller-added checks still run. A tampered
credential is reported as `INVALID_SIGNATURE` whatever its dates.

```json
{
  "id": "cryptographic.proof.validity-period",
  "suite": "proof",
  "fatal": true,
  "halts": false,
  "outcome": {
    "status": "failure",
    "problems": [
      {
        "type": "https://www.w3.org/TR/vc-data-model#CREDENTIAL_EXPIRED",
        "title": "Credential Expired",
        "detail": "Validity ended at 2011-01-01T00:00:00Z (validUntil). Verified at 2026-10-21T12:00:00.000Z."
      }
    ]
  }
}
```

#### Example: Proof set

A credential or presentation may carry several proofs. Each is verified on its
own, and every proof a registered suite can check must verify. One failing proof
fails `proof.signature`, and its problem names the proof:

```json
{
  "type": "https://www.w3.org/TR/vc-data-model#INVALID_SIGNATURE",
  "title": "Invalid Signature",
  "detail": "Proof 2 of 2 (DataIntegrityProof, eddsa-rdfc-2022): Invalid signature."
}
```

A proof that no registered suite supports, or that was made for a different
proof purpose, does not fail the signature when another proof verified. The
non-fatal `proof.unsupported-proofs` check reports it with a `PROOF_UNSUPPORTED`
problem per proof, for example "Proof 2 of 2 (DataIntegrityProof, bbs-2023):
This verifier does not support this proof's cryptosuite." When no proof could be
checked at all, `proof.signature` fails with `PROOF_UNSUPPORTED`. Status list
credentials follow the same rule: a list with one bad proof is a
`STATUS_LIST_SIGNATURE_ERROR`.

#### Example: Check skipped

Checks skip when they're irrelevant to the input. For instance, a credential
with no `credentialStatus` skips the status check:

```json
{
  "id": "cryptographic.status.bitstring",
  "suite": "status",
  "outcome": {
    "status": "skipped",
    "reason": "Credential has no credentialStatus."
  }
}
```

#### Error taxonomy

All failures use `ProblemDetail` with a `type` URI. Common error types:

| Type URI                          | Title                                                                                     | When                                                                                                                    |
| --------------------------------- | ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `...#PARSING_ERROR`               | Credential Parsing Failed / Presentation Parsing Failed / Invalid JSON-LD / No VC Context | Envelope gate or context problems                                                                                       |
| `...#MALFORMED_VALUE_ERROR`       | Invalid Credential Structure / Invalid Presentation Structure                             | A VC Data Model structure rule is broken; `instance` points at the field                                                |
| `...#INVALID_SIGNATURE`           | Invalid Signature                                                                         | Signature doesn't match content                                                                                         |
| `...#CREDENTIAL_EXPIRED`          | Credential Expired                                                                        | `validUntil` / `expirationDate` has passed; reported by `proof.validity-period` once the signature verified             |
| `...#CREDENTIAL_NOT_YET_VALID`    | Credential Not Yet Valid                                                                  | `validFrom` / `issuanceDate` is in the future; reported by `proof.validity-period` once the signature verified          |
| `...#PROOF_UNSUPPORTED`           | Unsupported Proof                                                                         | No registered suite supports the proof, or it was made for another purpose; a warning beside a proof that verified      |
| `...#PROOF_PURPOSE_MISMATCH`      | Challenge Mismatch / Domain Mismatch                                                      | VP proof does not bind to the caller's challenge or domain                                                              |
| `...#VERIFICATION_METHOD_ERROR`   | Verification Method Error                                                                 | Proof's key is not listed by its controller, not authorized for the purpose, or names a fragment the DID document lacks |
| `...#DID_WEB_UNRESOLVED`          | DID Web Unresolved                                                                        | DID document (e.g. `did:web`) or `did:webvh` log couldn't be fetched                                                    |
| `...#HTTP_ERROR`                  | HTTP Error                                                                                | Network error during signature check                                                                                    |
| `...#CREDENTIAL_REVOKED`          | Credential Revoked                                                                        | A revocation status list has the credential's bit set; one per entry                                                    |
| `...#CREDENTIAL_SUSPENDED`        | Credential Suspended                                                                      | A suspension status list has the credential's bit set; one per entry                                                    |
| `...#STATUS_LIST_NOT_FOUND`       | Status List Not Found                                                                     | Status list URL unreachable                                                                                             |
| `...#STATUS_LIST_EXPIRED`         | Status List Expired                                                                       | Status list VC has expired (v1 or v2 dates); its signature verified                                                     |
| `...#STATUS_LIST_NOT_YET_VALID`   | Status List Not Yet Valid                                                                 | Status list VC is not yet valid (v1 or v2 dates); its signature verified                                                |
| `...#STATUS_LIST_SIGNATURE_ERROR` | Status List Signature Error                                                               | Status list VC signature invalid                                                                                        |
| `...#STATUS_LIST_ISSUER_MISMATCH` | Status List Issuer Mismatch                                                               | Status list `issuer` differs from the credential's; non-fatal warning                                                   |
| `...#ISSUER_NOT_REGISTERED`       | Issuer Not Registered                                                                     | Issuer DID not found in any registry that could be checked                                                              |
| `...#REGISTRY_UNCHECKED`          | Registry Unchecked                                                                        | Some or all registries couldn't be reached; alone when none could                                                       |

#### Problem types

Every built-in problem URI is also exported as a constant. Branch on the const
map for type-safe checks:

```typescript
import { ProblemTypes, type ProblemType } from '@interop/verifier-core';

switch (problem.type as ProblemType) {
  case ProblemTypes.INVALID_SIGNATURE:
    // ...
    break;
  case ProblemTypes.CREDENTIAL_REVOKED:
  case ProblemTypes.CREDENTIAL_SUSPENDED:
    // ...
    break;
  case ProblemTypes.STATUS_LIST_NOT_FOUND:
    // ...
    break;
  // ...
}
```

`ProblemDetail.type` stays typed as `string` so custom suites can emit their own
problem URIs; the cast above is opt-in for callers that only need to branch on
built-in types. See the per-token JSDoc on `ProblemTypes` for which entries are
W3C-spec error identifiers (`PARSING_ERROR`, `MALFORMED_VALUE_ERROR`) and which
are synthesized placeholders we use until a wider problem-type vocabulary is
published.

### verifyPresentation

```typescript
import { verifyPresentation } from '@interop/verifier-core';

const result = await verifyPresentation({
  presentation, // The VP to verify
  challenge: 'abc123', // Optional: expected challenge
  domain: 'verifier.example', // Optional: expected domain (requires challenge)
  unsignedPresentation: false, // Optional: accept a VP with no proof
  registries // Optional: issuer trust registries
});
```

#### Options

```typescript
interface VerifyPresentationOptions {
  presentation: unknown;
  challenge?: string | null;
  domain?: string;
  unsignedPresentation?: boolean;
  registries?: EntityIdentityRegistry[];
  additionalSuites?: VerificationSuite[];

  // Pipeline controls:
  recognizers?: RecognizerSpec[]; // See "Credential recognition + two-pass verification"
  phases?: SuitePhase[]; // See "Two-pass verification"
  timing?: boolean; // Per-check / per-suite timing instrumentation

  // Service overrides (otherwise sensible defaults are used):
  httpGetService?: HttpGetService; // See "Network policy of the built-in HTTP service"
  cacheService?: CacheService;
  cryptoServices?: CryptoService[];
  registryHandlers?: RegistryHandlerMap;
  documentLoader?: DocumentLoader;
  timeService?: TimeService; // See "Pluggable clock (TimeService)"
}
```

Like `VerifyCredentialOptions`, this is the alias
`VerifierConfig & VerifyPresentationCall`. The same `cryptoServices` that verify
the presentation also verify each embedded credential and any status list
credentials those credentials name.

#### Result

```typescript
interface PresentationVerificationResult {
  verified: boolean;
  verifiablePresentation: VerifiablePresentation;
  presentationResults: CheckResult[];
  credentialResults: CredentialVerificationResult[];
  summary: SuiteSummary[];
  // No allResults — use flattenPresentationResults(result)
}
```

`presentationResults` and each embedded `credentialResults[i].results` follow
the same shape as `verifyCredential`'s `results`, listing every check. The
top-level `summary` rolls up the VP envelope's own suites; per-credential
rollups live on `credentialResults[i].summary`.

Presentation verification does two things:

1. **Verifies the VP itself** — checks the presentation's structure
   (`core.vp-structure`), then its own proof only. A VP with no proof fails
   unless `unsignedPresentation: true`, in which case the check is skipped. A
   proof that is present is always verified. When `challenge` is passed, the
   presentation's proof must use the `authentication` purpose and carry that
   challenge (and `domain`, if passed); a mismatch is reported as
   `PROOF_PURPOSE_MISMATCH`. A proof made for another purpose is not checked and
   is reported as `PROOF_UNSUPPORTED`. In a proof set that is a warning beside
   an `authentication` proof that verified, and fatal when it is the only proof.
   Without a challenge only the signatures are checked. A `domain` without a
   `challenge`, or an empty-string `challenge`, is rejected before any check
   runs. Results go in `presentationResults`.
2. **Verifies each embedded credential** — extracts credentials from the VP and
   runs `verifyCredential` on each. Results go in `credentialResults`.

`verified` is `true` only if both the presentation and all embedded credentials
pass.

The parsed VP is returned as `verifiablePresentation`, mirroring the wire-level
property name so callers (and downstream systems whose templates reach into
result objects by property path) can reach it without carrying the original
input separately.

A VP needn't be signed — it can simply package credentials together. Set
`unsignedPresentation: true` to accept a VP that has no proof. Its
`proof.signature` check is then skipped with
`code: SIGNATURE_SKIP_CODES.unsignedPresentation`. The flag does not turn off
verification of a proof that is present.

#### Flattening results

When you want a single iterable view of every check that ran across the
presentation and its embedded credentials, use `flattenPresentationResults`:

```typescript
import { flattenPresentationResults } from '@interop/verifier-core';

const result = await verifyPresentation({ presentation });
for (const entry of flattenPresentationResults(result)) {
  if (entry.source === 'presentation') {
    // entry.result is a CheckResult from VP-level verification
  } else {
    // entry.source === 'credential'
    // entry.credentialIndex is the index into result.credentialResults
    // entry.result is a CheckResult from that embedded VC
  }
}
```

Each entry preserves provenance — you always know whether a check applied to the
presentation itself or to a specific embedded credential, by index.

### createVerifier (batch / repeated verification)

`verifyCredential` and `verifyPresentation` are convenient one-shot wrappers —
each call builds a fresh verifier internally. When you'll perform more than one
verification, construct a `Verifier` with `createVerifier(...)` and reuse it for
better performance. The instance owns long-lived dependencies (HTTP, cache,
crypto services, document loader, registries), so issuer DID documents, status
list credentials, and JSON-LD contexts are fetched once and reused across calls.

Each verifier owns its own `InMemoryCacheService` by default; cache contents are
isolated from other verifiers in the same process. To share cache state across
verifiers, construct one cache adapter and pass it to each
`createVerifier({ cacheService })`.

The `cryptoServices` passed to `createVerifier` are the complete and only set
that governs proof verification — for presentations, credentials, and the
BitstringStatusListCredentials fetched during a status check.

```typescript
import { createVerifier } from '@interop/verifier-core';

const verifier = createVerifier({ registries });

for (const credential of batch) {
  const result = await verifier.verifyCredential({ credential });
  // ... handle result ...
}
```

The same `Verifier` is also used recursively when verifying a presentation, so
all credentials embedded in a VP share the verifier's caches automatically:

```typescript
const result = await verifier.verifyPresentation({ presentation });
```

### Network policy of the built-in HTTP service

Verification fetches URLs the credential chooses. These include JSON-LD
contexts, `did:web` documents, status lists and registries. The built-in
`BuiltinHttpGetService` applies a network policy to every fetch.

- It allows `https:` only. It refuses `http:` and other schemes, `localhost` and
  `*.localhost`, and loopback, private (10/8, 172.16/12, 192.168/16,
  carrier-grade NAT 100.64/10, and Azure's `168.63.129.16`), link-local
  (including `169.254.169.254`), multicast, reserved (192.0.0/24, 240/4) and
  unspecified addresses. This covers IPv4 and IPv6, including site-local
  `fec0::/10`. An IPv4-mapped, IPv4-compatible, NAT64 (`64:ff9b::/96`) or 6to4
  IPv6 address is judged by the IPv4 address it embeds. Hosts are judged on the
  parsed URL, so shorthand forms such as `0x7f.1` are caught.
- On Node, redirects are followed manually. The policy is applied to each hop
  before it is requested, and at most five hops are followed. Browsers and React
  Native follow redirects themselves and hide the hops. There the request is
  made with the runtime's own redirect handling, and the first URL and the URL
  actually reached are judged before the body is read. An intermediate hop is
  not checked, so the hop-by-hop protection is a server-side one.
- Each request has a 10 s deadline and a 5 MiB body cap. Change them by
  constructing the service yourself and passing it as `httpGetService`:

  ```typescript
  import {
    BuiltinHttpGetService,
    createVerifier
  } from '@interop/verifier-core';

  const verifier = createVerifier({
    httpGetService: BuiltinHttpGetService({
      timeoutMs: 20_000,
      maxBytes: 1_000_000
    })
  });
  ```

- The body is read once and parsed as JSON whatever the content type. A body
  that is not JSON is returned as text.
- Error text is fixed and never quotes the response. It names the URL and the
  reason, for example `Request to <url> refused: <reason>`,
  `Request to <url> timed out after N ms` or
  `Request to <url> exceeded N bytes`. A network error is reported as
  `Request to <url> failed`, with the original error on `cause`. The document
  loader and the did:webvh resolver report a non-JSON body as
  `response is not JSON`.

JSON-LD contexts that are not bundled are fetched under this same policy. To
verify against a closed set of contexts, pass your own `documentLoader`.

The `allowInsecure` option relaxes the URL policy only. It allows `http:` and
local or private addresses on every hop. The deadline, the byte cap and the
redirect limit still apply. Use it for local development against a server on
`localhost`. Do not enable it on a server that verifies untrusted credentials.

```typescript
const devVerifier = createVerifier({
  httpGetService: BuiltinHttpGetService({ allowInsecure: true })
});
```

Hosts are judged by name or literal only. There is no portable DNS lookup, so a
public name that resolves to a private address is not caught.

The policy applies to the built-in service only. An injected `httpGetService` or
`documentLoader` keeps its own network policy.

## Custom Suites

Extend the default pipeline with custom verification logic:

```typescript
import { verifyCredential, VerificationSuite } from '@interop/verifier-core';

const myCustomSuite: VerificationSuite = {
  id: 'custom.expiry-policy',
  name: 'Expiry Policy',
  checks: [
    {
      id: 'custom.expiry-policy.grace-period',
      name: 'Grace Period Check',
      fatal: false,
      execute: async (subject, context) => {
        const credential = subject.verifiableCredential as any;
        // Custom logic: allow 30-day grace period after expiration
        return { status: 'success', message: 'Within grace period.' };
      }
    }
  ]
};

const result = await verifyCredential({
  credential,
  additionalSuites: [myCustomSuite]
});

// result.results includes checks from both default and custom suites
```

Custom suites run after the default suites. Each check receives the same
`VerificationSubject` and `VerificationContext` as built-in checks.

A failure of a `fatal: true` check makes `verified` false and halts every later
check for the subject. Set `halts: false` on a fatal check whose failure leaves
later checks meaningful. Its failure still makes `verified` false, but later
checks run. `halts` defaults to `fatal`. The built-in `proof.validity-period`
and `status.bitstring` checks set `halts: false`, so custom suites still run for
an expired or revoked credential.

## Per-suite summaries

Each `CredentialVerificationResult` and `PresentationVerificationResult` carries
a `summary: SuiteSummary[]` rollup of per-suite outcomes next to `results[]`,
which lists every check.

```ts
const result = await verifier.verifyCredential({ credential });
// result.summary[i] = { id, phase, suite, status, verified, message, counts, ... }
// result.results[]  = every check that ran, was skipped, or was not run
```

Render from `summary[]` and expand into `results[]` for per-check detail. A
summary's checks are the `results[]` rows whose `id` starts with the summary's
`id` plus a dot. Passes and skips share that prefix, so filter by
`outcome.status` as well to reach just the failures.

See [`docs/api/verification-results.md`](./docs/api/verification-results.md) for
the full reference (phase model, `SuiteSummary` fields, `id` namespace, UI
rendering recipe, and a prompt-ready appendix for downstream UIs).

## Capturing timing data

Every result can carry per-check, per-suite, and per-call `TaskTiming` data
(wall-clock `startedAt` / `endedAt` plus a monotonic `durationMs`). Off by
default; opt in via `timing: true` on `createVerifier(...)` or per-call.
Per-call wins, and `verifyPresentation` propagates the flag into embedded
`verifyCredential` calls so the top-level `result.timing` is an inclusive
wrapper.

```ts
const verifier = createVerifier({ timing: true });
const result = await verifier.verifyCredential({ credential });
console.log(result.timing!.durationMs);
console.log(result.summary[0].timing!.durationMs);
```

Every row in `results[]` carries its own `CheckResult.timing`, and each
`SuiteSummary.timing` rolls those up per suite. See
[`docs/api/timing.md`](./docs/api/timing.md) for the full reference, granularity
table, recipes, and a prompt-ready appendix.

## Pluggable clock (`TimeService`)

`verifier-core` reads wall-clock and monotonic time through a small
`TimeService` interface. The default is `RealTimeService` (`Date.now` /
`performance.now`); pass `{ timeService: FakeTimeService() }` on
`createVerifier(...)` in tests to make every `TaskTiming` field
exact-value-assertable. Both factories are exported from the package barrel. The
same clock decides credential validity: the instant is read once per verify
call, `proof.signature` and `status.bitstring` pass it to the crypto service as
`now`, and `proof.validity-period` judges the credential's dates at it. So a
`FakeTimeService` set inside an expired credential's validity window verifies
it. Dates are compared exactly against that instant, with no clock-skew
allowance. See [`docs/api/timing.md`](./docs/api/timing.md) for the reference.

## Open Badges 3.0 verification (opt-in submodule)

Open Badges 3.0 verification ships in two opt-in submodules. Neither is part of
the default suite list. Consumers that want OB checks pass a bundled suite via
`additionalSuites` on a verify call.

- `@interop/verifier-core/openbadges` holds the semantic suite, the recognizers,
  the Zod schemas and the problem types. It loads no JSON Schema validator.
- `@interop/verifier-core/openbadges/schema` holds JSON Schema validation:
  `openBadgesSuite`, `openBadgesSchemaSuite`, `obv3SchemaCheck` and
  `obv3DeclaredSchemaCheck`. It loads AJV and the bundled Open Badges 3.0
  schemas.

The split matters where a bundler does not tree-shake (Metro), and under a
Content Security Policy that forbids `unsafe-eval`. AJV compiles a schema with
`new Function`, so such pages should use `openBadgesSemanticSuite` alone.

> [!IMPORTANT] If you were on `1.0.0-beta.x` and relied on `obv3SchemaSuite`
> running by default, you now need to opt in explicitly. The simplest migration
> is to add `openBadgesSuite` to your verify call.

### Enabling OB verification

```ts
import { createVerifier } from '@interop/verifier-core';
import { openBadgesSuite } from '@interop/verifier-core/openbadges/schema';

const verifier = createVerifier();
const result = await verifier.verifyCredential({
  credential,
  additionalSuites: [openBadgesSuite]
});
```

With no recognizers configured, `recognition.profile` is skipped with the reason
`no recognizers configured`. When recognizers exist but none applies, the reason
is `no recognizer matched`.

### Strict parser versus JSON Schema

The strict Zod parser behind `recognition.profile` enforces spec MUST rules that
the OB 3.0 JSON Schema cannot express. One example is AchievementSubject:
"Either id or at least one identifier MUST be supplied." So
`recognition.profile` can fail while `schema.obv3.json` passes for the same
credential.

This is deliberate. The parser is the authority on conformance. The AJV schema
check is the spec-schema baseline. Treat a parser failure as the stronger
signal.

### Bundle variants

| Bundle                    | Entry point          | Contents                                                             | Applies to                                 |
| ------------------------- | -------------------- | -------------------------------------------------------------------- | ------------------------------------------ |
| `openBadgesSuite`         | `/openbadges/schema` | Semantic checks **and** the JSON Schema checks                       | OpenBadgeCredential, EndorsementCredential |
| `openBadgesSemanticSuite` | `/openbadges`        | Cross-field semantic checks only                                     | OpenBadgeCredential                        |
| `openBadgesSchemaSuite`   | `/openbadges/schema` | JSON Schema checks only (`schema.obv3.json`, `schema.obv3.declared`) | OpenBadgeCredential, EndorsementCredential |

Inside `openBadgesSuite`, the semantic checks skip an endorsement, since its
subject is not an `AchievementSubject`.

### JSON Schema validation

`schema.obv3.json` validates a credential against the Open Badges 3.0 JSON
Schema for its type and VC version. The four schemas are copied from the spec
appendix and bundled with the package:

| Credential                      | Schema                             |
| ------------------------------- | ---------------------------------- |
| `OpenBadgeCredential`, VC 2.0   | E.2.1.2 AchievementCredential      |
| `OpenBadgeCredential`, VC 1.1   | E.2.1.34 AchievementCredentialv1p1 |
| `EndorsementCredential`, VC 2.0 | E.2.1.7 EndorsementCredential      |
| `EndorsementCredential`, VC 1.1 | E.2.1.36 EndorsementCredentialv1p1 |

Nothing is fetched. Each schema is compiled once per process, on first use. A VC
1.1 credential is checked against the strict VC 1.1-only schema. The
credential's own `credentialSchema` does not choose the schema, so an issuer
cannot swap in a permissive one.

`schema.obv3.declared` is a non-fatal report on that `credentialSchema`. Each
entry that does not fit the credential produces one problem, with `instance`
pointing at the entry:

- `OB_DECLARED_SCHEMA_MISMATCH`: a known Open Badges 3.0 schema URL for the
  other OB credential type, or one that does not accept the credential's VC
  version.
- `OB_DECLARED_SCHEMA_NOT_CHECKED`: a URL that is not a known Open Badges 3.0
  schema. It is not fetched.

The check is skipped when no `credentialSchema` is declared.

Pick `openBadgesSemanticSuite` when you want the OB-specific semantic checks
(`OB_INVALID_RESULT_REFERENCE`, `OB_INVALID_ACHIEVED_LEVEL`,
`OB_MISSING_RESULT_STATUS`, `OB_UNKNOWN_ACHIEVEMENT_TYPE`) without loading AJV
and the bundled schemas.

### Problem types

OB-specific problem URIs live on `OpenBadgesProblemTypes` (also exported as
`Obv3ProblemTypes` for symmetry with internal naming):

```ts
import {
  OpenBadgesProblemTypes,
  type OpenBadgesProblemType
} from '@interop/verifier-core/openbadges';

// In a result-handling callback...
switch (problem.type as OpenBadgesProblemType) {
  case OpenBadgesProblemTypes.OB_INVALID_RESULT_REFERENCE:
    // ...
    break;
  case OpenBadgesProblemTypes.OB_INVALID_ACHIEVED_LEVEL:
    // ...
    break;
  case OpenBadgesProblemTypes.OB_MISSING_RESULT_STATUS:
    // ...
    break;
  case OpenBadgesProblemTypes.OB_UNKNOWN_ACHIEVEMENT_TYPE:
    // ...
    break;
  case OpenBadgesProblemTypes.OB_DECLARED_SCHEMA_MISMATCH:
  case OpenBadgesProblemTypes.OB_DECLARED_SCHEMA_NOT_CHECKED:
    // ...
    break;
}
```

The wire URIs follow the `…#OB_*` shape (e.g.
`https://www.w3.org/TR/vc-data-model#OB_INVALID_ACHIEVED_LEVEL`). Callers
upgrading from `1.0.0-beta.x` who literal-matched
`OBV3_INVALID_RESULT_REFERENCE` need to update those literals to
`OB_INVALID_RESULT_REFERENCE` (or — preferred — switch to the
`OpenBadgesProblemTypes` constants).

### Caller-augmented `AchievementType` vocabulary

The default `obv3UnknownAchievementTypeCheck` validates against the OB 3.0
§B.1.1 enumeration plus the spec-sanctioned `ext:` prefix. Issuers that mint
additional vocabulary tokens (without an `ext:` prefix) can compose a custom
check that adds those tokens to the accepted set:

```ts
import {
  openBadgesSemanticSuite,
  createObv3UnknownAchievementTypeCheck
} from '@interop/verifier-core/openbadges';

const customCheck = createObv3UnknownAchievementTypeCheck({
  additionalKnownTypes: ['MyOrgInternalAchievementType']
});

const customSuite = {
  ...openBadgesSemanticSuite,
  checks: openBadgesSemanticSuite.checks.map(c =>
    c.id === 'schema.obv3.unknown-achievement-type' ? customCheck : c
  )
};

const result = await verifier.verifyCredential({
  credential,
  additionalSuites: [customSuite]
});
```

For version-pinned behavior, the `OB_3_0_ACHIEVEMENT_TYPES` set is exported
directly so callers can build their own check against an explicit OB version
rather than tracking the moving `KNOWN_ACHIEVEMENT_TYPES` alias.

## Advanced: Credential recognition + two-pass verification

`verifier-core` ships a **pluggable recognition pipeline**. Recognizers (e.g.,
`obv3p0Recognizer`, `obv3p0EndorsementRecognizer`) parse a credential's
profile-specific shape and return a normalized form. The default
`recognitionSuite` runs them in registration order and surfaces the first
applies-true match on `CredentialVerificationResult` as
`normalizedVerifiableCredential` + `recognizedProfile` — so consumers can branch
on the recognized profile and reach a typed view of the credential without
re-parsing.

### End-to-end Open Badges wiring

```ts
import { createVerifier } from '@interop/verifier-core';
import {
  obv3p0Recognizer,
  obv3p0EndorsementRecognizer
} from '@interop/verifier-core/openbadges';
import type { Obv3p0OpenBadgeCredential } from '@interop/verifier-core/openbadges';
import { openBadgesSuite } from '@interop/verifier-core/openbadges/schema';

const verifier = createVerifier({
  recognizers: [obv3p0Recognizer, obv3p0EndorsementRecognizer]
});

// One pass: full crypto + recognition + OB semantic checks.
const presResult = await verifier.verifyPresentation({
  presentation: vp,
  additionalSuites: [openBadgesSuite]
});

for (const credResult of presResult.credentialResults) {
  if (credResult.recognizedProfile === 'obv3p0.openbadge') {
    const ob =
      credResult.normalizedVerifiableCredential as Obv3p0OpenBadgeCredential;
    console.log('Achievement:', ob.credentialSubject);
  }
}
```

This is the recommended advanced integration shape for services like
`dcc-transaction-service` that verify a presentation up front and then inspect
each embedded credential's profile to drive downstream business logic. If
performance matters, you're verifying high volumes of credentials, you want to
show partial results to a user for verification in progress, or you have
specific requirements for the verification process, this advanced integration
pattern may be for you.

### Two-pass verification

When a credential has already been cryptographically verified — e.g.
re-rendering a previously-verified credential, or running deeper semantic
analysis on demand — the `phases:` filter lets you re-run only the work you
need. Phases are `'cryptographic' | 'trust' | 'recognition' | 'semantic'`;
requesting `'semantic'` automatically includes `'recognition'` so semantic
checks can consume the normalized form.

```ts
// Pass 1 (default — every phase runs): full crypto + trust + recognition + semantic.
const fullResult = await verifier.verifyCredential({
  credential,
  additionalSuites: [openBadgesSuite]
});

// Pass 2: re-run only the semantic checks (recognition is auto-included).
const semanticOnly = await verifier.verifyCredential({
  credential,
  additionalSuites: [openBadgesSuite],
  phases: ['semantic']
});
// semanticOnly.partial === true
// semanticOnly.results contains only the recognition.profile + OB semantic check entries
```

`partial: true` is set on the result whenever the consumer passed an explicit
`phases:` value, so downstream code can tell that the result covers only a
subset of the pipeline. The default (no `phases:`) leaves `partial` unset —
existing consumers see no change in result shape.

### `applies` predicate contract

A `VerificationSuite` may declare an `applies(subject, context)` predicate. The
orchestrator uses it as follows:

- **Implicit (default suite list):** if `applies` returns false, the suite is
  silently skipped — no entries in `results`.
- **Explicit (suite passed via `additionalSuites`):** if `applies` returns
  false, a synthetic `<suite-id>.applies` `'skipped'` `CheckResult` is emitted
  so the consumer sees their explicit request was acknowledged but not
  actionable.

This is what lets you queue `openBadgesSuite` against an arbitrary credential
and still get a clear signal in the result when the credential isn't an Open
Badge.

### `ProblemDetail.instance` attribution

Failure-outcome `ProblemDetail` entries from semantic and envelope checks carry
an [RFC 6901 JSON Pointer](https://datatracker.ietf.org/doc/html/rfc6901) on
`instance`, locating the offending portion of the credential — aligned with
[RFC 9457](https://datatracker.ietf.org/doc/html/rfc9457). For example, an OB
credential that names a `result.achievedLevel` not declared on the referenced
`ResultDescription` produces:

```ts
{
  type: 'https://www.w3.org/TR/vc-data-model#OB_INVALID_ACHIEVED_LEVEL',
  title: 'Invalid Achieved Level',
  detail: 'Result entry at index 0 claims achievedLevel "urn:lvl:NOT_REAL", ...',
  instance: '/credentialSubject/result/0/achievedLevel',
}
```

UI surfaces can highlight the exact field by walking the pointer.

## Architecture

For internal architecture details — verification pipeline, suite model, type
system, dependencies, and architectural direction — see
[`docs/architecture.md`](docs/architecture.md).

## Migration from earlier 1.0.0-beta.x

This release tightens the public API surface. The following changes may require
small migrations:

- **Demoted from `index.ts`** — these symbols remain reachable via their module
  paths (`@interop/verifier-core/dist/...`) but are no longer part of the
  published 1.0 surface: `runSuites`, `createRegistryLookup`, `DEFAULT_TTL_MS`,
  `parseCacheControlMaxAge`, `resolveTtl`, `ttlFromValidUntil`,
  `documentLoaderFromHttpGet`, `extractCredentialsFrom`, `registryKeyHash`. Most
  callers should build verifiers via `createVerifier(...)` rather than reach for
  these directly.

- **Result-shape changes:**
  - `CredentialVerificationResult.credential` → `verifiableCredential`
    (`s/\.credential\b/.verifiableCredential/` on accessor sites).
  - `PresentationVerificationResult.allResults` removed — replace with
    `flattenPresentationResults(result)`.
  - `PresentationVerificationResult.verifiablePresentation` added — new field
    carrying the parsed VP.

- **Default cache isolation:** two `createVerifier()` calls without an explicit
  `cacheService` no longer share a process-wide cache. To preserve the previous
  "shared" behavior, construct one `InMemoryCacheService` and pass it to each
  verifier explicitly.

- **Legacy result types removed:** `VerificationResponse`,
  `PresentationVerificationResponse`, and friends were already removed from
  `index.ts` in `1.0.0-beta.11`; the type definitions are now gone too. Anyone
  who needed the old shape can pin `1.0.0-beta.11` or earlier.

- **`ProblemTypes` const map added:** built-in problem URIs are now importable
  as `ProblemTypes.INVALID_SIGNATURE` etc. Existing literal-string comparisons
  against `ProblemDetail.type` continue to work unchanged.

- **OBv3 verification is opt-in** — the OBv3 schema suite no longer runs by
  default. Add `openBadgesSuite` (or one of its variants) via `additionalSuites`
  on the verify call to restore previous behavior. See the
  [Open Badges 3.0 verification](#open-badges-30-verification-opt-in-submodule)
  section for details.

- **OBv3 problem-type rename** — `OBV3_INVALID_RESULT_REFERENCE` (and other OB
  problems mirrored on `ProblemTypes`) moved out of the core catalog into
  `OpenBadgesProblemTypes` in the `/openbadges` submodule, and the wire URIs
  shifted from `…#OBV3_*` to `…#OB_*`. Callers comparing literal strings against
  `ProblemDetail.type` need to update the affected literals; callers using the
  constants should switch to the new module.

## Install

Node.js 24+ is required.

### NPM

```
npm install @interop/verifier-core
```

### Development

This repo uses [pnpm](https://pnpm.io/).

```
git clone https://github.com/interop-alliance/verifier-core.git
cd verifier-core
pnpm install
pnpm test            # lint + node tests (vitest)
pnpm run test-browser # playwright (run `pnpm exec playwright install chromium` first)
```

## Contribute

PRs accepted.

## License

[MIT License](LICENSE.md) © 2025 Digital Credentials Consortium.
