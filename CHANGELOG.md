# @interop/verifier-core CHANGELOG

## 3.4.1 - TBD

### Fixed

- The issuer registry check now treats an explicitly empty `registries` list
  (`registries: []`) as opting out of registry lookup and skips, instead of
  failing with "issuer not found in any registry" -- e.g. for self-issued
  credentials.
- `INVALID_SIGNATURE` problem details now surface the underlying sub-error
  messages from an aggregate jsonld-signatures error (deduplicated and joined),
  instead of the unhelpful top-level "Verification error(s)." message.

## 3.4.0 - 2026-07-22

### Added

- Two opt-in verification suites (pass them via a verify call's
  `additionalSuites`; neither is part of `defaultSuites`):
  - `expirationSuite` (suite id `validity`, check id `validity.expiration`) -- a
    non-fatal check that a credential is within its validity period, reading the
    expiry from VC 2.0 `validUntil` and falling back to VC 1.x `expirationDate`.
    "Now" comes from the injected time service
    (`context.timeService.dateNowMs()`) when present, else `Date.now()`. Emits
    the new exported `EXPIRED_PROBLEM_TYPE` on failure.
  - `createIssuerDetailsSuite({ lookupDid })` (suite id `trust`, check id
    `trust.issuer-details`) -- a factory for a non-fatal check that surfaces
    rich issuer registry metadata on the outcome `payload` for a UI to consume.
    The registry lookup is injected as `lookupDid`, so the library takes on no
    concrete registry-client dependency. The individual
    `createIssuerDetailsCheck` is also exported for a la carte suite
    composition.

## 3.3.1 - 2026-06-28

### Changed

- Update to `@interop/data-integrity-core@8.1.0` and related latest deps.

## 3.3.0 - 2026-06-25

### Added

- New `VERIFICATION_METHOD_UNRESOLVED` problem type. When a proof's verification
  method uses a DID method the document loader has no driver for (did-io throws
  `Driver for DID ... not found.`), `classifySignatureError` now surfaces a
  distinct, actionable problem -- "the verifier cannot resolve this DID method;
  register a resolver/driver in the document loader" -- instead of a misleading
  `INVALID_SIGNATURE`. The signature was never actually checked, so reporting it
  as invalid was wrong.

## 3.2.1 - 2026-06-13

### Changed

- Update to `@digitalcredentials/data-integrity-core@8.0.0` and related latest
  deps.

## 3.2.0 - 2026-06-09

### Added

- Verify ECDSA (P-256 / P-384) `ecdsa-rdfc-2019` Data Integrity credentials out
  of the box. Two changes to the default services:
  - `defaultCryptoSuites()` now includes `ecdsa-rdfc-2019` (via
    `@interop/ecdsa-signature`), alongside `Ed25519Signature2020` and
    `eddsa-rdfc-2022`.
  - The default document loader (`documentLoaderFromHttpGet`) registers the
    standard `did:key` suites -- Ed25519 plus ECDSA P-256/P-384/P-521 -- via
    `@interop/security-document-loader`'s new `registerDefaultDidKeyHeaders`
    helper, so ECDSA `did:key` verification methods resolve (previously only the
    Ed25519 `z6Mk` header was registered). Requires
    `@interop/security-document-loader@^9.3.0`.

## 3.1.0 - 2026-06-06

### Added

- `ProblemTypes.ISSUER_PROOF_MISMATCH`: a distinct problem type for credentials
  whose `issuer` does not match the controller of the proof's verification
  method. The Data Integrity crypto service now classifies this case explicitly
  (title `Issuer / Proof Mismatch`, with the offending issuer in the detail)
  instead of collapsing it into a generic `INVALID_SIGNATURE` -- the signature
  itself is cryptographically valid; it is the proof-purpose validation that
  fails, so reporting it as a bad signature was misleading.

## 3.0.0-3.0.1 - 2026-06-04

### Changed

- **BREAKING**: Fork from https://github.com/skybridgeskills/dcc-verifier-core
  (v2 below)
- **Tooling / packaging** (infrastructure aligned with
  `isomorphic-lib-template`, no library behavior change): build is a single-pass
  `tsc` under `moduleResolution: Bundler`; tests run on **vitest** (Node) +
  **playwright** (browser, replacing karma); lint/format on eslint flat config +
  prettier 3; package manager is **pnpm**. `engines.node` raised to `>=24`.
  `exports` now declare `react-native` / `import` / `default` conditions for `.`
  and `./openbadges`, and the package is marked `sideEffects: false`.
- **Dependencies**: switched `@digitalcredentials/security-document-loader`
  (`^8.0.0`) to the `@interop/security-document-loader` fork (`^9.2.1`). The
  `securityLoader` export and document-loader behavior are unchanged; the fork
  ships its own type declarations, so the module shim in `declarations.d.ts` was
  dropped.
- **Dependencies**: switched the DCC crypto/DID packages to their TypeScript
  `@interop/*` forks (which ship their own type declarations, so the
  corresponding `declare module` shims were dropped):
  - `@digitalcredentials/ed25519-multikey` (`^1.4.0`) and
    `@digitalcredentials/ed25519-verification-key-2020` (`^4.0.0`, dev) to
    `@interop/ed25519-verification-key` (`^7.0.1`); `Ed25519Multikey.from`
    becomes `Ed25519VerificationKey.from`.
  - `@digitalcredentials/data-integrity` (`^2.6.0`) to
    `@interop/data-integrity-proof` (`^3.2.1`) for the `DataIntegrityProof`
    suite.
  - `@digitalcredentials/did-method-web` (`^1.1.0`) to
    `@interop/did-web-resolver` (`^6.1.0`); `DidWebDriver` becomes
    `DidWebResolver` and `didUrlToHttpsUrl` is replaced by `urlFromDid`.
  - `@digitalcredentials/ed25519-signature-2020` (`^7.0.0`) +
    `@digitalcredentials/eddsa-rdfc-2022-cryptosuite` (`^1.3.0`) to
    `@interop/ed25519-signature` (`^7.0.1`), which provides both
    `Ed25519Signature2020` and the `eddsaRdfc2022` cryptosuite.
- **Dependencies**: switched the last remaining DCC packages to their TypeScript
  `@interop/*` forks: `@digitalcredentials/vc` (`^10.0.0`) → `@interop/vc`
  (`^11.0.1`); `@digitalcredentials/jsonld-signatures` (`^12.0.1`) →
  `@interop/jsonld-signatures` (`^11.6.7`);
  `@digitalcredentials/vc-bitstring-status-list` (`^1.0.0`) →
  `@interop/vc-bitstring-status-list` (`^3.0.1`); `@digitalcredentials/did-io`
  (`^1.0.2`) → `@interop/did-io` (`^4.0.2`);
  `@digitalcredentials/did-method-key` (`^3.0.0`) → `@interop/did-method-key`
  (`^7.1.1`). Added `@interop/data-integrity-core` (`^6.1.2`) as a direct
  dependency for the ecosystem's shared types.
- **Types**: The local `DocumentLoader`, `CryptoSuite`, and `ProofPurpose` types
  are now thin aliases over the shared `@interop/data-integrity-core`
  (`IDocumentLoader`/`IRemoteDocument`) and `@interop/jsonld-signatures`
  (`LinkedDataProof`/`ProofPurpose`) types, so the verifier speaks the
  ecosystem's vocabulary end-to-end. The unused `LinkedDataSuite` /
  `DataIntegritySuite` public exports were dropped (`CryptoSuite` is now
  `LinkedDataProof`).
- **Fix (status list)**: `@interop/vc-bitstring-status-list` (`v3`) splits the
  `checkStatus` result — `verified` now means "status checked without error" and
  the revoked/suspended bit moved into each `results[].status`. The status suite
  reads `results[].status` accordingly (previously relied on
  `verified === false` meaning revoked).
- **Removed (`@interop/vc`)**: the `verifyMatchingIssuers` option is gone from
  `@interop/vc`'s verify APIs; the Data Integrity adapter no longer passes it
  (it had always passed `false` to disable that check).
- **Fix (document loader)**: the custom http(s) protocol handler in
  `documentLoaderFromHttpGet` now returns the bare document. The
  `@interop/security-document-loader` (jsonld-document-loader ≥ 2) wraps the
  handler result in `{ contextUrl, document, documentUrl }` itself, so the
  previous wrapper double-nested it (`document.document`). Restores networked
  status-list / context fetching (`test:smoke`).
- **Fix (`BuiltinHttpGetService`)**: the default `HttpGetService` now also
  JSON-parses a string response body (falling back to raw text), so hosts that
  serve JSON-LD as `text/plain` (e.g. raw.githubusercontent.com status lists)
  yield a parsed document. Centralizes the contract that `body` is the parsed
  JSON document for all consumers (document loader, did:web driver, registry
  fetches), not just the JSON Content-Type path.

## 2.0.0 - Month XX 2026

Verifier results now fold per-suite checks into a single
`summary: SuiteSummary[]` rollup; `results[]` carries only failures and explicit
`<suite>.applies` skips by default. The full check list remains available via
`verbose: true` on the verifier or per call.

### Added

- `SuiteSummary` type and `summary: SuiteSummary[]` field on
  `CredentialVerificationResult` and `PresentationVerificationResult`.
- `id: string` field on `CheckResult` — dot-separated
  `<phase>.<suite>.<localPart>` namespace.
- `verbose?: boolean` on `VerifierConfig`, `VerifyCredentialCall`,
  `VerifyPresentationCall` (per-call wins over instance default;
  `verifyPresentation` propagates the flag to embedded credentials).
- Pure `foldCheckResults` helper and `computeId` namespace builder, both
  exported from the package barrel.
- New consumer doc at `docs/api/verification-results.md` covering the folded
  shape, the `id` namespace, a UI rendering recipe, and a prompt-ready appendix
  for downstream UIs.
- `timing?: boolean` flag on `VerifierConfig`, `VerifyCredentialCall`, and
  `VerifyPresentationCall`. When true, every `CheckResult`, every
  `SuiteSummary`, and every top-level
  `Credential|PresentationVerificationResult` carries a `timing: TaskTiming`
  field describing wall-clock start/end and monotonic duration. Mirrors the
  `verbose` flag's plumbing; per-call wins; propagates from `verifyPresentation`
  into embedded `verifyCredential` calls. See `docs/api/timing.md`.
- `TaskTiming` interface (`startedAt`, `endedAt`, `durationMs`, optional
  recursive `events`). The reserved `events` field is forward-compatible with
  future sub-event capture from inside a single check.
- `TimeService` interface plus `RealTimeService` and `FakeTimeService`
  factories. New optional `timeService` on `VerifierConfig` (defaults to
  `RealTimeService()`). Now available on `VerificationContext.timeService` for
  any future check that needs to ask "what time is it?" — useful groundwork for
  credential expiration, signature clock-skew, key rotation, and status-list
  freshness work.

### Changed

- **Default `results[]` shape**: failures + explicit `<suite>.applies` skips
  only. Pass `verbose: true` to restore the prior shape.
- `flattenPresentationResults` semantically unchanged; in folded mode the
  returned array is naturally smaller.

### Deprecated

- `CheckResult.check` and `CheckResult.suite` — use `CheckResult.id` instead.
  Removal target: the next major.

### Migration

- To restore the prior result shape with no other changes: pass `verbose: true`
  on the verifier or per call.
- To adopt the new shape: read `result.summary[]` for the per-suite rollup; read
  `result.results[]` for failure detail; use
  `r.id?.startsWith(summary.id + '.')` to find detail rows under a failing
  summary entry.

## 1.0.0-beta.11 - December 15 2025

### Added

- Returns staus list errors that had been incorrectly swallowed. See the README
  for new errors that are returned.

## 1.0.0-beta.10 - October 24 2025

### Added

- Returns more informative results for json-ld safe-mode errors. See the README
  for details.

## 1.0.0-beta.9 - October 2 2025

### Added

- Adds schema validation results to the returned verification results.
