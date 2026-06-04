# @digitalcredentials/verifier-core CHANGELOG

## 3.0.0 -

### Changed

- **Tooling / packaging** (infrastructure aligned with
  `isomorphic-lib-template`, no library behavior change): build is a single-pass
  `tsc` under `moduleResolution: Bundler`; tests run on **vitest** (Node) +
  **playwright** (browser, replacing karma); lint/format on eslint flat config +
  prettier 3; package manager is **pnpm**. `engines.node` raised to `>=24`.
  `exports` now declare `react-native` / `import` / `default` conditions for
  `.` and `./openbadges`, and the package is marked `sideEffects: false`.
- **Dependencies**: switched `@digitalcredentials/security-document-loader`
  (`^8.0.0`) to the `@interop/security-document-loader` fork (`^9.2.1`). The
  `securityLoader` export and document-loader behavior are unchanged; the fork
  ships its own type declarations, so the module shim in `declarations.d.ts` was
  dropped.
- **Dependencies**: switched the remaining DCC crypto/DID packages to their
  TypeScript `@interop/*` forks (which ship their own type declarations, so the
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
