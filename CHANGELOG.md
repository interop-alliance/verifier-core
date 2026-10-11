# @interop/verifier-core CHANGELOG

## 3.8.0 - TBD

### Security

- `unsignedPresentation: true` no longer skips a presentation proof that is
  present. The flag was forwarded to `@interop/vc`, which then skipped the VP
  proof, so a VP with a tampered holder signature verified. A proof that is
  present is now always verified.
- A supplied `challenge` is always enforced. The default crypto service used to
  pick the proof purpose from the VP's own `proofPurpose`, so a replayed
  `assertionMethod` VP verified even when the caller passed a `challenge`. A
  supplied `challenge` now selects `AuthenticationProofPurpose`, and an
  `assertionMethod` VP fails `proof.signature`.
- The built-in HTTP service no longer fetches whatever a credential names. It
  allows `https:` only and refuses `localhost`, loopback, private, link-local,
  multicast, reserved and unspecified addresses, including NAT64, 6to4 and
  IPv4-compatible IPv6 forms and cloud metadata hosts. On Node the check runs on
  the first URL and on every redirect hop (at most five). Browsers and React
  Native hide redirect hops, so there only the first and final URLs are checked.
  Each request has a 10 s deadline and a 5 MiB body cap. Errors have fixed text
  and do not quote the response. Injected `httpGetService` and `documentLoader`
  implementations keep their own policy.
- OIDF registry membership is now verified. Both entity statements used to be
  payload-decoded only, and any statement with a `metadata` object counted as
  registered. The trust anchor's entity configuration is now verified against
  its own `jwks` (`iss === sub`, unexpired `exp`), the federation fetch endpoint
  is read only from that verified payload, and the issuer's subordinate
  statement is verified against the anchor's keys (`iss` is the anchor entity
  id, `sub` is the issuer DID, unexpired `exp`). Both headers must carry
  `typ: entity-statement+jwt` and no `crit`. ES256 and EdDSA are supported;
  among alg-compatible keys, those matching `kid` are tried first, then all of
  them. A subordinate statement no longer needs a `metadata` object. A statement
  that does not verify reports the registry as unchecked. Only raw JWTs are
  cached, re-verified on every hit, with a TTL capped at `exp`. Response bodies
  are trimmed before decoding.
- dcc-legacy lookups match own keys only, so `__proto__` and `constructor`
  cannot match.
- `registryKeyHash` is renamed `registryCacheKey` and returns the JSON encoding
  of the sorted `[type, name, url]` triples (plus sorted `acceptedIssuers` for
  `vc-recognition`) instead of a 32-bit djb2 hash, so two registry lists cannot
  share a cache key.

### Changed

- **BREAKING**: the Zod gate in front of `verifyCredential` /
  `verifyPresentation` is now minimal. A credential needs only `@context`,
  `type`, `issuer` (a string or an object with a string `id`) and
  `credentialSubject`; a presentation needs `@context`, `type` and, when
  present, `holder`. Everything else passes through, so spec-legal inputs the
  old gate rejected (an id-less or non-Bitstring `credentialStatus`, a
  language-map `name`, an issuer `image` that is only `{ id }`, a proof with an
  object `verificationMethod`, an array `credentialSchema.type`) now reach the
  suites. The inferred `VerifiableCredential` / `VerifiablePresentation` types
  are passthrough objects: fields other than the gated ones are `unknown`.
  `ProofSchema`, `JsonLdField`, `JsonLdFieldAllowEmpty`, `CredentialV1Schema`,
  `CredentialV2Schema` and `IssuerObjectSchema` are removed.
- A presentation's gate no longer validates embedded credentials. Each one is
  gated and verified by its own `verifyCredential` call, so a malformed or
  enveloped credential yields its own `parsing.envelope` failure in
  `credentialResults` instead of failing the whole presentation.
- Gate failures carry plain messages (for example
  `"issuer" is required and must be a string or an object with a string "id".`)
  instead of zod's "Invalid input", and the detail is no longer prefixed with a
  path.
- `coreSuite` runs for presentations, ahead of `proof`; only `core.vp-structure`
  applies to a VP. A presentation result's `summary` gains a `core` entry.
- `foldCheckResults` takes `subjectType` in its options, so the "not run after
  fatal" count in a suite message counts only the checks whose `appliesTo`
  admits the subject. `createVerifier` passes it.
- OIDF lookups work in browsers and React Native: JWT decoding uses
  `@scure/base` instead of `Buffer`. `@interop/ecdsa-multikey` and `@scure/base`
  are runtime dependencies.
- A registry lookup result with any unchecked registry is cached for 60 s
  instead of 1 h. A recognition credential is cached for at most 1 h, or until
  its `validUntil` if sooner, measured on the verifier's `timeService`.
  `ttlFromValidUntil` takes `nowMs` and accepts a missing `validUntil`.
- The OIDF lookup URL is built with `URL.searchParams`, so a fetch endpoint that
  already has a query keeps it; a non-URL endpoint yields unchecked.
- `RegistryHandlerContext` carries the verifier's `timeService`; custom handlers
  and tests that build the context must supply one. `createRegistryLookup` takes
  it as an optional fifth argument.

- **BREAKING**: `CryptoVerifyOptions.unsignedPresentation` is removed. A
  `CryptoService` is only asked to verify a proof that exists. Custom
  implementations must drop the field.
- **BREAKING**: `RegistryLookupResult.matchingRegistries: string[]` is replaced
  by `matches: RegistryMatch[]`, each
  `{ registry: RegistryReference, entity?: RegistryEntity }`, and
  `uncheckedRegistries` is now `RegistryReference[]` (`{ name, type, url }`)
  instead of names. The `registry.issuer` outcome `payload` is the new
  `RegistryCheckPayload` (`matches`, `uncheckedRegistries`), present on success
  and on both lookup failures. `CheckOutcome` failures gain an optional
  `payload`. A registry's `url` is where it is read from: the list URL for
  `dcc-legacy` and `vc-recognition`, `trustAnchorEC` for `oidf`. The dcc-legacy
  handler fills `entity` (`name`, `url`, `raw`) from the registry entry; OIDF
  and vc-recognition matches carry no entity yet. The DID-level result cache key
  is now versioned (`reg-result:2:`), so a persistent cache warmed by an older
  release is not read as the new shape, and a lookup returns a copy of the
  cached result rather than the cached object.
- **BREAKING**: `HandlerResult` no longer carries `registryName`; the lookup
  names the registry from its configured entry. Custom `registryHandlers`
  handlers must drop the field.
- When no configured registry could be checked, `registry.issuer` fails with
  `REGISTRY_UNCHECKED` only (detail
  `Issuer registration could not be determined: ...`) instead of a contradictory
  `ISSUER_NOT_REGISTERED` plus `REGISTRY_UNCHECKED`. When some registries
  answered and the issuer was not found, the `ISSUER_NOT_REGISTERED` detail
  reads
  `was not found in the N registries that could be checked; M could not be checked.`;
  with no unchecked registries the text is unchanged.
- A presentation with no proof fails `proof.signature` with
  `Presentation Not Signed`, instead of `No Applicable Crypto Service`. With
  `unsignedPresentation: true` the check is `skipped` and `verified` stays true.
- With no `challenge` supplied, an `authentication` VP proof is verified under a
  `ControllerProofPurpose` with the `authentication` term instead of the
  placeholder challenge `meaningless`. Only the signature and the key's
  `authentication` authorization are checked; the proof's own `challenge` and
  `domain` are not compared.
- The default crypto service verifies only the VP's own proof, via `@interop/vc`
  `verify` with `verifyCredentials: false`. An embedded credential failure no
  longer reads as a VP `Invalid Signature`, and embedded credentials are not
  verified twice. Requires `@interop/vc@11.1.0`.
- `documentHasProof` is shared by `core.proof-exists`, `proof.signature` and the
  default crypto service. A proof array counts when it holds at least one object
  entry.
- A `challenge`, `domain` or proof purpose mismatch on a VP proof is reported as
  `PROOF_PURPOSE_MISMATCH` (titles `Challenge Mismatch`, `Domain Mismatch`,
  `Proof Purpose Mismatch`) instead of `Invalid Signature`.
- `verifyPresentation` rejects a `domain` without a `challenge`, and an
  empty-string `challenge`, before any suite runs. Both produce a
  `proof.signature` failure with `Challenge Required`, whatever the input
  document.
- The document loader reports a non-JSON body as `response is not JSON` instead
  of quoting the parser message.

### Added

- Fatal `core.vc-structure` and `core.vp-structure` checks validate VC Data
  Model structure: `type` includes `VerifiableCredential` /
  `VerifiablePresentation`; `credentialSubject` is a non-empty object (or
  non-empty array of them) with a URL `id` if present; `issuer` is a URL or an
  object with a URL `id`; v1 `issuanceDate` (required) / `expirationDate` and v2
  `validFrom` / `validUntil` are whole-string dateTimes (format only, via
  `@interop/vc` `dateRegex`); `credentialStatus`, `proof`, `termsOfUse` and
  `evidence` entries are objects with a `type`; `credentialStatus` and
  `evidence` ids are URLs; `credentialSchema` entries have a `type` and a URL
  `id`; the first `@context` entry is a VC context. For a VP: `id` and `holder`
  are URLs if present, `proof` entries are typed objects, `verifiableCredential`
  entries are objects. Every violation is its own problem with a JSON Pointer
  `instance`.
- `ProblemTypes.MALFORMED_VALUE_ERROR` (VC Data Model 2.0 section 7.1), emitted
  by the two structure checks.
- `parseCredential` rejects an `EnvelopedVerifiableCredential` (VC-JOSE-COSE)
  with
  `Enveloped credentials (VC-JOSE-COSE) are not supported by this verifier.`
  `parsePresentation` rejects an `EnvelopedVerifiablePresentation` the same way,
  with
  `Enveloped presentations (VC-JOSE-COSE) are not supported by this verifier.`
- `domain` on `verifyPresentation`, `VerificationContext` and
  `CryptoVerifyOptions`, checked alongside `challenge`.
- `ProblemTypes.PROOF_PURPOSE_MISMATCH`.
- `SIGNATURE_SKIP_CODES.unsignedPresentation`, the `code` on the
  `proof.signature` skip for an accepted unsigned presentation.
- `BuiltinHttpGetService({ timeoutMs, maxBytes, allowInsecure })` and the
  exported `BuiltinHttpGetServiceOptions` type. Defaults are 10 s, 5 MiB and
  `false`. `allowInsecure` relaxes only the URL policy, for local development.
- `RegistryCheckPayload`, `RegistryMatch`, `RegistryReference`, `RegistryEntity`
  and `HandlerResult` are exported from the main entry, so a custom
  `registryHandlers` handler can return an `entity`.

### Documentation

- README: the Core suite row no longer claims to "resolve issuers" (that is the
  registry suite); the `verifyCredential` / `verifyPresentation` option blocks
  now list `recognizers`, `phases`, `verbose`, `timing` and `timeService`.
- Architecture doc: the "no `Clock` port" gap is restated as the cache layer
  bypassing the existing `TimeService` seam.
- `src/index.ts` license header now matches `LICENSE.md` (MIT, 2025).

## 3.7.0 - 2026-09-30

### Changed

- Status list credential proofs are verified through the `cryptoServices`
  configured on `createVerifier`, so injected custom crypto services apply to
  `BitstringStatusListCredential`s as well as to VC and VP proofs.
- **BREAKING**: The `cryptoSuites` and `verifyBitstringStatusListCredential`
  fields are removed from the exported `VerificationContext` type. Custom suites
  that build a context by hand must drop them.
- Only `BitstringStatusListEntry` entries in `credentialStatus` have their
  `statusListCredential` fetched and proof-verified; entries of other status
  types are ignored wherever they appear in the array. The check is skipped only
  when no Bitstring entry is present, and the skip reason names every unchecked
  type. Distinct lists are loaded and verified concurrently, and a list shared
  by several entries is loaded and verified once.
- Status list proof verification is injected into `checkStatus` through the
  `verifyStatusListCredential` hook of `@interop/vc-bitstring-status-list`
  `^3.1.0`, which now owns list loading again.
- **BREAKING**: `CheckResult.id` is required. `runSuites` populates it, so the
  verifier no longer sets it afterward. Code that builds a `CheckResult` by hand
  must supply an `id`. The deprecated `check` and `suite` fields remain.
- `SuiteSummary.verified` is true unless a check marked `fatal` failed in that
  suite, matching the top-level `verified`. A suite can have `status: 'failure'`
  with `verified: true` when the failing check is non-fatal.
- `SuiteSummary.message` always reads `<passed> of <total> checks passed`, with
  non-zero counts in parentheses: `(<k> failed)`, `(<k> skipped)`,
  `(<r> not run after fatal)`.
- `proof.signature` fails with `No Proof` when the subject has no `proof`,
  instead of `No Applicable Crypto Service`. A presentation verified with
  `unsignedPresentation: true` is exempt.
- `recognition.profile` skips with `no recognizers configured` when
  `recognizers` is empty, and `no recognizer matched` when none applies.

### Added

- `registry.issuer` success outcomes carry the `RegistryLookupResult` (`found`,
  `matchingRegistries`, `uncheckedRegistries`) on `outcome.payload`.

### Fixed

- The `verified` doc comments and docs state that only `fatal` failures make
  `verified` false.
- Presentation `holder` accepts an object with an `id` as well as a URL string,
  per VCDM 2.0.

## 3.6.0 - 2026-09-28

### Added

- The default document loader resolves `did:webvh` DIDs through
  `@interop/did-method-webvh`, fetching the DID log and witness file via the
  injected `HttpGetService`. A `did:webvh` log that cannot be fetched (an HTTP
  error status or a network failure) is reported as `DID_WEB_UNRESOLVED`, as is
  a `DIDResolutionError` coded `notFound` or `internalError` from any DID
  driver.

### Fixed

- `BuiltinHttpGetService` reads the response body once, so a non-JSON body under
  a JSON-like content type (e.g. a `did.jsonl` log served as
  `application/jsonl`) comes back as text instead of throwing.

## 3.5.10 - 2026-09-27

### Changed

- Update to latest vc and status list deps.

## 3.5.9 - 2026-09-25

### Fixed

- The http(s) document loader protocol handler now parses string bodies, so a
  custom `HttpGetService` that returns raw text (e.g. a `text/plain` status
  list) no longer passes a string through to `checkStatus`. Unparseable bodies
  surface as a url-bearing `NotFoundError`.

## 3.5.8 - 2026-09-10

### Changed

- Update to latest ed25519 key dep (`didKeySigner()`).

## 3.5.7 - 2026-09-10

### Fixed

- `verifyCredential` / `verifyPresentation` now run the suites against the
  caller's original object instead of the Zod parse output, and return that
  object as `verifiableCredential` / `verifiablePresentation`. Zod rewrites
  nested objects (dropping unknown keys such as `issuer.image.caption`), which
  changed the canonicalized N-Quads and made valid proofs fail as
  `INVALID_SIGNATURE`.
- `issuer.image` uses the Open Badges Image schema: unknown keys pass through
  and `type` accepts `'Image'` or `['Image']`. String-form images normalize to
  `{ id, type: 'Image' }` (previously `['Image']`).
- OB 3.0 recognizers and `getVcVersion` accept a string-valued `@context`.

## 3.5.6 - 2026-09-05

### Changed

- Update to latest key deps.

## 3.5.5 - 2026-08-18

### Changed

- Update to latest `@interop/data-integrity-core@8.7.1`.

## 3.5.4 - 2026-08-10

### Changed

- Update to `security-document-loader@10` (byoe-context unbundled).

## 3.5.3 - 2026-08-05

### Fixed

- Presentation verification now derives the proof purpose by scanning every
  proof in the proof set instead of reading `proof[0]` alone. A presentation
  carrying an `assertionMethod` proof ahead of its `authentication` proof was
  verified under `AssertionProofPurpose`, which skips non-matching proofs and
  aggregates with "any verified" -- so the authentication proof binding the
  response to the request's challenge and domain was never signature-checked. If
  any proof declares `authentication` (or `authenticationMethod`),
  `AuthenticationProofPurpose` is used.

## 3.5.2 - 2026-08-01

### Changed

- Update to latest `@interop/security-document-loader@9.5.1` dep.

## 3.5.1 - 2026-08-01

### Changed

- Update to latest `@interop/security-document-loader@9.5.0` dep.

## 3.5.0 - 2026-07-30

### Added

- `'skipped'` check outcomes can now carry an optional machine-readable `code`
  alongside the prose `reason`, so consumers can branch on the skip cause
  without parsing English text. The expiration check (`validity.expiration`) is
  the first emitter: its three skip causes are tagged `no-credential`,
  `no-expiration`, and `unparseable-date` (catalog exported as
  `EXPIRATION_SKIP_CODES`). The distinction matters because a credential whose
  expiry exists but does not parse is an issuer defect a consumer may want to
  surface as a warning, not a pass.

## 3.4.1 - 2026-07-22

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
