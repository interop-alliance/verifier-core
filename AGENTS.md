# Agent Guidelines -- @interop/verifier-core

Verifies W3C Verifiable Credentials (VC data model v1, v1.1, v2) and
Presentations across Node.js, browsers, and React Native. Returns a structured
report and lets the consumer decide what "valid" means.

## Repo lineage (read this first)

This is a fork of the DCC `verifier-core`. **Nate Otto (Skybridge Skills)
rewrote it**: his 67 commits (~20.5k insertions / 4.8k deletions, 224 files)
took it from `1.0.0-beta.11` to `2.0.0`. The pre-Nate baseline is commit
`8f86b7b` -- a near-monolithic `src/Verify.ts` plus a few helpers
(`credentialStatus.ts`, `issuerRegistries.ts`, `schemaCheck.ts`) returning a
`{ verified, log[] }` shape. Everything below `8f86b7b` is upstream DCC;
everything above is the rewrite.

To inspect the rewrite: `git log --author="Nate" --oneline`. His commits are
phased and conventional-commit tagged (e.g.
`feat(verifier-core): obv3p0-recognizer - phase N`).

## Architecture (hexagonal / ports-and-adapters)

`docs/architecture.md` is the authoritative, detailed guide -- keep it in sync
with code changes. Quick map:

- **`createVerifier(config)`** (`src/verifier.ts`) is the composition root.
  Injectable adapters on `VerifierConfig`: `HttpGetService`, `CacheService`,
  `CryptoService[]`, `DocumentLoader`, `RegistryHandlerMap`, `TimeService`.
  Defaults are lazy/memoized in `src/default-services.ts` (not exported).
- **Standalone `verifyCredential` / `verifyPresentation`**
  (`src/verify-suite.ts`) are thin wrappers that build a fresh verifier per
  call.
- **Suite/check engine** (`src/run-suites.ts`): an ordered pipeline of suites ->
  checks. Default order: `core -> recognition -> proof -> status -> registry`.
  Each check returns a discriminated `CheckOutcome`
  (`success | failure | skipped`) -- **no exceptions for verification
  failures**. Append custom suites via `additionalSuites`.
- **Suites carry a `phase` tag**
  (`cryptographic | trust | recognition | semantic`) and an optional
  `applies(subject)` predicate. The `phases?:` filter enables two-pass
  verification (run crypto+trust once, re-run `semantic` later; requesting
  `semantic` auto-includes `recognition`). A `phases:` value sets
  `partial: true` on the result.
- **Structured errors**: `ProblemDetail` (RFC 9457-inspired: `type` URI,
  `title`, `detail`) with an optional `instance` field carrying an RFC 6901 JSON
  Pointer to the offending field (`src/util/json-pointer.ts`). Type-URI catalog
  in `src/problem-types.ts`.
- **Result folding (v2.0.0)**: `results[]` carries only failures + explicit
  `<suite>.applies` skips; per-suite rollup lives in `summary: SuiteSummary[]`.
  `verbose: true` restores the full check list. Pure helpers `foldCheckResults`
  / `computeId` in `src/fold-results.ts`.
- **Trust registries** (`EntityIdentityRegistry` discriminated union):
  `dcc-legacy` (old URL-based DID list), `oidf` (OpenID Federation),
  `vc-recognition` (a recognition VC recursively verified through the _same_
  verifier instance via a `getVerifier` thunk + `registries: []` recursion
  guard). Per-type handlers in `src/services/registry-handlers/`.
- **Presentation flow** recurses each embedded VC through the same `Verifier` so
  cache / loader / crypto / registries are shared. `flattenPresentationResults`
  gives a single provenance-tagged view.

### Opt-in suites (main entry, not in `defaultSuites`)

Generic (non-vertical) suites can ship from the **main** entry point but stay
out of `defaultSuites` -- consumers pass them via a verify call's
`additionalSuites`. Current ones:

- `expirationSuite` (`src/suites/validity/`, check id `validity.expiration`) --
  non-fatal validity-period check (VC 2.0 `validUntil`, falling back to VC 1.x
  `expirationDate`); reads "now" from `context.timeService` when present. Emits
  the exported `EXPIRED_PROBLEM_TYPE` (kept standalone, not mirrored into the
  core `ProblemTypes` map).
- `createIssuerDetailsSuite({ lookupDid })` (`src/suites/trust/`, check id
  `trust.issuer-details`) -- a factory for a non-fatal check that surfaces rich
  issuer registry metadata on the outcome `payload` for a UI. The lookup is
  injected as `lookupDid`, so the library takes no concrete registry-client
  dependency; `createIssuerDetailsCheck` is also exported for a la carte
  composition.

### Vertical submodules (`/openbadges`)

Vertical-specific logic ships **opt-in** under a `package.json#exports` subpath,
NOT in `defaultSuites`. First one: `@interop/verifier-core/openbadges`
(`src/openbadges/`) -- OB 3.0 recognizers, strict version-pinned Zod envelope
schemas, AJV JSON-Schema checks, semantic checks, and its own
`OpenBadgesProblemTypes` catalog. Future verticals (EU DCC, jurisdiction trust
frameworks) follow the same pattern.

**Bundle note**: `ajv`/`ajv-formats` are only reachable via
`src/suites/schema/obv3/`, which is consumed exclusively by the `/openbadges`
submodule. The default suite chain does not import them -- a consumer importing
only the main entry tree-shakes ajv out. The heavy weight is the unchanged
crypto/JSON-LD stack (`@digitalcredentials/vc`, `jsonld-signatures`,
`data-integrity`, `security-document-loader`, `did-method-*`,
`vc-bitstring-status-list`); the rewrite adds `zod` (main path) + `klona`
(tiny).

## Direction Nate is taking it

From a DCC-specific verifier -> a general-purpose, composable VC verification
_framework_: environment-agnostic, network-free testability, consumers wire in
only what they need. Stated remaining hexagonal work (`docs/architecture.md`
§Direction): route the bitstring-status check through
`Verifier.verifyCredential` (drop the `cryptoSuites` dependency on
`VerificationContext`), wrap AJV behind a `JsonSchemaValidator` port, and add a
`Clock` port. Server-fit signals: per-verifier cache sharing, lean serializable
results (Redis-friendly), timing instrumentation, OIDF.

## v2.0.0 is NOT a drop-in for pre-Nate consumers

Downstream wallets pinned to pre-Nate's rewrites are coupled to the **old** API
on both ends:

- **Input**: they pass `knownDIDRegistries` -- gone; replaced by the
  `registries` discriminated union (`dcc-legacy` is the migration target for the
  old known-registries JSON).
- **Output**: they read `result.log[]` with `{ id, valid, error }` rows, magic
  ids like `'revocation_status'`, and `error.name === 'status_list_not_found'`.
  v2.0.0 has none of that -- it returns `results: CheckResult[]` + `summary[]` +
  `ProblemDetail`.

Migration path: a thin compatibility shim in each wallet's adapter
(`freewallet/src/lib/verify.ts`, `dcw/app/lib/validate.ts`) that maps
`registries` config in and the v2 result shape back to the legacy
`{ verified, log[] }` shape, leaving the wallets' view-mapper/UI layers
untouched.

## Build / test

Toolchain is aligned with `isomorphic-lib-template` (pnpm, single-pass `tsc`,
vitest, playwright, eslint flat config, prettier 3). Package manager is **pnpm**
(`packageManager: pnpm@11.9.0`); use `pnpm run <script>`.

- `pnpm run build` = `clear` is single `tsc` (one pass emits both JS and `.d.ts`
  from `tsconfig.json`; `src/**/*.spec.ts` excluded from the build output).
- `pnpm test` = `lint` + `test-node`. `pnpm run test-node` = `vitest run` (runs
  TS directly via esbuild, v8 coverage via `pnpm run test-coverage`); config in
  `vite.config.ts`, includes `test/**/*.spec.ts` + the two co-located
  `src/**/*.spec.ts`, excludes the networked `smoke.spec.ts` and `test/browser`.
  `pnpm run test:smoke` runs the networked interop regression
  (`vitest.smoke.config.ts`).
- `pnpm run test-browser` = `playwright test` against a vite dev server
  (`pnpm run dev`) + `test/index.html`; one isomorphic smoke spec in
  `test/browser/`. Run `pnpm exec playwright install chromium` first. Browser
  tests are **not** part of `pnpm test` (run separately / in CI) so the default
  test run needs no browser binaries.
- **tsconfigs (2)**: `tsconfig.json` (build) uses `moduleResolution: Bundler`,
  `module: ESNext`, `isolatedModules`, and **keeps** the
  `@digitalcredentials/vc` `paths` shim (->
  `src/types/@digitalcredentials/vc.d.ts`) under `baseUrl: .`.
  `tsconfig.dev.json` (`noEmit`, widens `include` to `test/**`,
  `vite.config.ts`) backs editor + eslint typed-linting. `verbatimModuleSyntax`
  and `noUncheckedIndexedAccess` are **deferred** (template enables them;
  adopting them here is a follow-up that will surface real source-level
  findings).

## Conventions

- Suites are plugins with a uniform `VerificationCheck` interface; adding one
  requires no core changes. No dynamic imports in `src/` (proof suite is
  statically wired).
- Vertical problem-type catalogs live next to their vertical and are NOT
  mirrored into the core `ProblemTypes` map.
- `ProblemDetail.type` stays typed as `string` so custom suites can emit their
  own URIs.
- Don't bump `package.json` version; new CHANGELOG entries use `TBD` as the
  date.
