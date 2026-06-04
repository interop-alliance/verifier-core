/**
 * Test-only helper that assembles a {@link VerificationContext} with
 * sensible defaults — equivalent to the old `buildContext()` from
 * `src/defaults.ts` (deleted in P-A phase 4).
 *
 * Production code does not use this; the public path is
 * `createVerifier(...)`. Suite unit tests use it because they exercise
 * a single suite against a hand-built context, not the full pipeline.
 *
 * Precedence matches the post-P-E production factory: explicit
 * overrides win, otherwise the document loader and JSON fetcher are
 * always derived from the effective `httpGetService` (default or
 * override). No "first-time caller bypass" branch.
 */

import {
  Ed25519Signature2020,
  eddsaRdfc2022
} from '@interop/ed25519-signature';
import { DataIntegrityProof } from '@interop/data-integrity-proof';
import { DataIntegrityCryptoService } from '../../../src/services/data-integrity-crypto.js';
import { createRegistryLookup } from '../../../src/services/registry-lookup.js';
import { BuiltinHttpGetService } from '../../../src/services/http-get-service/builtin-http-get-service.js';
import { InMemoryCacheService } from '../../../src/services/cache-service/in-memory-cache-service.js';
import { documentLoaderFromHttpGet } from '../../../src/util/document-loader-from-http-get.js';
import { fetchJsonFromHttpGet } from '../../../src/util/fetch-json-from-http-get.js';
import type { VerificationContext } from '../../../src/types/context.js';
import type { CryptoSuite } from '../../../src/types/crypto-suite.js';

const eddsaSuite = new DataIntegrityProof({
  cryptosuite: eddsaRdfc2022
});
const ed25519Suite = new Ed25519Signature2020();

const defaultCryptoSuites: CryptoSuite[] = [ed25519Suite, eddsaSuite];

/** Build a {@link VerificationContext} for tests, optionally overridden. */
export function buildTestContext(
  overrides?: Partial<VerificationContext>
): VerificationContext {
  const cryptoSuites = overrides?.cryptoSuites ?? defaultCryptoSuites;
  const cryptoServices = overrides?.cryptoServices ?? [
    DataIntegrityCryptoService({ suites: cryptoSuites })
  ];

  const effectiveHttpGetService =
    overrides?.httpGetService ?? BuiltinHttpGetService();
  const effectiveCacheService =
    overrides?.cacheService ?? InMemoryCacheService();

  const documentLoader =
    overrides?.documentLoader ??
    documentLoaderFromHttpGet(effectiveHttpGetService);

  const fetchJson =
    overrides?.fetchJson ?? fetchJsonFromHttpGet(effectiveHttpGetService);

  return {
    documentLoader,
    fetchJson,
    httpGetService: effectiveHttpGetService,
    cacheService: effectiveCacheService,
    cryptoSuites,
    cryptoServices,
    registries: overrides?.registries,
    lookupIssuers:
      overrides?.lookupIssuers ??
      createRegistryLookup(effectiveHttpGetService, effectiveCacheService),
    challenge: overrides?.challenge ?? null,
    unsignedPresentation: overrides?.unsignedPresentation ?? false,
    verifyBitstringStatusListCredential:
      overrides?.verifyBitstringStatusListCredential ?? true
  };
}
