import { VerificationSuite } from '../../types/check.js';
import { createIssuerDetailsCheck } from './issuer-details-check.js';

export { createIssuerDetailsCheck } from './issuer-details-check.js';

/**
 * Build the issuer-details ("issuer trust") suite.
 *
 * Surfaces rich issuer registry metadata (logo, legal name, homepage, registry
 * org, etc.) on the check outcome's `payload` for a UI to consume. Opt-in: pass
 * the returned suite via a verify call's `additionalSuites`; it is not part of
 * `defaultSuites`.
 *
 * The registry lookup is injected as `lookupDid` -- a
 * `(did) => Promise<{ matchingIssuers }>` -- so this library never depends on a
 * concrete issuer-registry client. `TIssuer` (the element type of
 * `matchingIssuers`) defaults to `unknown` and is inferred from `lookupDid`, so
 * an app keeps its own richer issuer type end-to-end.
 *
 * ```ts
 * import { createVerifier, createIssuerDetailsSuite } from '@interop/verifier-core';
 *
 * const issuerDetailsSuite = createIssuerDetailsSuite({
 *   lookupDid: (did) => registryManager.lookupDid(did)
 * });
 * const verifier = createVerifier();
 * await verifier.verifyCredential({
 *   credential,
 *   additionalSuites: [issuerDetailsSuite]
 * });
 * ```
 */
export function createIssuerDetailsSuite<TIssuer = unknown>({
  lookupDid
}: {
  lookupDid: (did: string) => Promise<{ matchingIssuers: TIssuer[] }>;
}): VerificationSuite {
  return {
    id: 'trust',
    name: 'Issuer Trust',
    description: 'Surfaces rich issuer registry metadata.',
    phase: 'trust',
    checks: [createIssuerDetailsCheck(lookupDid)]
  };
}
