import { VerificationSuite } from '../../types/check.js';
import { expirationCheck } from './expiration-check.js';

export {
  EXPIRED_PROBLEM_TYPE,
  EXPIRATION_SKIP_CODES
} from './expiration-check.js';

/**
 * Credential validity-period suite.
 *
 * Checks that a credential is within its validity period (its `validUntil` /
 * `expirationDate` has not passed). Opt-in: pass it via a verify call's
 * `additionalSuites`; it is not part of `defaultSuites`. Non-fatal -- an
 * expired credential is surfaced as a warning rather than invalidating the
 * credential.
 *
 * ```ts
 * import { createVerifier, expirationSuite } from '@interop/verifier-core';
 *
 * const verifier = createVerifier();
 * await verifier.verifyCredential({
 *   credential,
 *   additionalSuites: [expirationSuite]
 * });
 * ```
 */
export const expirationSuite: VerificationSuite = {
  id: 'validity',
  name: 'Validity Period',
  description: 'Checks the credential expiration / validity period.',
  phase: 'cryptographic',
  checks: [expirationCheck]
};
