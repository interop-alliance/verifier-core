import { VerificationCheck, CheckOutcome } from '../../types/check.js';
import { VerificationSubject } from '../../types/subject.js';
import { VerificationContext } from '../../types/context.js';

/**
 * Problem `type` URI for an expired credential.
 *
 * Uses the same `https://www.w3.org/TR/vc-data-model#...` placeholder host
 * as the rest of the catalog (see {@link ../../problem-types.ts}); treat it
 * as an opaque key until a real error registry exists. Kept as a standalone
 * constant rather than mirrored into the core `ProblemTypes` map because the
 * validity suite is opt-in (passed via `additionalSuites`), following the
 * same "vertical catalogs live with their suite" convention as the
 * OpenBadges submodule.
 */
export const EXPIRED_PROBLEM_TYPE =
  'https://www.w3.org/TR/vc-data-model#CREDENTIAL_EXPIRED';

/**
 * Machine-readable `code` values carried on this check's `'skipped'`
 * outcomes. Branch on these rather than on the prose `reason` -- the three
 * causes are not interchangeable: `noExpiration` means the credential
 * genuinely never expires, while `unparseableDate` means an expiry exists
 * but could not be evaluated (an issuer defect a consumer may well want to
 * surface as a warning rather than a pass).
 */
export const EXPIRATION_SKIP_CODES = {
  /** The subject carried no verifiable credential. */
  noCredential: 'no-credential',
  /** The credential has no `validUntil` / `expirationDate`. */
  noExpiration: 'no-expiration',
  /** An expiry value exists but does not parse as a date. */
  unparseableDate: 'unparseable-date'
} as const;

/**
 * Reads the credential's expiry instant, preferring the VC 2.0 `validUntil`
 * property and falling back to the VC 1.x `expirationDate`.
 *
 * @param credential {Record<string, unknown>}
 * @returns {string | undefined} The ISO date string, or undefined when none.
 */
function getExpirationIso(
  credential: Record<string, unknown>
): string | undefined {
  const validUntil = credential.validUntil;
  if (typeof validUntil === 'string' && validUntil) {
    return validUntil;
  }
  const expirationDate = credential.expirationDate;
  if (typeof expirationDate === 'string' && expirationDate) {
    return expirationDate;
  }
  return undefined;
}

/**
 * Credential expiration check.
 *
 * Reads the credential's expiry off `validUntil` (VC 2.0) or `expirationDate`
 * (VC 1.x) and compares it against "now". This is a non-fatal informational
 * check: an expired credential is reported as a warning, not a hard
 * cryptographic failure.
 *
 * "Now" is read from the injected clock -- `context.timeService.dateNowMs()`
 * when present, else `Date.now()` -- so the check is deterministic under a
 * fake time service in tests.
 *
 * Skipped when (each cause tagged with its {@link EXPIRATION_SKIP_CODES}
 * entry on the outcome's `code`):
 * - No credential in the subject (`no-credential`).
 * - Credential has no expiration date (`no-expiration`).
 * - The expiration date is not a valid date (`unparseable-date`).
 *
 * Success when:
 * - The credential is within its validity period.
 *
 * Failure ({@link EXPIRED_PROBLEM_TYPE}) when:
 * - The expiration instant is in the past.
 */
export const expirationCheck: VerificationCheck = {
  id: 'validity.expiration',
  name: 'Credential Expiration Check',
  description:
    'Verifies the credential is within its validity period (validUntil / expirationDate).',
  fatal: false,
  appliesTo: ['verifiableCredential'],
  execute: async (
    subject: VerificationSubject,
    context: VerificationContext
  ): Promise<CheckOutcome> => {
    const credential = subject.verifiableCredential as
      Record<string, unknown> | undefined;

    if (!credential) {
      return {
        status: 'skipped',
        reason: 'No verifiable credential found in subject.',
        code: EXPIRATION_SKIP_CODES.noCredential
      };
    }

    const expirationIso = getExpirationIso(credential);
    if (!expirationIso) {
      return {
        status: 'skipped',
        reason: 'Credential has no expiration date.',
        code: EXPIRATION_SKIP_CODES.noExpiration
      };
    }

    const expiresMs = new Date(expirationIso).getTime();
    if (Number.isNaN(expiresMs)) {
      return {
        status: 'skipped',
        reason: 'Credential expiration date is not a valid date.',
        code: EXPIRATION_SKIP_CODES.unparseableDate
      };
    }

    const nowMs = context.timeService
      ? context.timeService.dateNowMs()
      : Date.now();

    if (expiresMs >= nowMs) {
      return {
        status: 'success',
        message: `Credential is within its validity period (expires ${expirationIso}).`
      };
    }

    return {
      status: 'failure',
      problems: [
        {
          type: EXPIRED_PROBLEM_TYPE,
          title: 'Credential Expired',
          detail: `Credential expired on ${expirationIso}.`
        }
      ]
    };
  }
};
