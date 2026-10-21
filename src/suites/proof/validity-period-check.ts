import { VerificationCheck, CheckOutcome } from '../../types/check.js';
import { ProblemDetail } from '../../types/problem-detail.js';
import { VerificationSubject } from '../../types/subject.js';
import { VerificationContext } from '../../types/context.js';
import { vcVersionOf } from '../../util/vc-contexts.js';
import { dateRejectionProblem } from '../../util/vc-date-messages.js';

/** The credential's start and end date properties, by VC version. */
const VALIDITY_PROPERTIES = {
  v1: { start: 'issuanceDate', end: 'expirationDate' },
  v2: { start: 'validFrom', end: 'validUntil' }
} as const;

/**
 * Machine-readable `code` values carried on this check's `'skipped'`
 * outcomes. Branch on these rather than on the prose `reason`.
 */
export const VALIDITY_PERIOD_SKIP_CODES = {
  /** The first `@context` entry is neither VC context, so the date names are unknown. */
  unknownVersion: 'unknown-vc-version',
  /** A stated date is not a string naming a date. */
  unparseableDate: 'unparseable-date'
} as const;

/**
 * The date `value` names: `undefined` when the property is absent, `null`
 * when it is present but is not a string naming a date.
 */
function dateOf(value: unknown): Date | undefined | null {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'string') {
    return null;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/**
 * Validity period check: the credential's own dates against
 * {@link VerificationContext.now}, the instant `proof.signature` and
 * `status.bitstring` judge at too.
 *
 * The version comes from the first `@context` entry, as in `@interop/vc`
 * and `core.vc-structure`: v1 reads `issuanceDate` / `expirationDate`, v2
 * `validFrom` / `validUntil`. The comparisons are the library's: expired
 * once the clock is past the end, not yet valid while it is before the
 * start. Every fault is reported, not only the first.
 *
 * A credential whose version cannot be read, or whose stated date does
 * not parse, is skipped with a {@link VALIDITY_PERIOD_SKIP_CODES} code
 * rather than passed: there is no validity period to judge. In the
 * default chain `core.vc-structure` has already failed the credential for
 * either, so the skip is seen only when this check runs on its own.
 *
 * It runs after `proof.signature`, so by the time it runs the credential
 * is authentic. Being out of date makes it unusable, so the check is
 * fatal (`verified: false`). Whether it was also revoked, and whether its
 * issuer is registered, still matter to a verifier, so it does not halt
 * the checks after it (`halts: false`).
 */
export const validityPeriodCheck: VerificationCheck = {
  id: 'proof.validity-period',
  name: 'Validity Period',
  description:
    "Checks the credential's validity dates against the verifier's clock.",
  fatal: true,
  halts: false,
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
        reason: 'No verifiable credential found in subject.'
      };
    }

    const version = vcVersionOf(credential['@context']);
    if (!version) {
      return {
        status: 'skipped',
        reason:
          'The first @context entry is not a VC context, so the validity period cannot be read.',
        code: VALIDITY_PERIOD_SKIP_CODES.unknownVersion
      };
    }
    const properties = VALIDITY_PROPERTIES[version];
    const start = dateOf(credential[properties.start]);
    const end = dateOf(credential[properties.end]);
    if (start === null || end === null) {
      const field = start === null ? properties.start : properties.end;
      return {
        status: 'skipped',
        reason: `${field} is not a date, so the validity period cannot be judged.`,
        code: VALIDITY_PERIOD_SKIP_CODES.unparseableDate
      };
    }
    if (start === undefined && end === undefined) {
      return { status: 'success', message: 'No validity period stated.' };
    }

    const { now } = context;
    const problems: ProblemDetail[] = [];
    if (end !== undefined && now > end) {
      problems.push(
        dateRejectionProblem('expired', credential, now, properties.end)
      );
    }
    if (start !== undefined && now < start) {
      problems.push(
        dateRejectionProblem('not-yet-valid', credential, now, properties.start)
      );
    }

    if (problems.length > 0) {
      return { status: 'failure', problems };
    }
    return {
      status: 'success',
      message: 'The credential is within its validity period.'
    };
  }
};
