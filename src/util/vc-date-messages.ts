/**
 * Validity-period rejections from `@interop/vc`.
 *
 * `verifyCredential` verifies the proof first and checks the credential's
 * validity dates only once it has verified. A date failure comes back as
 * a plain `Error` whose message is the only machine-readable signal; a
 * proof failure comes back as a `VerificationError` carrying the reasons
 * in `errors[]`. {@link classifyDateRejection} tells the two apart, and
 * the default crypto adapter reports a date failure as a typed
 * `CREDENTIAL_EXPIRED` / `CREDENTIAL_NOT_YET_VALID` problem. That typed
 * problem is how the rest of the verifier learns the proof itself
 * verified.
 *
 * VC 2.0 dates (`validUntil` / `validFrom`) and VC 1.x dates
 * (`expirationDate` / `issuanceDate`) are reported with different text,
 * and all four messages are matched in full. The contract test in
 * `test/util/vc-date-messages.spec.ts` drives the library's own
 * `_checkCredential` through all four, so a reworded message fails there
 * instead of silently turning an expired credential into a signature
 * failure.
 *
 * `proof.validity-period` describes its own faults with
 * {@link dateRejectionProblem} too, so both read the same way.
 */

import type { ProblemDetail } from '../types/problem-detail.js';
import { ProblemTypes } from '../problem-types.js';

const DATE_REJECTIONS = {
  expired: {
    messages: [
      /^Credential has expired\.$/,
      /^The current date time \(.+\) is after "validUntil" \(.+\)\.$/
    ],
    type: ProblemTypes.CREDENTIAL_EXPIRED,
    title: 'Credential Expired',
    verdict: 'Validity ended',
    /** The credential property the rejection reads, VC 2.0 first. */
    properties: ['validUntil', 'expirationDate']
  },
  'not-yet-valid': {
    messages: [
      /^The current date time \(.+\) is before "validFrom" \(.+\)\.$/,
      /^The current date time \(.+\) is before the "issuanceDate" \(.+\)\.$/
    ],
    type: ProblemTypes.CREDENTIAL_NOT_YET_VALID,
    title: 'Credential Not Yet Valid',
    verdict: 'Validity starts',
    properties: ['validFrom', 'issuanceDate']
  }
} as const;

export type DateRejection = keyof typeof DATE_REJECTIONS;

/**
 * Which validity-period rejection `error` is (v1 or v2), or `undefined`
 * when it is not one.
 *
 * `@interop/vc` throws these from `_checkCredential` only after the proof
 * verified, as a plain `Error`. A proof failure is a `VerificationError`
 * carrying `errors[]`. Both conditions are required, and the message must
 * match the library's wording in full, so a date phrase quoted inside a
 * wrapped proof error never counts.
 */
export function classifyDateRejection(
  error: unknown
): DateRejection | undefined {
  if (!(error instanceof Error) || error.name === 'VerificationError') {
    return undefined;
  }
  if (Array.isArray((error as { errors?: unknown }).errors)) {
    return undefined;
  }
  for (const [kind, { messages }] of Object.entries(DATE_REJECTIONS)) {
    if (messages.some(pattern => pattern.test(error.message))) {
      return kind as DateRejection;
    }
  }
  return undefined;
}

/**
 * The problem for a validity-period rejection. Its `detail` names the
 * credential's own date (with the property it came from) and the
 * verification instant, built from the credential rather than from the
 * library message so a VC 1.x rejection ("Credential has expired.") gets
 * its dates too. `property` names the date to quote; without it, the
 * first of the rejection's properties the credential carries is used
 * (VC 2.0 first). A credential without the property is described
 * without it.
 */
export function dateRejectionProblem(
  rejection: DateRejection,
  credential: Record<string, unknown> | undefined,
  now: Date,
  property?: string
): ProblemDetail {
  const { type, title, verdict, properties } = DATE_REJECTIONS[rejection];
  const quoted =
    property ?? properties.find(name => typeof credential?.[name] === 'string');
  const when =
    quoted === undefined || credential?.[quoted] === undefined
      ? ''
      : ` at ${String(credential[quoted])} (${quoted})`;
  return {
    type,
    title,
    detail: `${verdict}${when}. Verified at ${now.toISOString()}.`
  };
}
