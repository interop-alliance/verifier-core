/**
 * Validity-period rejections from `@interop/vc`.
 *
 * The library checks a credential's dates only after its signature has
 * verified, so one of these messages proves the document is authentic
 * and merely out of date. It reports VC 2.0 dates (`validUntil` /
 * `validFrom`) and VC 1.x dates (`expirationDate` / `issuanceDate`) with
 * different text; both forms are matched here. The match is on message
 * text because that is the only signal `@interop/vc` 11.x gives for three
 * of the four rejections. The contract test in
 * `test/util/vc-date-messages.spec.ts` drives the library's own
 * `_checkCredential` through all four so a reworded message fails there
 * instead of silently demoting expired credentials to a signature failure.
 *
 * Only the default crypto adapter reads messages; it reports the rejection
 * as `CREDENTIAL_EXPIRED` / `CREDENTIAL_NOT_YET_VALID`, and the proof and
 * status checks key on that problem `type`.
 */

import type { ProblemDetail } from '../types/problem-detail.js';
import { ProblemTypes } from '../problem-types.js';

const DATE_REJECTIONS = {
  expired: {
    patterns: ['is after "validUntil"', 'Credential has expired.'],
    type: ProblemTypes.CREDENTIAL_EXPIRED,
    title: 'Credential Expired',
    verdict: 'Validity ended',
    /** The credential property the rejection reads, VC 2.0 first. */
    properties: ['validUntil', 'expirationDate']
  },
  'not-yet-valid': {
    patterns: ['is before "validFrom"', 'is before the "issuanceDate"'],
    type: ProblemTypes.CREDENTIAL_NOT_YET_VALID,
    title: 'Credential Not Yet Valid',
    verdict: 'Validity starts',
    properties: ['validFrom', 'issuanceDate']
  }
} as const;

export type DateRejection = keyof typeof DATE_REJECTIONS;

/**
 * Which validity-period rejection `message` is (v1 or v2), or `undefined`
 * when it is not one.
 */
export function classifyDateRejection(
  message: string
): DateRejection | undefined {
  for (const [kind, { patterns }] of Object.entries(DATE_REJECTIONS)) {
    if (patterns.some(pattern => message.includes(pattern))) {
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
 * its dates too. A credential without the property is described without
 * it.
 */
export function dateRejectionProblem(
  rejection: DateRejection,
  credential: Record<string, unknown> | undefined,
  now: Date
): ProblemDetail {
  const { type, title, verdict, properties } = DATE_REJECTIONS[rejection];
  const property = properties.find(
    name => typeof credential?.[name] === 'string'
  );
  const when =
    property === undefined
      ? ''
      : ` at ${String(credential?.[property])} (${property})`;
  return {
    type,
    title,
    detail: `${verdict}${when}. Verified at ${now.toISOString()}.`
  };
}
