/**
 * Recognise the validity-period rejections of `@interop/vc`.
 *
 * The library checks a credential's dates only after its proof has
 * verified, so one of these messages proves the document is authentic
 * and merely out of date. It reports VC 2.0 dates (`validUntil` /
 * `validFrom`) and VC 1.x dates (`expirationDate` / `issuanceDate`) with
 * different text; both forms are matched here. Used by the status check
 * to classify a rejected status list credential.
 */

const DATE_REJECTION_PATTERNS = {
  expired: ['is after "validUntil"', 'Credential has expired.'],
  'not-yet-valid': ['is before "validFrom"', 'is before the "issuanceDate"']
} as const;

export type DateRejection = keyof typeof DATE_REJECTION_PATTERNS;

/**
 * Which validity-period rejection `message` is (v1 or v2), or `undefined`
 * when it is not one.
 */
export function classifyDateRejection(
  message: string
): DateRejection | undefined {
  for (const [kind, patterns] of Object.entries(DATE_REJECTION_PATTERNS)) {
    if (patterns.some(pattern => message.includes(pattern))) {
      return kind as DateRejection;
    }
  }
  return undefined;
}
