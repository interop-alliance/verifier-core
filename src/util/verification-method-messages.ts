/**
 * The `@interop/jsonld-signatures` messages for a verification method that
 * resolved but cannot back the proof.
 *
 * The library throws these as plain `Error`s inside a `VerificationError`
 * wrapper, so the message text is the only machine-readable signal. The
 * patterns are pinned by unit tests, so a library upgrade that rewords one
 * fails a test instead of quietly demoting the fault to `INVALID_SIGNATURE`.
 * The same patterns, with the same problem type, are used by the
 * digitalcredentials/verifier-core fork.
 *
 * None of these mean the content was altered. They mean the issuer's key
 * setup does not back the proof it published.
 */

/** Messages that mean the proof's verification method is unusable. */
export const VERIFICATION_METHOD_PATTERNS: readonly RegExp[] = [
  // ControllerProofPurpose: the controller document does not list the
  // method under the proof purpose's term.
  /^Verification method .+ not authorized by controller for proof purpose .+\.$/,
  // ControllerProofPurpose: the resolved method has no string `id`.
  /^Verification method ID .+ must be a string\.$/,
  // LinkedDataSignature: the loaded document does not frame the method.
  /^Verification method .+ not found\.$/
];

/** Whether a library error message names a verification method fault. */
export function isVerificationMethodMessage(message: string): boolean {
  return VERIFICATION_METHOD_PATTERNS.some(pattern => pattern.test(message));
}
