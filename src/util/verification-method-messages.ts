/**
 * The library messages for a verification method whose DID resolved but
 * which cannot back the proof. `@interop/jsonld-signatures` throws them for
 * a method the controller document does not authorize or frame. The DID
 * drivers throw them for a fragment the DID document does not have.
 *
 * The current libraries throw these as a typed `VerificationMethodError`
 * (`name` + `code`), which the classifier matches first. These patterns are
 * the fallback for library builds that still throw plain `Error`s. They are
 * pinned by unit tests, so a library that rewords one fails a test instead of
 * quietly demoting the fault to `INVALID_SIGNATURE`. The jsonld-signatures
 * patterns, with the same problem type, are shared with the
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
  /^Verification method .+ not found\.$/,
  // did:web driver: the fragment is not in the DID document.
  /^DID document entity with id .+ not found\.$/,
  // did-method-key: the fragment is not in the did:key document.
  /^Key .+ not found in DID document\.$/
];

/** Whether a library error message names a verification method fault. */
export function isVerificationMethodMessage(message: string): boolean {
  return VERIFICATION_METHOD_PATTERNS.some(pattern => pattern.test(message));
}
