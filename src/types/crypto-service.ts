/**
 * Cryptographic verification port — hexagonal adapter boundary for proof verification.
 *
 * Implementations wrap concrete libraries (e.g. `@interop/vc` for Data
 * Integrity). The proof suite dispatches to `CryptoService` instances from
 * `VerificationContext` (phase 2).
 */

import type { DocumentLoader } from './context.js';
import type { ProblemDetail } from './problem-detail.js';
import type { VerificationSubject } from './subject.js';

/**
 * Outcome of a credential or presentation cryptographic verification.
 *
 * Failures carry pre-classified `ProblemDetail` entries (adapter-specific error mapping).
 *
 * A rejection with `proofVerified: true` says the proof itself verified
 * and the service rejected the document for another reason, such as its
 * validity dates (`CREDENTIAL_EXPIRED`, `CREDENTIAL_NOT_YET_VALID`).
 * `proof.signature` treats such a rejection as a verified signature and
 * leaves the dates to `proof.validity-period`. A service that did not
 * verify the proof leaves the flag unset, whatever its problems say.
 *
 * A document carrying a proof set is handed to the service one proof at
 * a time (`dispatchProofSetVerification`), so "the proof itself" is that
 * one proof. A service that cannot check the proof it was handed (no
 * suite supports it, or it was made for another purpose) should reject
 * with only `PROOF_UNSUPPORTED` problems. Beside a proof that verified,
 * `proof.unsupported-proofs` then reports it as a warning rather than a
 * failure.
 */
export type CryptoResult =
  | { verified: true; message?: string }
  | { verified: false; problems: ProblemDetail[]; proofVerified?: boolean };

/**
 * Options passed to crypto verification — mirrors the seams the DCC vc stack needs.
 *
 * A `CryptoService` is only asked to verify a proof that exists.
 * `signatureCheck` decides the proof-less presentation case before dispatch.
 */
export interface CryptoVerifyOptions {
  documentLoader: DocumentLoader;
  /**
   * Expected challenge on a presentation's proof. When a string, the proof
   * must use the `authentication` purpose and carry it.
   */
  challenge?: string | null;
  /** Expected `domain` on a presentation's authentication proof. */
  domain?: string;
  /**
   * The instant validity dates are judged against (`VerificationContext.now`).
   * A service that judges dates reports an expired or not-yet-valid document
   * as `CREDENTIAL_EXPIRED` / `CREDENTIAL_NOT_YET_VALID`, which the status
   * check maps onto its own problem types. The default adapter compares
   * dates exactly against it, with no clock-skew allowance, and uses the
   * current time when undefined.
   */
  now?: Date;
}

/**
 * Pluggable cryptographic verification for one proof family (e.g. Data Integrity).
 */
export interface CryptoService {
  canVerify: (subject: VerificationSubject) => boolean;
  verifyCredential: (
    credential: unknown,
    options: CryptoVerifyOptions
  ) => Promise<CryptoResult>;
  verifyPresentation: (
    presentation: unknown,
    options: CryptoVerifyOptions
  ) => Promise<CryptoResult>;
}
