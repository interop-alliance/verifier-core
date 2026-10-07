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
 */
export type CryptoResult =
  | { verified: true; message?: string }
  | { verified: false; problems: ProblemDetail[] };

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
