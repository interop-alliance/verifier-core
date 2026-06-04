/**
 * Cryptographic suite and proof-purpose types for the verification stack.
 *
 * These are thin aliases over the shared `@interop/jsonld-signatures` types so the
 * verifier speaks the same vocabulary as the rest of the `@interop/*` ecosystem
 * (`@interop/vc`, `@interop/data-integrity-proof`, `@interop/ed25519-signature`),
 * rather than maintaining loosened local port duplicates.
 */

import type {
  LinkedDataProof,
  ProofPurpose as JsigsProofPurpose
} from '@interop/jsonld-signatures';

/**
 * Any cryptographic suite accepted by `@interop/vc` for verification — e.g.
 * `Ed25519Signature2020` or `DataIntegrityProof`, both of which extend
 * `LinkedDataProof`.
 */
export type CryptoSuite = LinkedDataProof;

/**
 * A proof purpose used during verification (`AssertionProofPurpose`,
 * `AuthenticationProofPurpose`, etc.), passed to `@interop/vc` as the
 * `purpose` / `presentationPurpose` option.
 */
export type ProofPurpose = JsigsProofPurpose;
