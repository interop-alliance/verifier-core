import { VerificationCheck, CheckOutcome } from '../../types/check.js';
import { ProblemDetail } from '../../types/problem-detail.js';
import { VerificationSubject } from '../../types/subject.js';
import { VerificationContext } from '../../types/context.js';
import { ProblemTypes } from '../../problem-types.js';
import { dispatchProofVerification } from '../../crypto-dispatch.js';

const NO_APPLICABLE_SERVICE: ProblemDetail = {
  type: ProblemTypes.PROOF_VERIFICATION_ERROR,
  title: 'No Applicable Crypto Service',
  detail:
    'No registered crypto service can verify this subject (check canVerify / cryptoServices).'
};

const NO_PROOF: ProblemDetail = {
  type: ProblemTypes.PROOF_VERIFICATION_ERROR,
  title: 'No Proof',
  detail: 'Subject has no proof to verify.'
};

function hasProof(doc: unknown): boolean {
  if (typeof doc !== 'object' || doc === null) {
    return false;
  }
  const proof = (doc as { proof?: unknown }).proof;
  if (Array.isArray(proof)) {
    return proof.length > 0;
  }
  return typeof proof === 'object' && proof !== null;
}

/**
 * Signature verification check — dispatches to {@link VerificationContext.cryptoServices}.
 *
 * A subject with no `proof` fails with `No Proof` before any crypto
 * service is consulted. This keeps an unsigned credential (already
 * reported by `core.proof-exists`) from reading as a `cryptoServices`
 * configuration fault. An unsigned presentation verified with
 * `unsignedPresentation: true` is exempt and still goes to dispatch.
 */
export const signatureCheck: VerificationCheck = {
  id: 'proof.signature',
  name: 'Signature Verification',
  description:
    'Verifies the cryptographic signature of the credential or presentation.',
  fatal: true,
  appliesTo: ['verifiableCredential', 'verifiablePresentation'],
  execute: async (
    subject: VerificationSubject,
    context: VerificationContext
  ): Promise<CheckOutcome> => {
    if (!subject.verifiableCredential && !subject.verifiablePresentation) {
      return {
        status: 'failure',
        problems: [
          {
            type: ProblemTypes.PROOF_VERIFICATION_ERROR,
            title: 'No Verifiable Content',
            detail: 'No verifiable credential or presentation found in subject.'
          }
        ]
      };
    }

    const document =
      subject.verifiablePresentation ?? subject.verifiableCredential;
    const unsignedAllowed =
      subject.verifiablePresentation !== undefined &&
      context.unsignedPresentation === true;
    if (!unsignedAllowed && !hasProof(document)) {
      return { status: 'failure', problems: [NO_PROOF] };
    }

    const dispatched = await dispatchProofVerification({
      services: context.cryptoServices,
      subject,
      options: {
        documentLoader: context.documentLoader,
        challenge: context.challenge,
        unsignedPresentation: context.unsignedPresentation
      }
    });

    switch (dispatched.kind) {
      case 'verified':
        return {
          status: 'success',
          message: dispatched.message ?? 'Signature verified successfully.'
        };
      case 'rejected':
        return { status: 'failure', problems: dispatched.problems };
      case 'no-service':
        return { status: 'failure', problems: [NO_APPLICABLE_SERVICE] };
      case 'threw':
        return {
          status: 'failure',
          problems: [
            {
              type: ProblemTypes.PROOF_VERIFICATION_ERROR,
              title: 'Verification Error',
              detail: dispatched.message
            }
          ]
        };
    }
  }
};
