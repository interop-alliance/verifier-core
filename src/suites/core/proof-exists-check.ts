import { VerificationCheck, CheckOutcome } from '../../types/check.js';
import { VerificationSubject } from '../../types/subject.js';
import { VerificationContext } from '../../types/context.js';
import { ProblemTypes } from '../../problem-types.js';
import { proofEntries } from '../../util/document-has-proof.js';

/**
 * Check that a proof property exists on the credential.
 * This is a fatal check - we cannot verify without a proof.
 */
export const proofExistsCheck: VerificationCheck = {
  id: 'core.proof-exists',
  name: 'Proof Exists',
  description: 'Verifies that the credential has a proof property.',
  fatal: true,
  appliesTo: ['verifiableCredential'],
  execute: async (
    subject: VerificationSubject,
    _context: VerificationContext
  ): Promise<CheckOutcome> => {
    const credential = subject.verifiableCredential as
      Record<string, unknown> | undefined;

    if (!credential) {
      return {
        status: 'failure',
        problems: [
          {
            type: ProblemTypes.PROOF_VERIFICATION_ERROR,
            title: 'No Proof',
            detail: 'No verifiable credential found in subject.'
          }
        ]
      };
    }

    const entries = proofEntries(credential);
    if (entries.length === 0) {
      return {
        status: 'failure',
        problems: [
          {
            type: ProblemTypes.PROOF_VERIFICATION_ERROR,
            title: 'No Proof',
            detail: 'Credential is missing required proof property.'
          }
        ]
      };
    }

    // A proof array must hold only proof objects.
    const proof = credential.proof;
    if (Array.isArray(proof) && entries.length !== proof.length) {
      return {
        status: 'failure',
        problems: [
          {
            type: ProblemTypes.PROOF_VERIFICATION_ERROR,
            title: 'No Proof',
            detail: 'Credential proof property is invalid.'
          }
        ]
      };
    }

    return {
      status: 'success',
      message: 'Credential has a valid proof property.'
    };
  }
};
