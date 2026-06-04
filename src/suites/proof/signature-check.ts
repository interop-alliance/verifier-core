import { VerificationCheck, CheckOutcome } from '../../types/check.js';
import { ProblemDetail } from '../../types/problem-detail.js';
import { VerificationSubject } from '../../types/subject.js';
import { VerificationContext } from '../../types/context.js';
import { ProblemTypes } from '../../problem-types.js';

const NO_APPLICABLE_SERVICE: ProblemDetail = {
  type: ProblemTypes.PROOF_VERIFICATION_ERROR,
  title: 'No Applicable Crypto Service',
  detail:
    'No registered crypto service can verify this subject (check canVerify / cryptoServices).'
};

/**
 * Signature verification check — dispatches to {@link VerificationContext.cryptoServices}.
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
    const credential = subject.verifiableCredential as
      | Record<string, unknown>
      | undefined;
    const presentation = subject.verifiablePresentation as
      | Record<string, unknown>
      | undefined;

    if (!credential && !presentation) {
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

    const services = context.cryptoServices;
    if (!services || services.length === 0) {
      return { status: 'failure', problems: [NO_APPLICABLE_SERVICE] };
    }

    const service = services.find(s => s.canVerify(subject));
    if (!service) {
      return { status: 'failure', problems: [NO_APPLICABLE_SERVICE] };
    }

    const cryptoOptions = {
      documentLoader: context.documentLoader,
      challenge: context.challenge,
      unsignedPresentation: context.unsignedPresentation
    };

    let cryptoResult;
    try {
      if (presentation) {
        cryptoResult = await service.verifyPresentation(
          presentation,
          cryptoOptions
        );
      } else {
        if (!credential) {
          return {
            status: 'failure',
            problems: [
              {
                type: ProblemTypes.PROOF_VERIFICATION_ERROR,
                title: 'No Verifiable Content',
                detail:
                  'No verifiable credential or presentation found in subject.'
              }
            ]
          };
        }
        cryptoResult = await service.verifyCredential(
          credential,
          cryptoOptions
        );
      }
    } catch (e) {
      return {
        status: 'failure',
        problems: [
          {
            type: ProblemTypes.PROOF_VERIFICATION_ERROR,
            title: 'Verification Error',
            detail:
              e instanceof Error
                ? e.message
                : 'An unexpected error occurred during signature verification.'
          }
        ]
      };
    }

    if (cryptoResult.verified) {
      return {
        status: 'success',
        message: cryptoResult.message ?? 'Signature verified successfully.'
      };
    }

    return {
      status: 'failure',
      problems: cryptoResult.problems
    };
  }
};
