import { VerificationCheck, CheckOutcome } from '../../types/check.js';
import { ProblemDetail } from '../../types/problem-detail.js';
import { VerificationSubject } from '../../types/subject.js';
import { VerificationContext } from '../../types/context.js';
import { ProblemTypes } from '../../problem-types.js';
import { documentHasProof } from '../../util/document-has-proof.js';
import { beginProofRun, verifyProofSet } from './proof-set-verification.js';

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

const PRESENTATION_NOT_SIGNED: ProblemDetail = {
  type: ProblemTypes.PROOF_VERIFICATION_ERROR,
  title: 'Presentation Not Signed',
  detail:
    'The presentation has no proof. Pass unsignedPresentation: true to accept an unsigned presentation.'
};

/**
 * Machine-readable `code` values carried on this check's `'skipped'`
 * outcomes. Branch on these rather than on the prose `reason`.
 */
export const SIGNATURE_SKIP_CODES = {
  /** The presentation has no proof and `unsignedPresentation` is set. */
  unsignedPresentation: 'unsigned-presentation'
} as const;

const UNSIGNED_PRESENTATION_ACCEPTED =
  'Presentation is unsigned; accepted because unsignedPresentation is set.';

/**
 * Signature verification check — dispatches to {@link VerificationContext.cryptoServices}.
 *
 * A credential with no `proof` fails with `No Proof` before any crypto
 * service is consulted. This keeps an unsigned credential (already
 * reported by `core.proof-exists`) from reading as a `cryptoServices`
 * configuration fault.
 *
 * A presentation must carry a proof unless
 * {@link VerificationContext.unsignedPresentation} is set. With the flag, a
 * proof-less presentation is skipped. Without it, the check fails with
 * `Presentation Not Signed`. A proof that is present is always verified,
 * whatever the flag says.
 *
 * A supplied {@link VerificationContext.challenge} (and
 * {@link VerificationContext.domain}) is always enforced on a presentation's
 * proof. `verifyPresentation` rejects a `domain` without a `challenge` before
 * any suite runs.
 *
 * A document carrying a proof set passes only when every proof a
 * registered suite can check verified (VC Data Integrity section 4.5).
 * Each proof is verified on its own (see `verifyProofSet`), and a failing
 * proof's problems name it: "Proof 2 of 2 (DataIntegrityProof,
 * eddsa-rdfc-2022): ...". Proofs no suite can check, beside one that
 * verified, do not fail this check. `proof.unsupported-proofs` reports
 * them.
 *
 * The credential's validity dates belong to `proof.validity-period`,
 * which runs after this check. A crypto service may still reject for
 * them: the default one judges the dates at
 * {@link VerificationContext.now}, and only once the proof has verified.
 * It says so with `proofVerified` on its result, and such a rejection
 * reads as success here. So an out-of-date credential is not reported as
 * forged, and does not halt the checks after it. The flag is the
 * service's word; this check does not infer it from the problem types.
 */
export const signatureCheck: VerificationCheck = {
  id: 'proof.signature',
  name: 'Signature Verification',
  description:
    'Verifies the cryptographic signature of the credential or presentation. A presentation must be signed unless unsignedPresentation is set.',
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

    const presentation = subject.verifiablePresentation;
    if (presentation) {
      if (!documentHasProof(presentation)) {
        return context.unsignedPresentation === true
          ? {
              status: 'skipped',
              reason: UNSIGNED_PRESENTATION_ACCEPTED,
              code: SIGNATURE_SKIP_CODES.unsignedPresentation
            }
          : { status: 'failure', problems: [PRESENTATION_NOT_SIGNED] };
      }
    } else if (!documentHasProof(subject.verifiableCredential)) {
      return { status: 'failure', problems: [NO_PROOF] };
    }

    beginProofRun(context);
    const dispatched = (await verifyProofSet(subject, context)).combined;

    switch (dispatched.kind) {
      case 'verified':
        return {
          status: 'success',
          message: dispatched.message ?? 'Signature verified successfully.'
        };
      case 'rejected':
        if (dispatched.proofVerified) {
          return {
            status: 'success',
            message: 'Signature verified successfully.'
          };
        }
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
