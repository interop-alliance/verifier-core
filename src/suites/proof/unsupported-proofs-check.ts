import { VerificationCheck, CheckOutcome } from '../../types/check.js';
import { VerificationSubject } from '../../types/subject.js';
import { VerificationContext } from '../../types/context.js';
import {
  isUnsupportedProof,
  problemsOfProof,
  proofDocument
} from '../../crypto-dispatch.js';
import { documentHasProof } from '../../util/document-has-proof.js';
import { verifyProofSet } from './proof-set-verification.js';

/**
 * Unsupported proofs check: the proofs in a proof set that this verifier
 * could not check.
 *
 * A proof set often carries proofs for different audiences, and not
 * every verifier supports every cryptosuite. So a proof that no
 * registered suite supports, or that was made for a different proof
 * purpose, does not fail `proof.signature` when another proof verified.
 * It is reported here instead, one `PROOF_UNSUPPORTED` problem per
 * proof. The check is not fatal. It is a warning, and the proofs that
 * were checked decide the signature.
 *
 * It reads the verification `proof.signature` already ran in this run
 * (see `verifyProofSet`), so it verifies nothing itself. List it after
 * `proof.signature` in the same suite run: on its own it still works,
 * but then it verifies the proof set a second time. When the signature
 * check fails it halts, and this check is not run. A proof no
 * registered crypto service took at all is reported the same way as one
 * a service rejected as unsupported.
 */
export const unsupportedProofsCheck: VerificationCheck = {
  id: 'proof.unsupported-proofs',
  name: 'Unsupported Proofs',
  description:
    'Reports proofs in a proof set that this verifier could not check, such as a cryptosuite it does not support. A warning: the other proofs still decide the signature.',
  fatal: false,
  appliesTo: ['verifiableCredential', 'verifiablePresentation'],
  execute: async (
    subject: VerificationSubject,
    context: VerificationContext
  ): Promise<CheckOutcome> => {
    // An unsigned presentation accepted through `unsignedPresentation`:
    // there is nothing to verify, and asking the memo would dispatch.
    if (!documentHasProof(proofDocument(subject))) {
      return { status: 'skipped', reason: 'The document has no proof.' };
    }

    const { proofs } = await verifyProofSet(subject, context);
    const problems = proofs
      .filter(outcome => isUnsupportedProof(outcome.result))
      .flatMap(problemsOfProof);

    return problems.length > 0
      ? { status: 'failure', problems }
      : { status: 'success', message: 'Every proof was checked.' };
  }
};
