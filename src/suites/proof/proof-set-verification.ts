import {
  dispatchProofSetVerification,
  proofDocument,
  type ProofSetDispatchResult
} from '../../crypto-dispatch.js';
import type { VerificationContext } from '../../types/context.js';
import type { VerificationSubject } from '../../types/subject.js';

/**
 * Proof verifications of the current proof-suite run, by document, keyed
 * by the context the run received. `proof.signature` starts the run with
 * {@link beginProofRun}, which drops whatever an earlier run on the same
 * context left, then verifies; `proof.unsupported-proofs` reads the same
 * verdict through {@link verifyProofSet}. So each document is verified
 * once per run, and a verdict never outlives one run on a context. The
 * same shape as the status suite's `beginStatusListRun`.
 */
const verifiedProofs = new WeakMap<
  VerificationContext,
  WeakMap<object, Promise<ProofSetDispatchResult>>
>();

/** Start a fresh record of proof verifications for this context. */
export function beginProofRun(context: VerificationContext): void {
  verifiedProofs.set(context, new WeakMap());
}

/**
 * Verify the proofs of the subject's document (its presentation if it
 * has one, otherwise its credential), one proof at a time when the
 * document carries a proof set. Within a run begun with
 * {@link beginProofRun}, a document is verified once and the verdict is
 * shared. Outside a run, every call verifies.
 */
export function verifyProofSet(
  subject: VerificationSubject,
  context: VerificationContext
): Promise<ProofSetDispatchResult> {
  const document = proofDocument(subject);
  const byDocument = verifiedProofs.get(context);
  if (
    byDocument === undefined ||
    document === null ||
    typeof document !== 'object'
  ) {
    return dispatch(subject, context);
  }

  let pending = byDocument.get(document);
  if (!pending) {
    pending = dispatch(subject, context);
    byDocument.set(document, pending);
  }
  return pending;
}

function dispatch(
  subject: VerificationSubject,
  context: VerificationContext
): Promise<ProofSetDispatchResult> {
  return dispatchProofSetVerification({
    services: context.cryptoServices,
    subject,
    options: {
      documentLoader: context.documentLoader,
      challenge: context.challenge,
      domain: context.domain,
      now: context.now
    }
  });
}
