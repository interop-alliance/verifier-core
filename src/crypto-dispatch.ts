/**
 * Shared crypto-service dispatch.
 *
 * Presentation proofs, credential proofs, and status-list-credential proofs
 * all resolve through this helper against the same `CryptoService[]`.
 * Callers own their problem types: the helper reports a neutral outcome so
 * a bad signature on a credential and a bad signature on its status list
 * credential stay distinct diagnostics.
 *
 * This is orchestration over injected adapters, not an adapter itself --
 * it lives at the `src/` root alongside `run-suites.ts` and
 * `fold-results.ts`, not under `src/services/`.
 */

import type {
  CryptoService,
  CryptoVerifyOptions
} from './types/crypto-service.js';
import type { ProblemDetail } from './types/problem-detail.js';
import type { VerificationSubject } from './types/subject.js';
import { ProblemTypes } from './problem-types.js';
import { errorMessage } from './util/error-message.js';

/**
 * Outcome of dispatching a proof to the registered {@link CryptoService}s.
 *
 * Deliberately *not* a `ProblemDetail`-bearing type: the two callers
 * (`signature-check` and `bitstring-status-check`) describe the same
 * underlying failures with different problem types, because a bad signature
 * on the credential and a bad signature on its status list credential are
 * different things to the consumer reading the result. Sharing the dispatch
 * must not homogenize the diagnostics.
 *
 * `rejected.proofVerified` is the service's own word
 * ({@link CryptoResult}) that the proof verified and the rejection is
 * about something else, such as the document's validity dates. It is the
 * one signal `proof.signature` and `status.bitstring` read for that;
 * neither infers it from the problem types.
 *
 * `threw` carries the thrown value plus a ready-to-display `message` so
 * callers do not each re-derive it.
 */
export type CryptoDispatchResult =
  | { kind: 'verified'; message?: string }
  | { kind: 'rejected'; problems: ProblemDetail[]; proofVerified: boolean }
  | { kind: 'no-service' }
  | { kind: 'threw'; error: unknown; message: string };

/** What both dispatch functions take. */
interface CryptoDispatchInput {
  services: CryptoService[];
  subject: VerificationSubject;
  options: CryptoVerifyOptions;
}

/**
 * Which of the subject's documents carries the proofs under verification:
 * the presentation when there is one, otherwise the credential.
 */
export function proofDocumentKey(
  subject: VerificationSubject
): 'verifiablePresentation' | 'verifiableCredential' {
  return subject.verifiablePresentation
    ? 'verifiablePresentation'
    : 'verifiableCredential';
}

/** The document whose proofs are verified; see {@link proofDocumentKey}. */
export function proofDocument(subject: VerificationSubject): unknown {
  return subject[proofDocumentKey(subject)];
}

/**
 * Select the first {@link CryptoService} that can verify `subject` and invoke
 * it. Presentations route to `verifyPresentation`, credentials to
 * `verifyCredential`; a subject carrying both prefers the presentation, which
 * matches the pre-extraction behavior of `signature-check`.
 */
export async function dispatchProofVerification({
  services,
  subject,
  options
}: CryptoDispatchInput): Promise<CryptoDispatchResult> {
  const presentation = subject.verifiablePresentation;
  const credential = subject.verifiableCredential;

  if (!presentation && !credential) {
    return { kind: 'no-service' };
  }

  try {
    // Service selection sits inside the `try` so a throwing `canVerify`
    // is reported as `threw` rather than rejecting the caller.
    const service = services.find(s => s.canVerify(subject));
    if (!service) {
      return { kind: 'no-service' };
    }

    const cryptoResult = presentation
      ? await service.verifyPresentation(presentation, options)
      : await service.verifyCredential(credential, options);

    if (cryptoResult.verified) {
      return { kind: 'verified', message: cryptoResult.message };
    }

    return {
      kind: 'rejected',
      problems: cryptoResult.problems,
      proofVerified: cryptoResult.proofVerified === true
    };
  } catch (error) {
    return {
      kind: 'threw',
      error,
      message: errorMessage(
        error,
        'An unexpected error occurred during signature verification.'
      )
    };
  }
}

/** One proof's verdict within a proof set. */
export interface ProofOutcome {
  /** 1-based position in the document's `proof` array. */
  position: number;
  /** Total proofs in the set. */
  total: number;
  /** `type`, plus `cryptosuite` when present: "DataIntegrityProof, eddsa-rdfc-2022". */
  label: string;
  result: CryptoDispatchResult;
}

export interface ProofSetDispatchResult {
  /** The verdict for the whole document, in the shape callers already handle. */
  combined: CryptoDispatchResult;
  /** Each proof's verdict; empty unless the document carries two or more proofs. */
  proofs: ProofOutcome[];
}

/** The problem a proof set's `no-service` proof is reported with. */
const NO_SERVICE_FOR_PROOF: ProblemDetail = {
  type: ProblemTypes.PROOF_UNSUPPORTED,
  title: 'Unsupported Proof',
  detail: 'No registered crypto service can verify this proof.'
};

/**
 * Whether a proof was not checked at all: no registered crypto service
 * took it, or the service rejected it only because no suite supports it
 * or it was made for another purpose.
 */
export function isUnsupportedProof(result: CryptoDispatchResult): boolean {
  if (result.kind === 'no-service') {
    return true;
  }
  return (
    result.kind === 'rejected' &&
    result.problems.length > 0 &&
    result.problems.every(p => p.type === ProblemTypes.PROOF_UNSUPPORTED)
  );
}

/**
 * A rejected or unserviced proof's problems, each `detail` saying which
 * proof of the set it is about: "Proof 2 of 2 (DataIntegrityProof,
 * eddsa-rdfc-2022): ...". Empty for a verified proof or one that threw.
 */
export function problemsOfProof(outcome: ProofOutcome): ProblemDetail[] {
  const { result } = outcome;
  let problems: ProblemDetail[];
  if (result.kind === 'rejected') {
    problems = result.problems;
  } else if (result.kind === 'no-service') {
    problems = [NO_SERVICE_FOR_PROOF];
  } else {
    return [];
  }
  const prefix = `Proof ${outcome.position} of ${outcome.total} (${outcome.label}): `;
  return problems.map(problem => ({
    ...problem,
    detail: prefix + problem.detail
  }));
}

/**
 * Verify a document's proofs one at a time, so that every proof a
 * registered suite can check must verify.
 *
 * jsonld-signatures' `ProofSet.verify` reports a proof set verified when
 * any of its proofs verified, and silently skips proofs no suite or
 * purpose matches. VC Data Integrity section 4.5 requires every proof to
 * verify instead. Handing each {@link CryptoService} call a shallow copy
 * carrying a single proof makes each verdict about exactly one proof.
 * That also keeps the `CryptoResult` contract (`proofVerified` is about
 * the one proof handed over) true for proof sets. Proof chains
 * (`previousProof`) are not supported by the underlying libraries either
 * way.
 *
 * A document with zero or one proof object is dispatched exactly as
 * {@link dispatchProofVerification} would. For a proof set, `combined`
 * is, in order:
 * - every failing proof's problems, prefixed with the proof's position
 *   and label. A definite rejection is reported ahead of anything else;
 * - the first proof that threw;
 * - the first rejection whose proof verified (`proofVerified`),
 *   unprefixed because what it reports, such as the validity dates,
 *   belongs to the document;
 * - the first verified proof;
 * - otherwise no proof was checked at all: the unsupported proofs'
 *   problems, prefixed, or `no-service` when no service took any proof.
 *
 * A proof this verifier cannot check, whether no service took it or the
 * service rejected it as `PROOF_UNSUPPORTED`, does not change `combined`
 * beside a checked proof. It is left in `proofs` for the caller to report.
 */
export async function dispatchProofSetVerification(
  input: CryptoDispatchInput
): Promise<ProofSetDispatchResult> {
  const { subject } = input;
  const key = proofDocumentKey(subject);
  const document = subject[key] as Record<string, unknown> | undefined;
  const proofSet: unknown[] = Array.isArray(document?.proof)
    ? document.proof
    : [];
  // A non-object entry is not a proof (`core.proof-exists` reports it) and
  // is not dispatched. Positions stay those of the document's array.
  const positioned = proofSet
    .map((proof, index) => ({ proof, position: index + 1 }))
    .filter(({ proof }) => typeof proof === 'object' && proof !== null);

  if (!document || positioned.length < 2) {
    return { combined: await dispatchProofVerification(input), proofs: [] };
  }

  const total = proofSet.length;
  // Copies, not edits: the signed bytes of the original document must
  // stay as they arrived.
  const proofs = await Promise.all(
    positioned.map(async ({ proof, position }): Promise<ProofOutcome> => ({
      position,
      total,
      label: proofLabel(proof),
      result: await dispatchProofVerification({
        ...input,
        subject: { ...subject, [key]: { ...document, proof } }
      })
    }))
  );

  return { combined: combineProofOutcomes(proofs), proofs };
}

/**
 * How a proof is named in a problem's `detail`: its `type`, plus its
 * `cryptosuite` when it has one, e.g. "DataIntegrityProof, eddsa-rdfc-2022".
 * Data Integrity proofs all share one `type`, so the cryptosuite is what
 * tells two of them apart.
 */
function proofLabel(proof: unknown): string {
  const { type, cryptosuite } = (proof ?? {}) as {
    type?: unknown;
    cryptosuite?: unknown;
  };
  const typeName = typeof type === 'string' ? type : 'unknown proof type';
  return typeof cryptosuite === 'string'
    ? `${typeName}, ${cryptosuite}`
    : typeName;
}

function combineProofOutcomes(proofs: ProofOutcome[]): CryptoDispatchResult {
  const unchecked: ProofOutcome[] = [];
  const verifiedButRejected: ProofOutcome[] = [];
  const failing: ProofOutcome[] = [];
  for (const outcome of proofs) {
    const { result } = outcome;
    if (isUnsupportedProof(result)) {
      unchecked.push(outcome);
    } else if (result.kind !== 'rejected') {
      continue;
    } else if (result.proofVerified) {
      verifiedButRejected.push(outcome);
    } else {
      failing.push(outcome);
    }
  }

  if (failing.length > 0) {
    return {
      kind: 'rejected',
      problems: failing.flatMap(problemsOfProof),
      proofVerified: false
    };
  }
  const threw = proofs.find(p => p.result.kind === 'threw');
  if (threw) {
    return threw.result;
  }
  if (verifiedButRejected.length > 0) {
    return verifiedButRejected[0].result;
  }
  const verified = proofs.find(p => p.result.kind === 'verified');
  if (verified) {
    return verified.result;
  }
  // Nothing was checked at all, so there is no verified proof to warn
  // beside: as fatal as a single unsupported proof.
  if (unchecked.every(p => p.result.kind === 'no-service')) {
    return { kind: 'no-service' };
  }
  return {
    kind: 'rejected',
    problems: unchecked.flatMap(problemsOfProof),
    proofVerified: false
  };
}
