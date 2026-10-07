/**
 * Proof entries of a credential or presentation.
 *
 * A proof entry is a non-null object. A single proof object counts as one
 * entry; a proof array contributes each of its non-null object entries. A
 * stray non-object entry does not hide the proofs next to it; `core.proof-exists`
 * reports it as malformed, and the signature check still runs on the real
 * proofs.
 */
export function proofEntries(doc: unknown): Array<Record<string, unknown>> {
  if (typeof doc !== 'object' || doc === null) {
    return [];
  }
  const proof = (doc as { proof?: unknown }).proof;
  return (Array.isArray(proof) ? proof : [proof]).filter(
    (entry): entry is Record<string, unknown> =>
      typeof entry === 'object' && entry !== null
  );
}

/**
 * Whether a credential or presentation carries a proof.
 *
 * Shared by the Data Integrity adapter's `canVerify` and by `signatureCheck`,
 * so "has a proof" means the same thing when choosing a crypto service and
 * when deciding whether a subject is unsigned.
 */
export function documentHasProof(doc: unknown): boolean {
  return proofEntries(doc).length > 0;
}
