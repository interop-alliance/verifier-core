/**
 * The verification subject passed to each check's `execute` function.
 *
 * A subject carries either a credential, a presentation, or both. Both
 * fields are optional because checks declare via `appliesTo` which type
 * they operate on — the orchestrator skips checks that don't match.
 *
 * The values are `unknown`: the envelope gate checks only that the few
 * properties the pipeline needs are readable, and the `core` suite judges
 * the structure. Checks read the shape they need defensively.
 */
export interface VerificationSubject {
  verifiableCredential?: unknown;
  verifiablePresentation?: unknown;
}
