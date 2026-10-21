/**
 * Core verification primitives: suites, checks, and outcomes.
 *
 * These types form the plugin contract for the verification pipeline.
 * Each suite is a named group of checks; each check returns a discriminated
 * outcome (success / failure / skip). The orchestrator in `run-suites.ts`
 * iterates suites and assembles a flat `CheckResult[]` report.
 *
 * @see {@link ../run-suites.ts} for orchestration
 * @see {@link ../defaults.ts} for the default suite ordering
 */

import type { ProblemDetail } from './problem-detail.js';
import type { VerificationSubject } from './subject.js';
import type { VerificationContext } from './context.js';
import type { TaskTiming } from './timing.js';

/**
 * Discriminated outcome of a single verification check.
 *
 * - **success** — the check passed; `message` describes what was validated.
 * - **failure** — the check found a problem; `problems` carries one or more
 *   RFC 9457-style `ProblemDetail` entries.
 * - `payload`, on a success or failure, is check-specific data: what the
 *   check learned, so a consumer need not parse it out of the prose.
 * - **skipped** — the check was irrelevant to this input (e.g. no
 *   `credentialStatus`); `reason` explains why. `code`, when present, is a
 *   stable machine-readable discriminator for the skip cause — consumers
 *   that need to branch on *why* a check was skipped must use it rather
 *   than parsing `reason` (which is prose and may be reworded). Each
 *   check documents and exports its own code catalog (e.g.
 *   `SIGNATURE_SKIP_CODES`); codes are only comparable within the check
 *   that emitted them. `haltedBy` is set only on the orchestrator's
 *   `NOT_RUN_AFTER_FATAL` rows and names the qualified id of the fatal
 *   failure that halted the subject.
 *
 * Checks never throw for verification failures — they return a failure outcome.
 * Throws are reserved for unexpected infrastructure errors; the orchestrator
 * contains them as `CHECK_ERROR` failures (see `run-suites.ts`).
 */
export type CheckOutcome =
  | { status: 'success'; message: string; payload?: unknown }
  | { status: 'failure'; problems: ProblemDetail[]; payload?: unknown }
  | { status: 'skipped'; reason: string; code?: string; haltedBy?: string };

/**
 * Machine-readable `code` values on the `'skipped'` rows the orchestrator
 * itself emits (as opposed to codes a check emits for its own skips).
 * Branch on these rather than on the prose `reason`.
 */
export const RUN_SUITES_SKIP_CODES = {
  /**
   * The check would have run but an earlier fatal failure halted the
   * subject. The row's `haltedBy` carries the qualified id of the
   * halting failure; the `reason` reads `Not run: <check-id> failed`.
   */
  notRunAfterFatal: 'NOT_RUN_AFTER_FATAL'
} as const;

/**
 * Tagged outcome emitted by the suite orchestrator.
 *
 * Wraps a `CheckOutcome` with metadata identifying which suite and check
 * produced it. The flat `CheckResult[]` array is the primary report
 * structure returned by `verifyCredential`. When the producing call
 * ran with `timing: true`, each result also carries
 * {@link CheckResult.timing}.
 */
export interface CheckResult {
  /**
   * Dot-separated namespaced id — `<phase>.<suite>.<localPart>`
   * (e.g. `"cryptographic.proof.signature"`). When `phase === suite`
   * the duplicate segment collapses (e.g. `"recognition.profile"`).
   *
   * A suite with no `phase` produces ids beginning `"unknown."`.
   *
   * Populated by `runSuites` on every row it emits. This is the
   * identity to match on.
   */
  id: string;

  /**
   * Suite id this check belongs to, e.g. `"core"`. Mirrors
   * `SuiteSummary.suite` and is how rows are grouped into summaries.
   * It cannot be recovered from {@link CheckResult.id}, because a
   * suite id may itself contain dots.
   */
  suite: string;

  outcome: CheckOutcome;
  /**
   * Whether this check was marked fatal in its suite definition.
   * Only a fatal failure makes the overall `verified` (and the owning
   * `SuiteSummary.verified`) false; a non-fatal failure is reported in
   * `results[]` and `SuiteSummary.status` / `counts` but leaves
   * `verified` untouched. Whether a fatal failure also halted later
   * checks is {@link CheckResult.halts}. A `'skipped'` "not run" row
   * carries its check's flag too, but only a `'failure'` counts as
   * fatal.
   */
  fatal?: boolean;
  /**
   * Copied from {@link VerificationCheck.halts} when the check sets it.
   * Absent, a fatal check halts.
   */
  halts?: boolean;
  /**
   * Per-check timing data. Only populated when the producing
   * call ran with `timing: true` on `VerifierConfig` or
   * per-call. See {@link TaskTiming}.
   */
  timing?: TaskTiming;
}

/**
 * Subject types that a check can apply to.
 *
 * Used by `VerificationCheck.appliesTo` to limit a check to credentials,
 * presentations, or both. The orchestrator skips checks whose `appliesTo`
 * doesn't match the current subject.
 */
export const SUBJECT_TYPES = [
  'verifiableCredential',
  'verifiablePresentation'
] as const;
export type VerificationSubjectType = (typeof SUBJECT_TYPES)[number];

/**
 * Suite-phase classification for the two-pass verification workflow.
 *
 * Lets consumers run subsets of the pipeline by passing
 * `phases: [...]` on `VerifierConfig` or per-call. Untagged suites
 * bypass the filter (run in every phase request) — every built-in
 * suite is required to be tagged so the filter is meaningful.
 *
 * - **cryptographic** — structural + signature + status; the work
 *   that must happen first to establish the credential is what it
 *   says it is.
 * - **trust** — trust-layer evaluations like issuer / DID registry
 *   recognition (currently {@link registrySuite}; expected to grow
 *   as additional trust signals are added).
 * - **recognition** — pluggable credential recognition; produces
 *   the normalized credential form. Auto-included when `'semantic'`
 *   is requested (semantic checks may consume the normalized form).
 * - **semantic** — content-aware semantic checks (e.g. OB
 *   cross-field, future verticals).
 *
 * The canonical use case is a two-pass workflow:
 * 1. First pass with no `phases` (or `['cryptographic', 'trust']`)
 *    — full crypto verification of a presentation and its embedded
 *    credentials.
 * 2. Second pass with `phases: ['semantic']` and the
 *    profile-specific suites in `additionalSuites` — re-runs only
 *    the semantic work (recognition is auto-included).
 *
 * The union of both passes' `results` is what a single full-phase
 * pass would have produced.
 */
export type SuitePhase = 'cryptographic' | 'trust' | 'recognition' | 'semantic';

/**
 * A single verification check — the smallest unit of verification logic.
 *
 * Checks are pure async functions: given a subject and context, they return
 * a `CheckOutcome`. They should not have side effects beyond reading from
 * the context's services (document loader, registries, etc.).
 */
export interface VerificationCheck {
  id: string;
  name: string;
  description?: string;
  /** Restricts this check to specific subject types. Unset = runs for all. */
  appliesTo?: readonly VerificationSubjectType[];
  /**
   * If true, a failure makes the subject's `verified` false and, unless
   * {@link VerificationCheck.halts} is `false`, halts every remaining
   * check for the subject, in this suite and all later suites. Checks
   * that would have run are reported as `'skipped'` with code
   * {@link RUN_SUITES_SKIP_CODES.notRunAfterFatal}.
   */
  fatal?: boolean;
  /**
   * Whether a fatal failure halts every later check for the subject.
   * Defaults to `fatal`. Set `halts: false` on a fatal check whose
   * failure leaves later checks still meaningful. The failure still
   * makes `verified` false, but later checks run.
   */
  halts?: boolean;
  execute: (
    subject: VerificationSubject,
    context: VerificationContext
  ) => Promise<CheckOutcome>;
}

/**
 * A named, ordered collection of checks — the unit of verification configuration.
 *
 * Suites run sequentially. Within a suite, checks run in array order.
 * Callers can extend the default suites via `additionalSuites` in the
 * options object, or replace them entirely by calling `runSuites` directly.
 */
export interface VerificationSuite {
  id: string;
  name: string;
  description?: string;
  checks: VerificationCheck[];
  /**
   * Optional predicate gating whether this suite runs against the
   * given subject. When false, the orchestrator silently skips —
   * unless the consumer explicitly queued the suite via
   * `additionalSuites`, in which case a synthetic
   * `<suite-id>.applies` `'skipped'` `CheckResult` is emitted so
   * the consumer sees their explicit request was dropped.
   */
  applies?: (
    subject: VerificationSubject,
    context: VerificationContext
  ) => boolean;
  /**
   * Suite-phase tag for the two-pass verification filter; see
   * {@link SuitePhase}. Untagged suites bypass the filter (run in
   * every phase request). All built-in suites are required to be
   * tagged so a `phases:` request reliably partitions them.
   */
  phase?: SuitePhase;
}
