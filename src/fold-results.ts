/**
 * Pure helper that folds a `CheckResult[]` (the raw
 * `runSuites` output) into a compact, UI-friendly
 * `{ results, summaries }` view.
 *
 * Called from `verifier.ts` after `runSuites` returns and after
 * the recognition payload has been lifted onto the result. The
 * helper has no I/O, no async, and no service dependencies — it
 * is safe to call from any context (incl. consumers refolding
 * after appending late results, e.g. dcc-transaction-service's
 * async OpenBadges merge).
 *
 * In **non-verbose** mode (the default), `results[]` carries
 * only failures and explicit `<suite>.applies` skips; everything
 * else is folded into the per-suite rollup on `summaries[]`. In
 * **verbose** mode `results[]` is the raw input, unchanged.
 *
 * `summaries[]` is always populated with one entry per (phase,
 * suite) that emitted at least one `CheckResult`. Suites that
 * silently no-op'd (predicate false, not explicitly queued) emit
 * nothing in either array, mirroring `runSuites`'s behavior.
 *
 * @see SuiteSummary
 * @see CheckResult
 * @see computeId
 */

import {
  type CheckResult,
  type SuitePhase,
  type VerificationSuite,
  RUN_SUITES_SKIP_CODES
} from './types/check.js';
import type { SuiteSummary, SuiteSummaryPhase } from './types/suite-summary.js';
import type { TaskTiming } from './types/timing.js';

export interface FoldOptions {
  /**
   * If true, `results[]` carries every `CheckResult` from the
   * input. If false (default), `results[]` carries only failures
   * and explicit `<suite>.applies` skips.
   */
  verbose?: boolean;
}

export function foldCheckResults(
  checks: CheckResult[],
  suites: VerificationSuite[],
  opts: FoldOptions = {}
): { results: CheckResult[]; summaries: SuiteSummary[] } {
  if (checks.length === 0 && suites.length === 0) {
    return { results: [], summaries: [] };
  }

  const suiteIndex = indexSuitesById(suites);
  const grouped = groupChecksBySuite(checks);
  const summaries: SuiteSummary[] = [];

  for (const [suiteId, suiteChecks] of grouped) {
    const suiteDef = suiteIndex.get(suiteId);
    const phase = derivePhase(suiteDef);
    summaries.push(summarizeSuite(suiteId, phase, suiteChecks));
  }

  const results = selectResultsForVerbosity(checks, opts.verbose === true);
  return { results, summaries };
}

/**
 * Compute the dot-separated namespaced id for a single
 * `CheckResult` or `SuiteSummary`.
 *
 * Rules:
 *  - Strip the `<suite>.` prefix from `localCheckId` if present.
 *  - When `phase === suite`, collapse to a single segment.
 *  - When `phase` is missing, use `'unknown'`.
 *  - When `localCheckId` is empty (suite-summary case), drop the
 *    trailing segment.
 *
 * @example
 *   computeId('cryptographic', 'core', 'core.proof-exists')
 *     // → 'cryptographic.core.proof-exists'
 *   computeId('recognition', 'recognition', 'recognition.profile')
 *     // → 'recognition.profile'
 *   computeId('cryptographic', 'core', '')
 *     // → 'cryptographic.core'
 */
export function computeId(
  phase: SuitePhase | undefined,
  suite: string,
  localCheckId: string
): string {
  const phaseSeg: SuiteSummaryPhase = phase ?? 'unknown';
  const localPart = localCheckId.startsWith(`${suite}.`)
    ? localCheckId.slice(suite.length + 1)
    : localCheckId;
  const segments: string[] =
    phaseSeg === suite ? [phaseSeg, localPart] : [phaseSeg, suite, localPart];
  return segments.filter(Boolean).join('.');
}

// ----------------------------------------------------------------
// helpers
// ----------------------------------------------------------------

function indexSuitesById(
  suites: VerificationSuite[]
): Map<string, VerificationSuite> {
  const m = new Map<string, VerificationSuite>();
  for (const s of suites) {
    m.set(s.id, s);
  }
  return m;
}

/**
 * Group input checks by suite id, preserving first-seen suite
 * order so `summaries[]` matches the suite execution order from
 * `runSuites`.
 */
function groupChecksBySuite(checks: CheckResult[]): Map<string, CheckResult[]> {
  const m = new Map<string, CheckResult[]>();
  for (const c of checks) {
    const arr = m.get(c.suite);
    if (arr) {
      arr.push(c);
    } else {
      m.set(c.suite, [c]);
    }
  }
  return m;
}

function derivePhase(
  suite: VerificationSuite | undefined
): SuitePhase | undefined {
  return suite?.phase;
}

/**
 * Reduce a single suite's `CheckResult[]` into one `SuiteSummary`.
 */
function summarizeSuite(
  suiteId: string,
  phase: SuitePhase | undefined,
  suiteChecks: CheckResult[]
): SuiteSummary {
  const tally = tallySuite(suiteChecks);
  const counts = {
    passed: tally.passed,
    failed: tally.failed,
    skipped: tally.skipped + tally.notRun
  };

  const fatalCheck = suiteChecks.find(
    c => c.fatal === true && c.outcome.status === 'failure'
  );
  const fatalFailureAt = fatalCheck?.id;

  const status = deriveStatus(counts);
  const verified = fatalCheck === undefined;

  const message = formatMessage(
    suiteId,
    tally,
    pickAppliesSkipReason(suiteChecks, suiteId)
  );

  const timing = rollupSuiteTiming(suiteChecks);

  return {
    id: computeId(phase, suiteId, ''),
    phase: phase ?? 'unknown',
    suite: suiteId,
    status,
    verified,
    message,
    counts,
    ...(fatalFailureAt !== undefined ? { fatalFailureAt } : {}),
    ...(timing !== undefined ? { timing } : {})
  };
}

/**
 * Roll a suite's child-check timings into a single
 * suite-level {@link TaskTiming}, or return `undefined` when
 * none of the children carried `timing` (i.e. the call ran
 * without `timing: true`).
 *
 *  - `startedAt` = earliest child `startedAt` (lex-min of ISO
 *    strings, which is correct because all are UTC `Z`-suffixed).
 *  - `endedAt`   = latest child `endedAt`.
 *  - `durationMs` = sum of child `durationMs`. The summed-CPU
 *    semantic is intentional: it is what consumers actually
 *    want when comparing suite cost — `endedAt - startedAt`
 *    would also include any inter-check gap (e.g. event-loop
 *    yields in the orchestrator), which is not part of the
 *    suite's own work.
 *
 * Computed before checks are folded out of `results[]`, so the
 * rollup survives `verbose: false` consumers.
 */
function rollupSuiteTiming(suiteChecks: CheckResult[]): TaskTiming | undefined {
  const timed = suiteChecks
    .map(c => c.timing)
    .filter((t): t is TaskTiming => t !== undefined);
  if (timed.length === 0) {
    return undefined;
  }

  let startedAt = timed[0].startedAt;
  let endedAt = timed[0].endedAt;
  let durationMs = 0;
  for (const t of timed) {
    if (t.startedAt < startedAt) {
      startedAt = t.startedAt;
    }
    if (t.endedAt > endedAt) {
      endedAt = t.endedAt;
    }
    durationMs += t.durationMs;
  }
  return { startedAt, endedAt, durationMs };
}

function deriveStatus(counts: {
  passed: number;
  failed: number;
  skipped: number;
}): SuiteSummary['status'] {
  if (counts.failed > 0 && counts.passed > 0) {
    return 'mixed';
  }
  if (counts.failed > 0) {
    return 'failure';
  }
  if (counts.passed > 0) {
    return 'success';
  }
  return 'skipped';
}

/**
 * If the only `CheckResult` for this suite is the synthetic
 * `<suite>.applies` skip emitted by `runSuites` for an
 * explicitly-queued suite whose `applies` predicate returned
 * false, return that outcome's `reason`. Otherwise undefined.
 */
function pickAppliesSkipReason(
  suiteChecks: CheckResult[],
  suiteId: string
): string | undefined {
  if (suiteChecks.length !== 1) {
    return undefined;
  }
  const only = suiteChecks[0];
  if (only.outcome.status !== 'skipped') {
    return undefined;
  }
  if (only.check !== `${suiteId}.applies`) {
    return undefined;
  }
  return only.outcome.reason;
}

/**
 * Per-outcome counts for one suite, in a single pass. "Not run" rows
 * (skips with code {@link RUN_SUITES_SKIP_CODES.notRunAfterFatal})
 * are tallied apart from ordinary skips, and `haltedBy` records the
 * halting check id from the first of them.
 */
interface SuiteTally {
  passed: number;
  failed: number;
  skipped: number;
  notRun: number;
  haltedBy: string | undefined;
}

function tallySuite(suiteChecks: CheckResult[]): SuiteTally {
  const tally: SuiteTally = {
    passed: 0,
    failed: 0,
    skipped: 0,
    notRun: 0,
    haltedBy: undefined
  };
  for (const { outcome } of suiteChecks) {
    if (outcome.status === 'success') {
      tally.passed += 1;
    } else if (outcome.status === 'failure') {
      tally.failed += 1;
    } else if (outcome.code === RUN_SUITES_SKIP_CODES.notRunAfterFatal) {
      tally.notRun += 1;
      tally.haltedBy ??= outcome.haltedBy;
    } else {
      tally.skipped += 1;
    }
  }
  return tally;
}

/**
 * Build the human-readable `SuiteSummary.message`. See
 * `SuiteSummary.message` TSDoc for the exact wording conventions.
 *
 * The message always reads in one direction, `<passed> of <total>
 * checks passed`, so a column of suite rows compares at a glance.
 * Non-zero failed / skipped / not-run counts follow in parentheses.
 * Two exceptions name a cause instead: a suite whose `applies`
 * predicate declined, and a suite every check of which was halted by
 * an earlier suite's fatal failure.
 */
function formatMessage(
  suiteId: string,
  tally: SuiteTally,
  appliesSkipReason: string | undefined
): string {
  if (appliesSkipReason !== undefined) {
    return `${suiteId} not applicable: ${appliesSkipReason}`;
  }

  const total = tally.passed + tally.failed + tally.skipped + tally.notRun;

  // Every row is a halt skip: an earlier suite's fatal failure stopped
  // the whole suite. A row without `haltedBy` was not built by
  // `runSuites`; fall through to the counted form for it.
  if (tally.notRun === total && tally.haltedBy !== undefined) {
    return `${suiteId} not run: ${tally.haltedBy} failed`;
  }

  const tail: string[] = [];
  if (tally.failed > 0) {
    tail.push(`${tally.failed} failed`);
  }
  if (tally.skipped > 0) {
    tail.push(`${tally.skipped} skipped`);
  }
  if (tally.notRun > 0) {
    tail.push(`${tally.notRun} not run after fatal`);
  }
  const tailStr = tail.length > 0 ? ` (${tail.join(', ')})` : '';
  return `${tally.passed} of ${total} ${pluralCheck(total)} passed${tailStr}`;
}

function pluralCheck(n: number): 'check' | 'checks' {
  return n === 1 ? 'check' : 'checks';
}

/**
 * Choose which checks to surface in `results[]` based on
 * `verbose`. See module-level docs for the rules.
 */
function selectResultsForVerbosity(
  checks: CheckResult[],
  verbose: boolean
): CheckResult[] {
  if (verbose) {
    return checks;
  }
  return checks.filter(isFailureOrExplicitSkip);
}

function isFailureOrExplicitSkip(c: CheckResult): boolean {
  if (c.outcome.status === 'failure') {
    return true;
  }
  if (c.outcome.status === 'skipped' && c.check.endsWith('.applies')) {
    return true;
  }
  return false;
}
