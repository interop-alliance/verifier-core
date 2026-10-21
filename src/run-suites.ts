/**
 * Suite orchestration engine.
 *
 * `runSuites` is the core loop of the verification pipeline: it iterates
 * suites in order, applies any per-suite `applies` predicate, runs each
 * check, respects `appliesTo` filtering and `fatal` / `halts`
 * short-circuiting, and returns a flat `CheckResult[]` report.
 *
 * Invariants:
 * - The first failure of a halting check (fatal, and `halts` not
 *   `false`) halts the subject: no later check executes, in the same
 *   suite or any later one. Each check that would have run is reported
 *   as a `'skipped'` row with code
 *   {@link RUN_SUITES_SKIP_CODES.notRunAfterFatal}, `haltedBy` naming the
 *   failed check, and reason `Not run: <check-id> failed`, so the report
 *   still lists it. A fatal check with `halts: false` still counts
 *   against `verified`, but later checks run.
 * - A throw never escapes. A throwing `execute` or `applies` becomes a
 *   `failure` result carrying {@link ProblemTypes.CHECK_ERROR}, so
 *   `runSuites` always resolves.
 *
 * This module is pure orchestration — it has no knowledge of what any
 * check actually does.
 */

import {
  VerificationSuite,
  VerificationCheck,
  CheckResult,
  CheckOutcome,
  SuitePhase,
  SUBJECT_TYPES,
  RUN_SUITES_SKIP_CODES
} from './types/check.js';
import { VerificationContext } from './types/context.js';
import { ProblemTypes } from './problem-types.js';
import { errorMessage } from './util/error-message.js';
import { VerificationSubject } from './types/subject.js';
import type { TimeService } from './services/time-service/time-service.js';
import type { TaskTiming } from './types/timing.js';
import { computeId } from './fold-results.js';
import { checkAppliesTo } from './util/check-applies.js';

/**
 * Optional orchestration knobs.
 *
 * - `explicitSuiteIds`: ids of suites the consumer queued
 *   themselves (typically via `additionalSuites`). When a suite's
 *   `applies` predicate returns false, suites in this set still
 *   surface a synthetic `<suite-id>.applies` `'skipped'`
 *   `CheckResult` so the consumer sees their explicit request was
 *   dropped. Suites not in this set silently skip.
 * - `phases`: when set, only suites whose `phase` matches one of
 *   the requested phases run. Untagged suites bypass the filter
 *   (run in every phase request); this is intentional so consumer
 *   suites added via `additionalSuites` without a phase tag still
 *   execute regardless of the filter. The `recognition` auto-include
 *   when `'semantic'` is requested is the verifier-layer's
 *   responsibility, not this function's — pass an already-expanded
 *   list.
 */
export interface RunSuitesOptions {
  explicitSuiteIds?: ReadonlySet<string>;
  phases?: SuitePhase[];
}

/**
 * Whether a suite is permitted to run under the current
 * phase filter. See {@link RunSuitesOptions.phases}.
 */
function suiteRunsInPhases(
  suite: VerificationSuite,
  phases: SuitePhase[] | undefined
): boolean {
  if (phases === undefined) {
    return true;
  }
  if (suite.phase === undefined) {
    return true;
  }
  return phases.includes(suite.phase);
}

/**
 * Check if a verification check applies to the given subject: its
 * `appliesTo` (see {@link checkAppliesTo}) must admit one of the
 * subject types the subject carries.
 */
function appliesToSubject(
  check: VerificationCheck,
  subject: VerificationSubject
): boolean {
  return checkAppliesTo(
    check,
    SUBJECT_TYPES.filter(type => subject[type] !== undefined)
  );
}

/**
 * Run a list of verification suites sequentially against a subject.
 *
 * - Suites whose `phase` is excluded by `options.phases` are
 *   silently skipped (no synthetic result emitted, even when the
 *   suite is in `explicitSuiteIds` — the consumer asked for a
 *   subset and will see only that subset). Untagged suites bypass
 *   the phase filter.
 * - Suites with an `applies` predicate that returns false are
 *   silently skipped, except when their id appears in
 *   `options.explicitSuiteIds` — in which case a synthetic
 *   `<suite-id>.applies` `'skipped'` `CheckResult` is emitted.
 * - A throwing `applies` predicate becomes a `<suite-id>.applies`
 *   `failure` carrying `CHECK_ERROR`, and that suite's checks do not
 *   run. The row is fatal when the suite has a fatal check that applies
 *   to the subject (a suite that could have failed the subject must not
 *   silently pass). A fatal row halts whatever the suite's checks set
 *   for `halts`, since the throw leaves every check in the suite
 *   unknown. After a halt the throw is not reported; the suite's
 *   checks are listed as not run instead.
 * - Checks are executed in order within each suite.
 * - Checks with `appliesTo` restrictions are skipped if they don't match the subject.
 * - A throwing check becomes a `failure` carrying `CHECK_ERROR`, and
 *   keeps the check's own `fatal` flag.
 * - A failure of a halting check (see {@link haltsOnFailure}) halts
 *   every remaining check for the subject, in this suite and all later
 *   suites. Each check that would have run is
 *   reported as `'skipped'` with code `NOT_RUN_AFTER_FATAL`, `haltedBy`
 *   naming the failed check, and reason `Not run: <check-id> failed`.
 *   Phase filtering and `applies` are still evaluated after a halt, so
 *   suites that would not have run stay silent.
 * - Every result carries its namespaced `id` (see `computeId`).
 * - Returns a flat array of all check results.
 */
export async function runSuites(
  suites: VerificationSuite[],
  subject: VerificationSubject,
  context: VerificationContext,
  options: RunSuitesOptions = {}
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  const timing = context.timing === true;
  const timeService = context.timeService;
  /** Qualified id of the first halting failure; once set, no check executes. */
  let haltedBy: string | undefined;

  for (const suite of suites) {
    if (!suiteRunsInPhases(suite, options.phases)) {
      continue;
    }

    const applies = evaluateApplies(suite, subject, context);

    // A throwing predicate is reported once, before any halt. Once
    // halted, nothing in the suite would have run anyway, so the throw
    // is not reported and the suite's checks are listed as not run.
    if (applies.threw && haltedBy === undefined) {
      const checkId = `${suite.id}.applies`;
      // A suite that could have failed the subject must not silently pass.
      // The throw leaves every check in the suite unknown, so any fatal
      // check halts here, whatever its `halts` says.
      const fatal = suite.checks.some(
        c => c.fatal === true && appliesToSubject(c, subject)
      );
      results.push(
        syntheticResult(
          suite,
          checkId,
          buildCheckErrorOutcome(checkId, applies.error),
          { fatal },
          timing,
          timeService
        )
      );
      if (fatal) {
        haltedBy = checkId;
      }
      continue;
    }

    if (!applies.threw && !applies.value) {
      if (options.explicitSuiteIds?.has(suite.id)) {
        results.push(
          syntheticResult(
            suite,
            `${suite.id}.applies`,
            { status: 'skipped', reason: 'suite predicate returned false' },
            {},
            timing,
            timeService
          )
        );
      }
      continue;
    }

    for (const check of suite.checks) {
      if (check.appliesTo && !appliesToSubject(check, subject)) {
        continue;
      }

      if (haltedBy !== undefined) {
        results.push(
          syntheticResult(
            suite,
            check.id,
            {
              status: 'skipped',
              code: RUN_SUITES_SKIP_CODES.notRunAfterFatal,
              haltedBy,
              reason: `Not run: ${haltedBy} failed`
            },
            check,
            timing,
            timeService
          )
        );
        continue;
      }

      const taskTiming = timing ? startTaskTiming(timeService) : undefined;
      let outcome: CheckOutcome;
      try {
        outcome = await check.execute(subject, context);
      } catch (error) {
        outcome = buildCheckErrorOutcome(check.id, error);
      }
      const finishedTiming = taskTiming
        ? finishTaskTiming(taskTiming, timeService)
        : undefined;

      const result = buildResult(suite, check.id, outcome, check);
      if (finishedTiming !== undefined) {
        result.timing = finishedTiming;
      }
      results.push(result);

      if (haltsOnFailure(check) && outcome.status === 'failure') {
        haltedBy = check.id;
      }
    }
  }

  return results;
}

/** Whether a failure of `check` halts the subject: fatal, and not opted out. */
function haltsOnFailure(check: VerificationCheck): boolean {
  return check.fatal === true && check.halts !== false;
}

/**
 * Internal: evaluate a suite's `applies` predicate without letting a
 * throw escape. A suite with no predicate applies.
 */
function evaluateApplies(
  suite: VerificationSuite,
  subject: VerificationSubject,
  context: VerificationContext
): { threw: false; value: boolean } | { threw: true; error: unknown } {
  if (!suite.applies) {
    return { threw: false, value: true };
  }
  try {
    return { threw: false, value: suite.applies(subject, context) };
  } catch (error) {
    return { threw: true, error };
  }
}

/**
 * Internal: turn a throw from `check.execute` (or `suite.applies`) into
 * a `failure` outcome carrying {@link ProblemTypes.CHECK_ERROR}. The
 * stack is not kept, only the message.
 */
function buildCheckErrorOutcome(id: string, error: unknown): CheckOutcome {
  const message = errorMessage(error, 'non-Error value thrown');
  return {
    status: 'failure',
    problems: [
      {
        type: ProblemTypes.CHECK_ERROR,
        title: 'Check Error',
        detail: `Check "${id}" threw: ${message}`
      }
    ]
  };
}

/**
 * Internal: assemble a `CheckResult` row for `checkId` within `suite`.
 * `fatal` and `halts` are copied from `flags` and omitted from the row
 * when undefined, so rows of checks that leave them unset keep their
 * shape.
 */
function buildResult(
  suite: VerificationSuite,
  checkId: string,
  outcome: CheckOutcome,
  flags: Pick<VerificationCheck, 'fatal' | 'halts'>
): CheckResult {
  const { fatal, halts } = flags;
  return {
    id: computeId(suite.phase, suite.id, checkId),
    suite: suite.id,
    outcome,
    ...(fatal !== undefined ? { fatal } : {}),
    ...(halts !== undefined ? { halts } : {})
  };
}

/**
 * Internal: build a row the orchestrator emits itself rather than from
 * `check.execute`: the `<suite-id>.applies` skip or error, and the
 * "not run after fatal" skip. Such a row records an instantaneous
 * decision, so when `timing` is on its window collapses to a single
 * sample of each clock. `endedAt` and `durationMs` then reflect the
 * cost of recording the decision, not of any predicate, and suite
 * rollups keep summing cleanly over synthetic rows.
 */
function syntheticResult(
  suite: VerificationSuite,
  checkId: string,
  outcome: CheckOutcome,
  flags: Pick<VerificationCheck, 'fatal' | 'halts'>,
  timing: boolean,
  timeService: TimeService | undefined
): CheckResult {
  const result = buildResult(suite, checkId, outcome, flags);
  if (timing) {
    const started = startTaskTiming(timeService);
    result.timing = finishTaskTiming(started, timeService);
  }
  return result;
}

interface InProgressTiming {
  startedAt: string;
  startedMonoMs: number;
}

/**
 * Sample wall-clock + monotonic clock at task start. Both
 * samples flow through the injected {@link TimeService} so
 * tests can pin them via `FakeTimeService`. Falls back to
 * `Date` / `performance` only as a defensive guard for code
 * paths that built a {@link VerificationContext} directly
 * without setting `timeService`; production callers set it
 * via `createVerifier(...)`.
 */
function startTaskTiming(
  timeService: TimeService | undefined
): InProgressTiming {
  const dateNowMs = timeService ? timeService.dateNowMs() : Date.now();
  const startedMonoMs = timeService
    ? timeService.performanceNowMs()
    : performance.now();
  return {
    startedAt: new Date(dateNowMs).toISOString(),
    startedMonoMs
  };
}

/**
 * Close out an {@link InProgressTiming} by sampling both
 * clocks again. `durationMs` comes from the monotonic clock
 * (immune to wall-clock jumps); `startedAt` / `endedAt` come
 * from the wall-clock for log correlation.
 */
function finishTaskTiming(
  started: InProgressTiming,
  timeService: TimeService | undefined
): TaskTiming {
  const endDateMs = timeService ? timeService.dateNowMs() : Date.now();
  const endMonoMs = timeService
    ? timeService.performanceNowMs()
    : performance.now();
  return {
    startedAt: started.startedAt,
    endedAt: new Date(endDateMs).toISOString(),
    durationMs: endMonoMs - started.startedMonoMs
  };
}
