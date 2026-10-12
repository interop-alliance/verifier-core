import { RUN_SUITES_SKIP_CODES } from '../../src/index.js';

/**
 * The `'skipped'` outcome `runSuites` emits for a check halted by an
 * earlier fatal failure of `haltedBy`.
 */
export function notRunOutcome(haltedBy: string) {
  return {
    status: 'skipped' as const,
    code: RUN_SUITES_SKIP_CODES.notRunAfterFatal,
    haltedBy,
    reason: `Not run: ${haltedBy} failed`
  };
}
