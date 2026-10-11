import type {
  VerificationCheck,
  VerificationSubjectType
} from '../types/check.js';

/**
 * Whether `check` applies to a subject of any of `subjectTypes`. A check
 * whose `appliesTo` is unset or empty applies to everything. This is the
 * one definition of `appliesTo`, shared by the orchestrator (which
 * decides whether to run the check) and result folding (which counts
 * the checks that could have run).
 */
export function checkAppliesTo(
  check: VerificationCheck,
  subjectTypes: readonly VerificationSubjectType[]
): boolean {
  if (check.appliesTo === undefined || check.appliesTo.length === 0) {
    return true;
  }
  return check.appliesTo.some(type => subjectTypes.includes(type));
}
