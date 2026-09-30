/**
 * `recognition.profile` — pluggable credential-recognition check.
 *
 * Iterates {@link VerificationContext.recognizers} in order and
 * selects the first whose `applies` predicate returns true. The
 * winner's `parse` step produces a {@link RecognitionResult}:
 *
 * - **`recognized`** → success outcome carrying the recognition
 *   result as `payload`. The verifier wrapper post-processes the
 *   payload and stashes the normalized form on
 *   {@link CredentialVerificationResult.normalizedVerifiableCredential}
 *   + `recognizedProfile`.
 * - **`malformed`** → failure outcome surfacing the recognizer's
 *   `ProblemDetail[]` directly. Non-fatal — recognition failure
 *   doesn't short-circuit the rest of the suite list.
 *
 * No applies-true recognizer → `'skipped'` with reason
 * `'no recognizer matched'`. No recognizers configured at all →
 * `'skipped'` with reason `'no recognizers configured'`, so a
 * consumer can tell "the question was never asked" from "asked, no
 * match".
 */

import type { VerificationCheck, CheckOutcome } from '../../types/check.js';

export const recognitionProfileCheck: VerificationCheck = {
  id: 'recognition.profile',
  name: 'Credential Recognition',
  description:
    'Selects the first matching recognizer and surfaces its normalized credential form.',
  appliesTo: ['verifiableCredential'],
  fatal: false,
  execute: async (subject, context): Promise<CheckOutcome> => {
    const recognizers = context.recognizers ?? [];
    if (recognizers.length === 0) {
      return { status: 'skipped', reason: 'no recognizers configured' };
    }
    const credential = subject.verifiableCredential;
    for (const recognizer of recognizers) {
      if (!recognizer.applies(credential, context)) {
        continue;
      }
      const result = recognizer.parse(credential);
      if (result.status === 'recognized') {
        return {
          status: 'success',
          message: `recognized as ${result.profile}`,
          payload: result
        };
      }
      return { status: 'failure', problems: result.problems };
    }
    return { status: 'skipped', reason: 'no recognizer matched' };
  }
};
