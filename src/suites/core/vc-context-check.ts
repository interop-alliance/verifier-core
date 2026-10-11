import { VerificationCheck, CheckOutcome } from '../../types/check.js';
import { VerificationSubject } from '../../types/subject.js';
import { VerificationContext } from '../../types/context.js';
import { ProblemTypes } from '../../problem-types.js';
import {
  includesVcContext,
  VC_CONTEXT_V1,
  VC_CONTEXT_V2
} from '../../util/vc-contexts.js';

/**
 * Check that @context includes a valid VC context URI.
 * This is a fatal check - we need to know which VC version we're dealing with.
 */
export const vcContextCheck: VerificationCheck = {
  id: 'core.vc-context',
  name: 'VC Context Present',
  description:
    'Verifies that the credential @context includes a valid Verifiable Credentials context URI.',
  fatal: true,
  appliesTo: ['verifiableCredential'],
  execute: async (
    subject: VerificationSubject,
    _context: VerificationContext
  ): Promise<CheckOutcome> => {
    const credential = subject.verifiableCredential as
      Record<string, unknown> | undefined;

    if (!credential) {
      return {
        status: 'failure',
        problems: [
          {
            type: ProblemTypes.PARSING_ERROR,
            title: 'No VC Context',
            detail: 'No verifiable credential found in subject.'
          }
        ]
      };
    }

    const context = credential['@context'];

    if (!includesVcContext(context)) {
      return {
        status: 'failure',
        problems: [
          {
            type: ProblemTypes.PARSING_ERROR,
            title: 'No VC Context',
            detail: `Credential @context does not include required VC context URI (${VC_CONTEXT_V1} or ${VC_CONTEXT_V2}).`
          }
        ]
      };
    }

    return {
      status: 'success',
      message: 'Credential @context includes a valid VC context URI.'
    };
  }
};
