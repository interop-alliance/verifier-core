import { VerificationCheck, CheckOutcome } from '../../types/check.js';
import { VerificationSubject } from '../../types/subject.js';
import { VerificationContext } from '../../types/context.js';
import { isPlainObject, isUrl } from '../../util/json-shape.js';
import {
  includesVcContext,
  VC_CONTEXT_V1,
  VC_CONTEXT_V2
} from '../../util/vc-contexts.js';
import {
  asEntries,
  checkFirstContextEntry,
  checkTypedEntry,
  checkTypeIncludes,
  checkUrlOrIdObject,
  displayPath,
  missingSubjectFailure,
  runStructureRules
} from './structure-helpers.js';

const TITLE = 'Invalid Presentation Structure';

/**
 * Check that the presentation meets the structural requirements of
 * the VC Data Model: a VC `@context` as its first entry, a `type`
 * including `VerifiablePresentation`, URL `id` and `holder` when
 * present, typed `proof` entries, and object `verifiableCredential`
 * entries.
 *
 * `proof` is not required, because unsigned presentations are
 * supported. A `@context` with no VC context at all is reported once,
 * at `/@context`; one with a VC context that is not first is reported
 * at `/@context/0` (or `/@context` for a single value). The contents
 * of embedded credentials are not checked here: each one gets its own
 * `verifyCredential` run. Every violation is reported, each as its own
 * `MALFORMED_VALUE_ERROR` problem with a JSON Pointer `instance`.
 *
 * This is a fatal check. A structurally invalid presentation cannot
 * be verified meaningfully.
 */
export const vpStructureCheck: VerificationCheck = {
  id: 'core.vp-structure',
  name: 'VP Structure',
  description:
    'Verifies the presentation meets the structural requirements of the VC Data Model.',
  fatal: true,
  appliesTo: ['verifiablePresentation'],
  execute: async (
    subject: VerificationSubject,
    _context: VerificationContext
  ): Promise<CheckOutcome> => {
    const presentation = subject.verifiablePresentation;
    if (!isPlainObject(presentation)) {
      return missingSubjectFailure(
        TITLE,
        'No verifiable presentation found in subject.'
      );
    }
    return runStructureRules(
      TITLE,
      'Presentation structure conforms to the VC Data Model.',
      report => {
        if (!includesVcContext(presentation['@context'])) {
          report(
            ['@context'],
            `"@context" must include "${VC_CONTEXT_V1}" or "${VC_CONTEXT_V2}".`
          );
        }
        checkFirstContextEntry(presentation['@context'], report);
        checkTypeIncludes(presentation.type, 'VerifiablePresentation', report);

        if (presentation.id !== undefined && !isUrl(presentation.id)) {
          report(['id'], '"id" must be a URL.');
        }
        if (presentation.holder !== undefined) {
          checkUrlOrIdObject(presentation.holder, ['holder'], report);
        }
        if (presentation.proof !== undefined) {
          for (const [entry, pointer] of asEntries(presentation.proof, [
            'proof'
          ])) {
            checkTypedEntry(entry, pointer, report);
          }
        }
        if (presentation.verifiableCredential !== undefined) {
          for (const [entry, pointer] of asEntries(
            presentation.verifiableCredential,
            ['verifiableCredential']
          )) {
            if (!isPlainObject(entry)) {
              report(pointer, `"${displayPath(pointer)}" must be an object.`);
            }
          }
        }
      }
    );
  }
};
