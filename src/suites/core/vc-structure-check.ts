import { VerificationCheck, CheckOutcome } from '../../types/check.js';
import { VerificationSubject } from '../../types/subject.js';
import { VerificationContext } from '../../types/context.js';
import { isPlainObject, isUrl } from '../../util/json-shape.js';
import {
  firstContextEntry,
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
  isDateTime,
  missingSubjectFailure,
  runStructureRules,
  type PointerSegments,
  type Report
} from './structure-helpers.js';

const TITLE = 'Invalid Credential Structure';

/** Whether a typed entry's `id` must be a URL when present, or always. */
type IdRule = 'optional' | 'required';

/**
 * Properties whose every entry must be an object with a `type`, and
 * the rule for the entry's `id` (unset: not checked).
 */
const TYPED_PROPERTIES: ReadonlyArray<{ prop: string; id?: IdRule }> = [
  { prop: 'credentialStatus', id: 'optional' },
  { prop: 'proof' },
  { prop: 'termsOfUse' },
  { prop: 'evidence', id: 'optional' },
  { prop: 'credentialSchema', id: 'required' }
];

/**
 * Check that the credential meets the structural requirements of the
 * VC Data Model: a VC context as the first `@context` entry, `type`,
 * `credentialSubject`, `issuer`, the date properties for its version
 * (format only, not the clock), and the shape of `credentialStatus`,
 * `proof`, `termsOfUse`, `evidence` and `credentialSchema`.
 *
 * The first-entry rule reports only a VC context that is present but
 * not first; a missing one is `core.vc-context`'s failure, and that
 * check runs (and halts the suite) first. The version comes from the
 * first `@context` entry, as in `@interop/vc`; when it is neither VC
 * context, only the version-independent rules apply. Every violation
 * is reported, each as its own `MALFORMED_VALUE_ERROR` problem with a
 * JSON Pointer `instance`.
 *
 * This is a fatal check. A structurally invalid credential cannot be
 * verified meaningfully, and reporting it here keeps it from surfacing
 * later as a signature failure.
 */
export const vcStructureCheck: VerificationCheck = {
  id: 'core.vc-structure',
  name: 'VC Structure',
  description:
    'Verifies the credential meets the structural requirements of the VC Data Model.',
  fatal: true,
  appliesTo: ['verifiableCredential'],
  execute: async (
    subject: VerificationSubject,
    _context: VerificationContext
  ): Promise<CheckOutcome> => {
    const credential = subject.verifiableCredential;
    if (!isPlainObject(credential)) {
      return missingSubjectFailure(
        TITLE,
        'No verifiable credential found in subject.'
      );
    }
    return runStructureRules(
      TITLE,
      'Credential structure conforms to the VC Data Model.',
      report => {
        checkFirstContextEntry(credential['@context'], report);
        checkTypeIncludes(credential.type, 'VerifiableCredential', report);
        checkCredentialSubject(credential, report);
        if (credential.issuer === undefined) {
          report(['issuer'], '"issuer" is required.');
        } else {
          checkUrlOrIdObject(credential.issuer, ['issuer'], report);
        }
        checkDates(credential, report);
        checkTypedProperties(credential, report);
      }
    );
  }
};

function checkCredentialSubject(
  credential: Record<string, unknown>,
  report: Report
): void {
  const value = credential.credentialSubject;
  if (value === undefined || value === null) {
    report(['credentialSubject'], '"credentialSubject" is required.');
    return;
  }
  if (Array.isArray(value) && value.length === 0) {
    report(
      ['credentialSubject'],
      '"credentialSubject" must have at least one entry.'
    );
    return;
  }
  for (const [entry, pointer] of asEntries(value, ['credentialSubject'])) {
    const name = displayPath(pointer);
    if (!isPlainObject(entry) || Object.keys(entry).length === 0) {
      report(pointer, `"${name}" must be a non-empty object.`);
      continue;
    }
    if (entry.id !== undefined && !isUrl(entry.id)) {
      report([...pointer, 'id'], `"${name}.id" must be a URL.`);
    }
  }
}

function checkDates(credential: Record<string, unknown>, report: Report): void {
  const firstContext = firstContextEntry(credential['@context']);

  if (firstContext === VC_CONTEXT_V1) {
    if (credential.issuanceDate === undefined) {
      report(['issuanceDate'], '"issuanceDate" is required.');
    }
    checkDateTime(credential, 'issuanceDate', report);
    checkDateTime(credential, 'expirationDate', report);
  } else if (firstContext === VC_CONTEXT_V2) {
    checkDateTime(credential, 'validFrom', report);
    checkDateTime(credential, 'validUntil', report);
  }
}

/** Report `prop` when it is present and not a dateTime. */
function checkDateTime(
  credential: Record<string, unknown>,
  prop: string,
  report: Report
): void {
  const value = credential[prop];
  if (value !== undefined && !isDateTime(value)) {
    report([prop], `"${prop}" must be a valid dateTime.`);
  }
}

/** Apply `TYPED_PROPERTIES`: every entry is a typed object, with its `id` rule. */
function checkTypedProperties(
  credential: Record<string, unknown>,
  report: Report
): void {
  for (const { prop, id } of TYPED_PROPERTIES) {
    if (credential[prop] === undefined) {
      continue;
    }
    for (const [entry, pointer] of asEntries(credential[prop], [prop])) {
      const typed = checkTypedEntry(entry, pointer, report);
      if (typed !== undefined && id !== undefined) {
        checkEntryId(typed, pointer, id, report);
      }
    }
  }
}

function checkEntryId(
  entry: Record<string, unknown>,
  pointer: PointerSegments,
  rule: IdRule,
  report: Report
): void {
  if (entry.id === undefined) {
    if (rule === 'required') {
      report(
        [...pointer, 'id'],
        `"${displayPath(pointer)}" must have a URL "id".`
      );
    }
  } else if (!isUrl(entry.id)) {
    report([...pointer, 'id'], `"${displayPath(pointer)}.id" must be a URL.`);
  }
}
