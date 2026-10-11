/**
 * Pure helpers shared by `core.vc-structure` and `core.vp-structure`:
 * the problem/outcome scaffolding and the rules both checks apply.
 */

import { dateRegex } from '@interop/vc';
import type { CheckOutcome } from '../../types/check.js';
import type { ProblemDetail } from '../../types/problem-detail.js';
import { ProblemTypes } from '../../problem-types.js';
import { formatJsonPointer } from '../../util/json-pointer.js';
import { isPlainObject, isUrl, stringValues } from '../../util/json-shape.js';
import {
  firstContextEntry,
  includesVcContext,
  isVcContext,
  VC_CONTEXT_V1,
  VC_CONTEXT_V2
} from '../../util/vc-contexts.js';

/** JSON Pointer segments, as accepted by {@link formatJsonPointer}. */
export type PointerSegments = Array<string | number>;

/** Receives one structural violation: where it is, and what is wrong. */
export type Report = (pointer: PointerSegments, detail: string) => void;

/** The failure outcome when the subject carries no object to check. */
export function missingSubjectFailure(
  title: string,
  detail: string
): CheckOutcome {
  return {
    status: 'failure',
    problems: [{ type: ProblemTypes.MALFORMED_VALUE_ERROR, title, detail }]
  };
}

/**
 * Run `rules` with a {@link Report} that collects each violation as a
 * `MALFORMED_VALUE_ERROR` problem whose `instance` is the JSON Pointer
 * for the reported path. The outcome is a failure carrying every
 * problem, or a success with `successMessage` when nothing was
 * reported.
 */
export function runStructureRules(
  title: string,
  successMessage: string,
  rules: (report: Report) => void
): CheckOutcome {
  const problems: ProblemDetail[] = [];
  rules((pointer, detail) => {
    problems.push({
      type: ProblemTypes.MALFORMED_VALUE_ERROR,
      title,
      detail,
      instance: formatJsonPointer(pointer)
    });
  });
  if (problems.length > 0) {
    return { status: 'failure', problems };
  }
  return { status: 'success', message: successMessage };
}

/**
 * Report when `@context` includes a VC context but its first entry is
 * not one, as `@interop/vc` requires. The pointer is `/@context/0` for
 * an array and `/@context` for a single value. When no VC context is
 * present at all this reports nothing, so the caller (or
 * `core.vc-context`) reports that once, as a missing context.
 */
export function checkFirstContextEntry(context: unknown, report: Report): void {
  if (!includesVcContext(context) || isVcContext(firstContextEntry(context))) {
    return;
  }
  report(
    Array.isArray(context) ? ['@context', 0] : ['@context'],
    `The first "@context" entry must be "${VC_CONTEXT_V1}" or "${VC_CONTEXT_V2}".`
  );
}

/** Report when `type` is missing or does not include `required`. */
export function checkTypeIncludes(
  type: unknown,
  required: string,
  report: Report
): void {
  if (type === undefined) {
    report(['type'], '"type" is required.');
  } else if (!stringValues(type).includes(required)) {
    report(['type'], `"type" must include "${required}".`);
  }
}

/**
 * The rule shared by `issuer` and `holder`: a URL string, or an object
 * whose `id` is a URL. The caller decides whether the property may be
 * absent.
 */
export function checkUrlOrIdObject(
  value: unknown,
  pointer: PointerSegments,
  report: Report
): void {
  const name = displayPath(pointer);
  if (typeof value === 'string') {
    if (!isUrl(value)) {
      report(pointer, `"${name}" must be a URL.`);
    }
  } else if (isPlainObject(value)) {
    if (!isUrl(value.id)) {
      report([...pointer, 'id'], `"${name}.id" must be a URL.`);
    }
  } else {
    report(pointer, `"${name}" must be a URL or an object with a URL "id".`);
  }
}

/**
 * An XML Schema dateTime string, tested with the `dateRegex` that
 * `@interop/vc` exports, so this check and the library agree on what a
 * valid date is.
 */
export function isDateTime(value: unknown): boolean {
  return typeof value === 'string' && dateRegex.test(value);
}

/**
 * Normalise a single value or an array into `[entry, pointer]` pairs.
 * A single value keeps its pointer (`['credentialStatus']`); an array
 * entry gets its index appended (`['credentialStatus', 0]`).
 */
export function asEntries(
  value: unknown,
  pointer: PointerSegments
): Array<[unknown, PointerSegments]> {
  if (Array.isArray(value)) {
    return value.map((entry, i) => [entry, [...pointer, i]]);
  }
  return [[value, pointer]];
}

/**
 * A readable name for a pointer in `detail` text, e.g.
 * `['credentialStatus', 1, 'id']` becomes `credentialStatus[1].id`.
 */
export function displayPath(pointer: PointerSegments): string {
  return pointer
    .map((segment, i) => {
      if (typeof segment === 'number') {
        return `[${segment}]`;
      }
      return i === 0 ? segment : `.${segment}`;
    })
    .join('');
}

/**
 * The rule shared by every property whose entries must be objects
 * with a `type` (`proof`, `credentialStatus`, `termsOfUse`,
 * `evidence`, `credentialSchema`): report the entry itself when it is
 * not an object, or its `type` when only that is missing. Returns the
 * entry when it is an object, so callers can check further fields.
 */
export function checkTypedEntry(
  entry: unknown,
  pointer: PointerSegments,
  report: Report
): Record<string, unknown> | undefined {
  const name = displayPath(pointer);
  if (!isPlainObject(entry)) {
    report(pointer, `"${name}" must be an object with a "type".`);
    return undefined;
  }
  if (stringValues(entry.type).length === 0) {
    report([...pointer, 'type'], `"${name}" must have a "type".`);
  }
  return entry;
}
