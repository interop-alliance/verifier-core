/**
 * Status list helpers shared by the status suite's checks: the one rule
 * that sorts `credentialStatus` entries into what `status.bitstring` does
 * with them, and the status lists its `verifyStatusListCredential` hook
 * verified during the current run.
 */

import type { VerificationContext } from '../../types/context.js';
import { isPlainObject, stringValues } from '../../util/json-shape.js';
import { asEntries, type PointerSegments } from '../core/structure-helpers.js';

export const BITSTRING_ENTRY_TYPE = 'BitstringStatusListEntry';

/** The purposes whose set bit means the credential is not currently valid. */
export const CHECKED_STATUS_PURPOSES: string[] = ['revocation', 'suspension'];

/**
 * The `credentialStatus` entries as `[entry, pointer]` pairs, the pointer
 * being `['credentialStatus']` for a single entry or
 * `['credentialStatus', index]` for an array element. Non-object entries
 * are kept so callers can report them. Empty when there is no entry.
 */
export function credentialStatusEntries(
  credential: Record<string, unknown>
): Array<[unknown, PointerSegments]> {
  const { credentialStatus } = credential;
  if (!credentialStatus) {
    return [];
  }
  return asEntries(credentialStatus, ['credentialStatus']);
}

/**
 * What `status.bitstring` does with one `credentialStatus` entry.
 *
 * - `checked`: a `BitstringStatusListEntry` for revocation or suspension,
 *   the kind `checkStatus` reads.
 * - `other-type`: an entry of another type (legacy or unknown); ignored.
 * - `other-purpose`: a Bitstring entry for a purpose the check does not
 *   read (for example `refresh` or `message`); ignored.
 * - `malformed`: an entry the check fails on. `field` names the offending
 *   property, or is undefined when the entry is not an object.
 */
export type StatusEntryClass =
  | { kind: 'checked'; entry: Record<string, unknown> }
  | { kind: 'other-type'; type: string }
  | { kind: 'other-purpose'; purpose: string }
  | { kind: 'malformed'; field?: string; detail: string };

/**
 * Sort one entry by the rule `@interop/vc-bitstring-status-list` applies:
 * an entry is a Bitstring entry when its `type` is the string
 * `BitstringStatusListEntry` or an array that includes it.
 */
export function classifyStatusEntry(entry: unknown): StatusEntryClass {
  if (!isPlainObject(entry)) {
    return {
      kind: 'malformed',
      detail: 'A credentialStatus entry must be an object.'
    };
  }
  const types = stringValues(entry.type);
  const [type] = types;
  if (type === undefined) {
    return {
      kind: 'malformed',
      field: 'type',
      detail: 'A credentialStatus entry must have a string type.'
    };
  }
  if (!types.includes(BITSTRING_ENTRY_TYPE)) {
    return { kind: 'other-type', type };
  }
  if (typeof entry.statusPurpose !== 'string') {
    return {
      kind: 'malformed',
      field: 'statusPurpose',
      detail: `A ${BITSTRING_ENTRY_TYPE} must have a string statusPurpose.`
    };
  }
  if (!CHECKED_STATUS_PURPOSES.includes(entry.statusPurpose)) {
    return { kind: 'other-purpose', purpose: entry.statusPurpose };
  }
  return { kind: 'checked', entry };
}

/**
 * Distinct `statusListCredential` URLs of the entries `status.bitstring`
 * checks, in first-seen order. Entries without a string URL are left for
 * `checkStatus` to reject.
 */
export function checkedStatusListUrls(
  credential: Record<string, unknown>
): string[] {
  const urls = new Set<string>();
  for (const [entry] of credentialStatusEntries(credential)) {
    const sorted = classifyStatusEntry(entry);
    if (sorted.kind !== 'checked') {
      continue;
    }
    const url = sorted.entry.statusListCredential;
    if (typeof url === 'string' && url.length > 0) {
      urls.add(url);
    }
  }
  return [...urls];
}

/** Status list credentials by URL. */
type ListsByUrl = Map<string, Record<string, unknown>>;

/**
 * Status lists whose proof verified during the current `status.bitstring`
 * run, by URL, keyed by the context the run received. The check starts
 * its run with {@link beginStatusListRun}, which drops whatever an earlier
 * run on the same context left; its `verifyStatusListCredential` hook
 * records each list it verifies; `status.list-issuer` takes the lists
 * back with {@link takeVerifiedStatusLists}, so a list is fetched once per
 * run and the store never outlives one run on a context.
 */
const verifiedLists = new WeakMap<VerificationContext, ListsByUrl>();

/**
 * Start a fresh record of verified lists for this context. Called right
 * before the lists are fetched, so a run that never reaches that point
 * allocates nothing.
 */
export function beginStatusListRun(context: VerificationContext): void {
  verifiedLists.set(context, new Map());
}

/**
 * Record a status list whose proof verified in the current run. A record
 * outside a run begun with {@link beginStatusListRun} is dropped.
 */
export function recordVerifiedStatusList(
  context: VerificationContext,
  url: string,
  list: Record<string, unknown>
): void {
  verifiedLists.get(context)?.set(url, list);
}

/**
 * The lists the current run verified, by URL, removed from the store so
 * a later run on the same context cannot read them. Empty when no run
 * recorded any.
 */
export function takeVerifiedStatusLists(
  context: VerificationContext
): ListsByUrl {
  const byUrl = verifiedLists.get(context) ?? new Map();
  verifiedLists.delete(context);
  return byUrl;
}
