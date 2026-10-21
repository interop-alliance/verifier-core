import {
  checkStatus,
  type VerifyStatusListCredential
} from '@interop/vc-bitstring-status-list';
import {
  dispatchProofSetVerification,
  type CryptoDispatchResult
} from '../../crypto-dispatch.js';
import { VerificationCheck, CheckOutcome } from '../../types/check.js';
import { ProblemDetail } from '../../types/problem-detail.js';
import { VerificationSubject } from '../../types/subject.js';
import { VerificationContext } from '../../types/context.js';
import { ProblemTypes } from '../../problem-types.js';
import { formatJsonPointer } from '../../util/json-pointer.js';
import { errorMessage } from '../../util/error-message.js';
import {
  BITSTRING_ENTRY_TYPE,
  CHECKED_STATUS_PURPOSES,
  beginStatusListRun,
  classifyStatusEntry,
  credentialStatusEntries,
  recordVerifiedStatusList
} from './status-lists.js';

// Legacy status types that are skipped
const LEGACY_STATUS_TYPES: string[] = [
  'StatusList2021Entry',
  '1EdTechRevocationList'
];

// Error pattern from the document loader.
const NOT_FOUND_ERROR = 'NotFoundError';
// Error pattern from `checkStatus`.
const STATUS_TYPE_ERROR =
  'Status list credential type must include "BitstringStatusListCredential".';

/**
 * How a validity-period rejection of a status list is reported, keyed by
 * the problem `type` the crypto service gives the list credential.
 */
const DATE_REJECTION_PROBLEMS: Record<
  string,
  { type: string; title: string; phrase: string }
> = {
  [ProblemTypes.CREDENTIAL_EXPIRED]: {
    type: ProblemTypes.STATUS_LIST_EXPIRED,
    title: 'Status List Expired',
    phrase: 'has expired'
  },
  [ProblemTypes.CREDENTIAL_NOT_YET_VALID]: {
    type: ProblemTypes.STATUS_LIST_NOT_YET_VALID,
    title: 'Status List Not Yet Valid',
    phrase: 'is not yet valid'
  }
};

function statusListSignatureProblem(detail: string): ProblemDetail {
  return {
    type: ProblemTypes.STATUS_LIST_SIGNATURE_ERROR,
    title: 'Status List Signature Error',
    detail
  };
}

/**
 * Carries the already-classified problems of a failed status list proof
 * out of the `verifyStatusListCredential` hook. `checkStatus` wraps the
 * hook's error as `cause`, and {@link classifyStatusError} unwraps it.
 */
class StatusListProofError extends Error {
  constructor(readonly problems: ProblemDetail[]) {
    super(problems[0].detail);
  }
}

/** Distinct values, quoted and comma-joined for a skip or success message. */
function quoted(values: string[]): string {
  return [...new Set(values)].map(v => `"${v}"`).join(', ');
}

/** A `MALFORMED_VALUE_ERROR` whose `instance` is the pointer to `path`. */
function malformedEntryProblem(
  path: Array<string | number>,
  detail: string
): ProblemDetail {
  return {
    type: ProblemTypes.MALFORMED_VALUE_ERROR,
    title: 'Malformed Status Entry',
    detail,
    instance: formatJsonPointer(path)
  };
}

/**
 * The `credentialStatus` entries sorted by what `status.bitstring` does
 * with them, one {@link classifyStatusEntry} verdict per entry. `checked`
 * counts the entries `checkStatus` reads. Every other entry is ignored
 * and its list is not fetched: `otherTypes` names the types of
 * non-Bitstring entries (legacy or unknown), `otherPurposes` the purposes
 * of Bitstring entries the check does not read. `malformed` collects a
 * problem for each entry the check fails on. `empty` is true when there
 * is no entry at all.
 */
function sortStatusEntries(credential: Record<string, unknown>): {
  empty: boolean;
  checked: number;
  otherTypes: string[];
  otherPurposes: string[];
  malformed: ProblemDetail[];
} {
  const entries = credentialStatusEntries(credential);
  let checked = 0;
  const otherTypes: string[] = [];
  const otherPurposes: string[] = [];
  const malformed: ProblemDetail[] = [];
  for (const [entry, pointer] of entries) {
    const sorted = classifyStatusEntry(entry);
    switch (sorted.kind) {
      case 'checked':
        checked += 1;
        break;
      case 'other-type':
        otherTypes.push(sorted.type);
        break;
      case 'other-purpose':
        otherPurposes.push(sorted.purpose);
        break;
      case 'malformed': {
        const path =
          sorted.field === undefined ? pointer : [...pointer, sorted.field];
        malformed.push(malformedEntryProblem(path, sorted.detail));
        break;
      }
    }
  }
  return {
    empty: entries.length === 0,
    checked,
    otherTypes,
    otherPurposes,
    malformed
  };
}

/** The sentences naming ignored entries, appended to a message. */
function uncheckedSuffix(
  otherTypes: string[],
  otherPurposes: string[]
): string {
  const parts: string[] = [];
  if (otherTypes.length > 0) {
    parts.push(`Unchecked status types: ${quoted(otherTypes)}.`);
  }
  if (otherPurposes.length > 0) {
    parts.push(`Unchecked status purposes: ${quoted(otherPurposes)}.`);
  }
  return parts.join(' ');
}

/** The skip reason when a credential has status entries but none is checked. */
function noCheckedEntryReason(
  otherTypes: string[],
  otherPurposes: string[]
): string {
  if (otherPurposes.length === 0) {
    const allLegacy = otherTypes.every(t => LEGACY_STATUS_TYPES.includes(t));
    return allLegacy
      ? `Legacy status type ${quoted(otherTypes)} is not checked.`
      : `Status type ${quoted(otherTypes)} is not ${BITSTRING_ENTRY_TYPE}.`;
  }
  if (otherTypes.length === 0) {
    return `${BITSTRING_ENTRY_TYPE} with statusPurpose ${quoted(otherPurposes)} is not checked.`;
  }
  return `No revocation or suspension ${BITSTRING_ENTRY_TYPE} to check. ${uncheckedSuffix(otherTypes, otherPurposes)}`;
}

/**
 * Map a non-verified dispatch onto a status list problem.
 *
 * `no-service` is a failure, not a skip: `DataIntegrityCryptoService.canVerify`
 * returns false for a document with no proof, so an unsigned status list
 * lands here. Passing that through as success would silently accept lists
 * the previous `vcVerifyCredential` path rejected.
 *
 * The crypto service also judges the list credential's validity period and
 * reports an authentic but out-of-date list as `CREDENTIAL_EXPIRED` /
 * `CREDENTIAL_NOT_YET_VALID`. That is surfaced as `STATUS_LIST_EXPIRED` /
 * `STATUS_LIST_NOT_YET_VALID`, naming the list, rather than as a signature
 * error.
 */
function statusListProofProblems(
  dispatched: Exclude<CryptoDispatchResult, { kind: 'verified' }>,
  listName: string
): ProblemDetail[] {
  switch (dispatched.kind) {
    case 'no-service':
      return [
        statusListSignatureProblem(
          "No registered crypto service can verify the status list credential's proof (unsigned list, or suite missing from cryptoServices)."
        )
      ];
    case 'threw':
      return [statusListSignatureProblem(dispatched.message)];
    case 'rejected': {
      const dated = dispatched.problems.find(
        problem => problem.type in DATE_REJECTION_PROBLEMS
      );
      if (dated !== undefined) {
        const { type, title, phrase } = DATE_REJECTION_PROBLEMS[dated.type];
        return [
          {
            type,
            title,
            detail: `The status list credential ${listName} ${phrase}. ${dated.detail}`
          }
        ];
      }
      return [
        statusListSignatureProblem(
          'The status list credential signature could not be verified.'
        )
      ];
    }
  }
}

/**
 * The `verifyStatusListCredential` hook handed to `checkStatus`: routes
 * each fetched BitstringStatusListCredential through
 * {@link dispatchProofSetVerification} against `context.cryptoServices`.
 * A list's proof set is verified proof by proof, like a credential's, so
 * one bad proof makes a bad list. `checkStatus` itself loads and verifies
 * each distinct list URL once and tells the hook which `url` it loaded.
 * The list's validity dates are judged at the verifier's clock, the same
 * instant `proof.signature` uses for the credential.
 *
 * A list whose proof verified is recorded for `status.list-issuer`, so
 * that check needs no second fetch. So is a list the service rejected
 * with `proofVerified` set, such as one that is only out of date: who
 * signed it is still known.
 */
function verifyStatusListVia(
  context: VerificationContext
): VerifyStatusListCredential {
  return async ({ credential, documentLoader, url }) => {
    const { combined: dispatched } = await dispatchProofSetVerification({
      services: context.cryptoServices,
      subject: { verifiableCredential: credential },
      options: { documentLoader, now: context.now }
    });
    if (dispatched.kind === 'verified') {
      recordVerifiedStatusList(context, url, credential);
      return { verified: true };
    }
    if (dispatched.kind === 'rejected' && dispatched.proofVerified) {
      recordVerifiedStatusList(context, url, credential);
    }
    return {
      verified: false,
      error: new StatusListProofError(statusListProofProblems(dispatched, url))
    };
  };
}

/**
 * Classify an error raised by `checkStatus` into a ProblemDetail.
 *
 * A failed proof surfaces as a wrapped {@link StatusListProofError}. An
 * unreachable list surfaces with the loader's `NotFoundError` as `cause`.
 * A wrong-typed list is thrown by `checkStatus` itself, without a cause.
 */
function classifyStatusError(error: unknown): ProblemDetail[] {
  const message = errorMessage(
    error,
    'An error occurred while checking credential status.'
  );
  const cause = (error as { cause?: { message?: string; name?: string } })
    ?.cause;
  const causeMessage = cause?.message || '';

  if (cause instanceof StatusListProofError) {
    return cause.problems;
  }

  if (
    cause?.name === NOT_FOUND_ERROR ||
    causeMessage.startsWith(NOT_FOUND_ERROR)
  ) {
    return [
      {
        type: ProblemTypes.STATUS_LIST_NOT_FOUND,
        title: 'Status List Not Found',
        detail: message
      }
    ];
  }

  if (
    message.startsWith(STATUS_TYPE_ERROR) ||
    causeMessage.startsWith(STATUS_TYPE_ERROR)
  ) {
    return [
      {
        type: ProblemTypes.STATUS_LIST_TYPE_ERROR,
        title: 'Status List Type Error',
        detail: STATUS_TYPE_ERROR
      }
    ];
  }

  return [
    {
      type: ProblemTypes.STATUS_LIST_ERROR,
      title: 'Status List Error',
      detail: message
    }
  ];
}

/** One problem for an entry whose bit is set, typed by its purpose. */
function setBitProblem(entry: Record<string, unknown>): ProblemDetail {
  const suspended = entry.statusPurpose === 'suspension';
  return {
    type: suspended
      ? ProblemTypes.CREDENTIAL_SUSPENDED
      : ProblemTypes.CREDENTIAL_REVOKED,
    title: suspended ? 'Credential Suspended' : 'Credential Revoked',
    detail: `The status list ${String(entry.statusListCredential)} marks the credential ${
      suspended ? 'suspended' : 'revoked'
    } (index ${String(entry.statusListIndex)}).`
  };
}

/**
 * Bitstring status list check for revocation/suspension status.
 *
 * This is a **fatal** check: if the verifier cannot conclude that the
 * credential is currently un-revoked and un-suspended (because a status
 * list is missing, has an invalid signature, is expired or not yet valid,
 * has a wrong type, or actually marks the credential as revoked or
 * suspended), the overall verification result is `verified: false`.
 * It does not halt (`halts: false`): the credential is authentic by now,
 * since `proof.signature` passed, so whether its issuer is registered and
 * who signed its status list still matter to a verifier.
 *
 * Every `BitstringStatusListEntry` with `statusPurpose` `revocation` or
 * `suspension` is checked, wherever it sits in `credentialStatus`. Each
 * set bit is its own problem, `CREDENTIAL_REVOKED` or
 * `CREDENTIAL_SUSPENDED`, naming the list and index. Other entries
 * (legacy `StatusList2021Entry` / `1EdTechRevocationList`, unknown types,
 * and Bitstring entries for other purposes such as `refresh`) are
 * ignored, their lists are not fetched, and the outcome names them. The
 * check is skipped when no entry is checked. A malformed entry (not an
 * object, no string `type`, or a Bitstring entry without a string
 * `statusPurpose`) fails the check with a `MALFORMED_VALUE_ERROR` whose
 * `instance` points at the entry.
 *
 * `@interop/vc-bitstring-status-list` owns entry selection (via its
 * `statusPurposes` option), list loading, purpose matching, bitstring
 * decoding, and index reading. Proof verification of
 * each fetched BitstringStatusListCredential is injected through its
 * `verifyStatusListCredential` hook and goes through
 * {@link dispatchProofSetVerification} against `context.cryptoServices`,
 * the same dispatch presentation and credential proofs use. Whether a list is
 * issued by the credential's issuer is reported separately, by the
 * non-fatal `status.list-issuer` check, which reads the lists this hook
 * verified.
 *
 * `statusSuite` is the sole owner of status verification; the proof
 * suite no longer performs an embedded status check (P-E, 2026-04-19).
 */
export const bitstringStatusCheck: VerificationCheck = {
  id: 'status.bitstring',
  name: 'Bitstring Status Check',
  description:
    'Checks revocation and suspension status via BitstringStatusList.',
  fatal: true,
  // The credential is authentic by now; who signed its list still matters.
  halts: false,
  appliesTo: ['verifiableCredential'],
  execute: async (
    subject: VerificationSubject,
    context: VerificationContext
  ): Promise<CheckOutcome> => {
    const credential = subject.verifiableCredential as
      Record<string, unknown> | undefined;

    if (!credential) {
      return {
        status: 'skipped',
        reason: 'No verifiable credential found in subject.'
      };
    }

    const { empty, checked, otherTypes, otherPurposes, malformed } =
      sortStatusEntries(credential);

    if (empty) {
      return {
        status: 'skipped',
        reason: 'Credential has no credentialStatus.'
      };
    }

    if (malformed.length > 0) {
      return { status: 'failure', problems: malformed };
    }

    if (checked === 0) {
      return {
        status: 'skipped',
        reason: noCheckedEntryReason(otherTypes, otherPurposes)
      };
    }

    // Whatever an earlier run on this context recorded is stale for the
    // `status.list-issuer` check that follows this run.
    beginStatusListRun(context);

    try {
      const statusResult = await checkStatus({
        credential,
        documentLoader: context.documentLoader,
        statusPurposes: CHECKED_STATUS_PURPOSES,
        verifyStatusListCredential: verifyStatusListVia(context),
        // Issuer binding is reported by the non-fatal `status.list-issuer`
        // check. The library's own comparison throws, which would make a
        // list signed by a separate status-service DID fatal, and real
        // deployments sign lists that way.
        verifyMatchingIssuers: false
      });

      if (statusResult.error !== undefined) {
        return {
          status: 'failure',
          problems: classifyStatusError(statusResult.error)
        };
      }

      // `@interop/vc-bitstring-status-list` reports `verified: true` once the
      // status was *successfully checked*; the revoked/suspended bit itself
      // lives in each per-entry `results[].status`.
      const results = (statusResult.results ?? []) as Array<{
        status?: unknown;
        credentialStatus?: Record<string, unknown>;
      }>;
      const problems = results
        .filter(result => result.status === true)
        .map(result => setBitProblem(result.credentialStatus ?? {}));

      // `checkStatus` reports a problem through `error` (handled above);
      // a result without one has read every bit, so only set bits remain.
      if (problems.length > 0) {
        return { status: 'failure', problems };
      }

      const message = 'Credential status is valid (not revoked or suspended).';
      const unchecked = uncheckedSuffix(otherTypes, otherPurposes);
      return {
        status: 'success',
        message: unchecked ? `${message} ${unchecked}` : message
      };
    } catch (error) {
      return { status: 'failure', problems: classifyStatusError(error) };
    }
  }
};
