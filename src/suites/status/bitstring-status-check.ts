import {
  checkStatus,
  type VerifyStatusListCredential
} from '@interop/vc-bitstring-status-list';
import {
  dispatchProofVerification,
  type CryptoDispatchResult
} from '../../crypto-dispatch.js';
import { VerificationCheck, CheckOutcome } from '../../types/check.js';
import { ProblemDetail } from '../../types/problem-detail.js';
import { VerificationSubject } from '../../types/subject.js';
import { VerificationContext } from '../../types/context.js';
import { ProblemTypes } from '../../problem-types.js';
import { formatJsonPointer } from '../../util/json-pointer.js';
import { isPlainObject, stringValues } from '../../util/json-shape.js';
import { errorMessage } from '../../util/error-message.js';
import {
  classifyDateRejection,
  type DateRejection
} from '../../util/vc-date-messages.js';

// Legacy status types that are skipped
const LEGACY_STATUS_TYPES: string[] = [
  'StatusList2021Entry',
  '1EdTechRevocationList'
];

const BITSTRING_ENTRY_TYPE = 'BitstringStatusListEntry';

// The purposes whose set bit means the credential is not currently valid.
const CHECKED_STATUS_PURPOSES: string[] = ['revocation', 'suspension'];

// Error pattern from the document loader.
const NOT_FOUND_ERROR = 'NotFoundError';
// Error pattern from `checkStatus`.
const STATUS_TYPE_ERROR =
  'Status list credential type must include "BitstringStatusListCredential".';

/** How each validity-period rejection of a status list is reported. */
const DATE_REJECTION_PROBLEMS: Record<
  DateRejection,
  { type: string; title: string; phrase: string }
> = {
  expired: {
    type: ProblemTypes.STATUS_LIST_EXPIRED,
    title: 'Status List Expired',
    phrase: 'has expired'
  },
  'not-yet-valid': {
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
 * with them. `checked` entries are `BitstringStatusListEntry` for
 * revocation or suspension and go to `checkStatus`. An entry's `type`
 * may be a string or a one-element array; a checked entry is handed on
 * with the string form, which is what the status-list library compares.
 * Every other entry is ignored and its list is not fetched: `otherTypes`
 * names the types of non-Bitstring entries (legacy or unknown),
 * `otherPurposes` the purposes of Bitstring entries the check does not
 * read (for example `refresh` or `message`). `malformed` collects a
 * problem for each entry that is not an object, has no usable `type`,
 * or is a Bitstring entry without a string `statusPurpose`. `empty` is
 * true when there is no entry at all.
 */
function sortStatusEntries(credential: Record<string, unknown>): {
  empty: boolean;
  checked: Array<Record<string, unknown>>;
  otherTypes: string[];
  otherPurposes: string[];
  malformed: ProblemDetail[];
} {
  const { credentialStatus } = credential;
  const single = !Array.isArray(credentialStatus);
  const entries: unknown[] = single ? [credentialStatus] : credentialStatus;
  const checked: Array<Record<string, unknown>> = [];
  const otherTypes: string[] = [];
  const otherPurposes: string[] = [];
  const malformed: ProblemDetail[] = [];
  entries.forEach((entry, index) => {
    const path: Array<string | number> = single
      ? ['credentialStatus']
      : ['credentialStatus', index];
    if (!isPlainObject(entry)) {
      malformed.push(
        malformedEntryProblem(
          path,
          'A credentialStatus entry must be an object.'
        )
      );
      return;
    }
    const [type] = stringValues(entry.type);
    if (type === undefined) {
      malformed.push(
        malformedEntryProblem(
          [...path, 'type'],
          'A credentialStatus entry must have a string type.'
        )
      );
    } else if (type !== BITSTRING_ENTRY_TYPE) {
      otherTypes.push(type);
    } else if (typeof entry.statusPurpose !== 'string') {
      malformed.push(
        malformedEntryProblem(
          [...path, 'statusPurpose'],
          `A ${BITSTRING_ENTRY_TYPE} must have a string statusPurpose.`
        )
      );
    } else if (CHECKED_STATUS_PURPOSES.includes(entry.statusPurpose)) {
      checked.push({ ...entry, type: BITSTRING_ENTRY_TYPE });
    } else {
      otherPurposes.push(entry.statusPurpose);
    }
  });
  return {
    empty: !credentialStatus || entries.length === 0,
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
 * The crypto service also enforces the list credential's validity period,
 * and `@interop/vc` checks dates only after the signature has verified. A
 * date message in the rejection therefore proves the list is authentic and
 * merely out of date, and is surfaced as `STATUS_LIST_EXPIRED` /
 * `STATUS_LIST_NOT_YET_VALID` (naming the list and carrying the library's
 * message) rather than as a signature error.
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
      for (const { detail } of dispatched.problems) {
        const rejection = classifyDateRejection(detail);
        if (rejection !== undefined) {
          const { type, title, phrase } = DATE_REJECTION_PROBLEMS[rejection];
          return [
            {
              type,
              title,
              detail: `The status list credential ${listName} ${phrase}: ${detail}`
            }
          ];
        }
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
 * {@link dispatchProofVerification} against `context.cryptoServices`.
 * `checkStatus` itself loads and verifies each distinct list URL once.
 */
function verifyStatusListVia(
  context: VerificationContext
): VerifyStatusListCredential {
  return async ({ credential, documentLoader }) => {
    const dispatched = await dispatchProofVerification({
      services: context.cryptoServices,
      subject: { verifiableCredential: credential },
      options: { documentLoader }
    });
    if (dispatched.kind === 'verified') {
      return { verified: true };
    }
    // The hook is not told the URL; a status list credential's `id` is it.
    const listName =
      typeof credential?.id === 'string' ? credential.id : '(no id)';
    return {
      verified: false,
      error: new StatusListProofError(
        statusListProofProblems(dispatched, listName)
      )
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
 * `@interop/vc-bitstring-status-list` owns list loading, purpose
 * matching, bitstring decoding, and index reading. Proof verification of
 * each fetched BitstringStatusListCredential is injected through its
 * `verifyStatusListCredential` hook and goes through
 * {@link dispatchProofVerification} against `context.cryptoServices`, the
 * same dispatch presentation and credential proofs use.
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

    if (checked.length === 0) {
      return {
        status: 'skipped',
        reason: noCheckedEntryReason(otherTypes, otherPurposes)
      };
    }

    try {
      // Only the checked entries go to `checkStatus`; it reads the bit of
      // every Bitstring entry it is given, whatever the purpose.
      const statusResult = await checkStatus({
        credential: { ...credential, credentialStatus: checked },
        documentLoader: context.documentLoader,
        verifyStatusListCredential: verifyStatusListVia(context),
        // Hosted status lists may use a different issuer than the VC (see DataIntegrityCryptoService).
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
