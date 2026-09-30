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

// Legacy status types that are skipped
const LEGACY_STATUS_TYPES: string[] = [
  'StatusList2021Entry',
  '1EdTechRevocationList'
];

const BITSTRING_ENTRY_TYPE = 'BitstringStatusListEntry';

// Error patterns from the document loader and the crypto service.
const NOT_FOUND_ERROR = 'NotFoundError';
const EXPIRED_ERROR = 'is after "validUntil"';
const NOT_YET_VALID_ERROR = 'is before "validFrom"';
// Error pattern from `checkStatus`.
const STATUS_TYPE_ERROR =
  'Status list credential type must include "BitstringStatusListCredential".';

const STATUS_LIST_EXPIRED_PROBLEM: ProblemDetail = {
  type: ProblemTypes.STATUS_LIST_EXPIRED,
  title: 'Status List Expired',
  detail: 'The status list credential has expired.'
};

const STATUS_LIST_NOT_YET_VALID_PROBLEM: ProblemDetail = {
  type: ProblemTypes.STATUS_LIST_NOT_YET_VALID,
  title: 'Status List Not Yet Valid',
  detail: 'The status list credential is not yet valid.'
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

function statusTypeString(type: unknown): string | undefined {
  if (typeof type === 'string') {
    return type;
  }
  if (Array.isArray(type) && typeof type[0] === 'string') {
    return type[0];
  }
  return undefined;
}

function credentialStatusTypes(credential: Record<string, unknown>): string[] {
  const credentialStatus = credential.credentialStatus as
    Record<string, unknown> | Array<Record<string, unknown>> | undefined;

  if (!credentialStatus) {
    return [];
  }

  const entries = Array.isArray(credentialStatus)
    ? credentialStatus
    : [credentialStatus];
  return entries.map(entry => String(statusTypeString(entry.type)));
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
 * and reports an expired or not-yet-valid list as a rejection whose problem
 * detail carries the library's date message. Those are surfaced as
 * `STATUS_LIST_EXPIRED` / `STATUS_LIST_NOT_YET_VALID` rather than as a
 * signature error.
 */
function statusListProofProblems(
  dispatched: Exclude<CryptoDispatchResult, { kind: 'verified' }>
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
      const { problems } = dispatched;
      if (problems.some(p => p.detail.includes(EXPIRED_ERROR))) {
        return [STATUS_LIST_EXPIRED_PROBLEM];
      }
      if (problems.some(p => p.detail.includes(NOT_YET_VALID_ERROR))) {
        return [STATUS_LIST_NOT_YET_VALID_PROBLEM];
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
    return {
      verified: false,
      error: new StatusListProofError(statusListProofProblems(dispatched))
    };
  };
}

/**
 * Classify an error raised by `checkStatus` into a ProblemDetail.
 *
 * A failed proof surfaces as a wrapped {@link StatusListProofError}. An
 * unreachable list surfaces with the loader's `NotFoundError` as `cause`.
 */
function classifyStatusError(error: unknown): ProblemDetail[] {
  const err = error as {
    message?: string;
    cause?: { message?: string; name?: string };
  };
  const errorMessage = err?.message || String(error);
  const cause = err?.cause;
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
        detail: errorMessage
      }
    ];
  }

  if (causeMessage.startsWith(STATUS_TYPE_ERROR)) {
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
      detail:
        errorMessage || 'An error occurred while checking credential status.'
    }
  ];
}

/**
 * Bitstring status list check for revocation/suspension status.
 *
 * This is a **fatal** check: if the verifier cannot conclude that the
 * credential is currently un-revoked and un-suspended (because the
 * status list is missing, has an invalid signature, is expired, has a
 * wrong type, or actually marks the credential as revoked or
 * suspended), the overall verification result is `verified: false`.
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
 *
 * Only `BitstringStatusListEntry` entries are checked. Entries of any
 * other type (legacy `StatusList2021Entry` / `1EdTechRevocationList`, or
 * unknown types) are ignored; the check is skipped when no Bitstring entry
 * is present.
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

    const types = credentialStatusTypes(credential);
    if (types.length === 0) {
      return {
        status: 'skipped',
        reason: 'Credential has no credentialStatus.'
      };
    }

    if (!types.includes(BITSTRING_ENTRY_TYPE)) {
      const unchecked = [...new Set(types)].map(t => `"${t}"`).join(', ');
      const allLegacy = types.every(t => LEGACY_STATUS_TYPES.includes(t));
      return {
        status: 'skipped',
        reason: allLegacy
          ? `Legacy status type ${unchecked} is not checked.`
          : `Status type ${unchecked} is not ${BITSTRING_ENTRY_TYPE}.`
      };
    }

    try {
      const statusResult = await checkStatus({
        credential,
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
      // lives in each per-status `results[].status`. Treat any set bit as a
      // failed status check.
      const revokedOrSuspended = (statusResult.results ?? []).some(result =>
        Boolean(result?.status)
      );

      if (statusResult.verified === true && !revokedOrSuspended) {
        return {
          status: 'success',
          message: 'Credential status is valid (not revoked or suspended).'
        };
      }

      return {
        status: 'failure',
        problems: [
          {
            type: ProblemTypes.CREDENTIAL_REVOKED_OR_SUSPENDED,
            title: 'Credential Revoked or Suspended',
            detail:
              'The credential has been revoked or suspended according to the status list.'
          }
        ]
      };
    } catch (error) {
      return { status: 'failure', problems: classifyStatusError(error) };
    }
  }
};
