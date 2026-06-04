import { checkStatus } from '@digitalcredentials/vc-bitstring-status-list';
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

// Error patterns from constants/external.ts
const NOT_FOUND_ERROR = 'NotFoundError';
const EXPIRED_ERROR = 'is after "validUntil"';
const STATUS_SIGNATURE_ERROR = 'Verification error';
const STATUS_TYPE_ERROR =
  'Status list credential type must include "BitstringStatusListCredential".';
const STATUS_NOT_YET_VALID_ERROR = 'is before "validFrom"';

function statusTypeString(type: unknown): string | undefined {
  if (typeof type === 'string') {
    return type;
  }
  if (Array.isArray(type) && typeof type[0] === 'string') {
    return type[0];
  }
  return undefined;
}

/**
 * Check if the credential has a valid status type that we can check.
 */
function hasBitstringStatusList(credential: Record<string, unknown>): boolean {
  const credentialStatus = credential.credentialStatus as
    | Record<string, unknown>
    | Array<Record<string, unknown>>
    | undefined;

  if (!credentialStatus) {
    return false;
  }

  // Normalize to array
  const statuses = Array.isArray(credentialStatus)
    ? credentialStatus
    : [credentialStatus];

  if (statuses.length === 0) {
    return false;
  }

  const [firstStatus] = statuses;
  const statusType = statusTypeString(firstStatus?.type);

  return statusType === 'BitstringStatusListEntry';
}

/**
 * Get the status type for skip reason messages.
 */
function getStatusType(
  credential: Record<string, unknown>
): string | undefined {
  const credentialStatus = credential.credentialStatus as
    | Record<string, unknown>
    | Array<Record<string, unknown>>
    | undefined;

  if (!credentialStatus) {
    return undefined;
  }

  const statuses = Array.isArray(credentialStatus)
    ? credentialStatus
    : [credentialStatus];
  if (statuses.length === 0) {
    return undefined;
  }

  return statusTypeString(statuses[0]?.type);
}

/**
 * Classify status check error into ProblemDetail.
 */
function classifyStatusError(error: unknown): ProblemDetail[] {
  const err = error as {
    message?: string;
    cause?: { message?: string };
    name?: string;
  };
  const errorMessage = err?.message || String(error);
  const causeMessage = err?.cause?.message || '';

  // Not found error
  if (
    err?.name === NOT_FOUND_ERROR ||
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

  // Expired error
  if (
    causeMessage.includes(EXPIRED_ERROR) ||
    errorMessage.includes(EXPIRED_ERROR.toLowerCase())
  ) {
    return [
      {
        type: ProblemTypes.STATUS_LIST_EXPIRED,
        title: 'Status List Expired',
        detail: 'The status list credential has expired.'
      }
    ];
  }

  // Signature verification error
  if (causeMessage.startsWith(STATUS_SIGNATURE_ERROR)) {
    return [
      {
        type: ProblemTypes.STATUS_LIST_SIGNATURE_ERROR,
        title: 'Status List Signature Error',
        detail: 'The status list credential signature could not be verified.'
      }
    ];
  }

  // Type error
  if (causeMessage.startsWith(STATUS_TYPE_ERROR)) {
    return [
      {
        type: ProblemTypes.STATUS_LIST_TYPE_ERROR,
        title: 'Status List Type Error',
        detail: STATUS_TYPE_ERROR
      }
    ];
  }

  // Not yet valid error
  if (causeMessage.includes(STATUS_NOT_YET_VALID_ERROR)) {
    return [
      {
        type: ProblemTypes.STATUS_LIST_NOT_YET_VALID,
        title: 'Status List Not Yet Valid',
        detail: 'The status list credential is not yet valid.'
      }
    ];
  }

  // Generic status error
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
 * `statusSuite` is the sole owner of status verification; the proof
 * suite no longer performs an embedded status check (P-E, 2026-04-19).
 *
 * Skipped (and therefore non-failing) when:
 * - Credential has no `credentialStatus`.
 * - Status type is a legacy type (`StatusList2021Entry`,
 *   `1EdTechRevocationList`).
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
      | Record<string, unknown>
      | undefined;

    if (!credential) {
      return {
        status: 'skipped',
        reason: 'No verifiable credential found in subject.'
      };
    }

    // Check if credential has any credentialStatus
    if (!credential.credentialStatus) {
      return {
        status: 'skipped',
        reason: 'Credential has no credentialStatus.'
      };
    }

    // Check for legacy status types that we skip
    const statusType = getStatusType(credential);
    if (statusType && LEGACY_STATUS_TYPES.includes(statusType)) {
      return {
        status: 'skipped',
        reason: `Legacy status type "${statusType}" is not checked.`
      };
    }

    // Check if it's a BitstringStatusListEntry
    if (!hasBitstringStatusList(credential)) {
      return {
        status: 'skipped',
        reason: `Status type "${String(statusType)}" is not BitstringStatusListEntry.`
      };
    }

    try {
      const verifySl = context.verifyBitstringStatusListCredential ?? true;

      const statusResult = (await checkStatus({
        credential,
        documentLoader: context.documentLoader,
        suite: context.cryptoSuites,
        verifyBitstringStatusListCredential: verifySl,
        // Hosted status lists may use a different issuer than the VC (see DataIntegrityCryptoService).
        verifyMatchingIssuers: false
      })) as { verified?: boolean; error?: unknown };

      if (statusResult.error !== undefined) {
        return {
          status: 'failure',
          problems: classifyStatusError(statusResult.error)
        };
      }

      if (statusResult.verified === true) {
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
      const problems = classifyStatusError(error);
      return {
        status: 'failure',
        problems
      };
    }
  }
};
