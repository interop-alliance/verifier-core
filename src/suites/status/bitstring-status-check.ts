import { checkStatus } from '@interop/vc-bitstring-status-list';
import {
  dispatchProofVerification,
  type CryptoDispatchResult
} from '../../crypto-dispatch.js';
import { VerificationCheck, CheckOutcome } from '../../types/check.js';
import { ProblemDetail } from '../../types/problem-detail.js';
import { VerificationSubject } from '../../types/subject.js';
import {
  VerificationContext,
  type DocumentLoader
} from '../../types/context.js';
import { ProblemTypes } from '../../problem-types.js';

// Legacy status types that are skipped
const LEGACY_STATUS_TYPES: string[] = [
  'StatusList2021Entry',
  '1EdTechRevocationList'
];

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

function statusListErrorProblem(detail: string): ProblemDetail {
  return {
    type: ProblemTypes.STATUS_LIST_ERROR,
    title: 'Status List Error',
    detail
  };
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

function credentialStatusEntries(
  credential: Record<string, unknown>
): Array<Record<string, unknown>> {
  const credentialStatus = credential.credentialStatus as
    Record<string, unknown> | Array<Record<string, unknown>> | undefined;

  if (!credentialStatus) {
    return [];
  }

  return Array.isArray(credentialStatus)
    ? credentialStatus
    : [credentialStatus];
}

/**
 * Distinct `statusListCredential` URLs named by the credential's
 * `BitstringStatusListEntry` entries, in first-seen order. Entries of any
 * other status type are ignored, matching what `checkStatus` reads. Entries
 * without a non-empty string URL are ignored so `checkStatus` can reject that
 * input itself.
 */
function statusListCredentialUrls(
  credential: Record<string, unknown>
): string[] {
  const urls = credentialStatusEntries(credential)
    .filter(
      entry => statusTypeString(entry.type) === 'BitstringStatusListEntry'
    )
    .map(entry => entry.statusListCredential)
    .filter((url): url is string => typeof url === 'string' && url.length > 0);
  return [...new Set(urls)];
}

/**
 * Load a status list credential through the JSON-LD document loader.
 *
 * The loader contract is `{ document }` with an already-parsed object
 * (`documentLoaderFromHttpGet` parses string bodies). An unreachable list
 * maps to `STATUS_LIST_NOT_FOUND`; anything else the loader raises, or a
 * non-object document, maps to the generic `STATUS_LIST_ERROR`.
 */
async function loadStatusListCredential(
  url: string,
  documentLoader: DocumentLoader
): Promise<{ document: object } | { problems: ProblemDetail[] }> {
  let document: unknown;
  try {
    ({ document } = await documentLoader(url));
  } catch (error) {
    const err = error as { name?: string; message?: string };
    const message = err?.message || String(error);
    const detail = `Could not load "BitstringStatusListCredential"; reason: ${message}`;
    const notFound =
      err?.name === NOT_FOUND_ERROR || message.startsWith(NOT_FOUND_ERROR);
    return {
      problems: [
        notFound
          ? {
              type: ProblemTypes.STATUS_LIST_NOT_FOUND,
              title: 'Status List Not Found',
              detail
            }
          : statusListErrorProblem(detail)
      ]
    };
  }

  if (document === null || typeof document !== 'object') {
    return {
      problems: [
        statusListErrorProblem(
          `Could not load "BitstringStatusListCredential"; reason: loader returned no document for ${url}`
        )
      ]
    };
  }

  return { document };
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
 * Serves already-fetched status list credentials so `checkStatus` does
 * not issue a second GET for the same URL. Anything else (JSON-LD
 * contexts, DID documents) delegates to the original loader.
 */
function preloadedLoader(
  loaded: Map<string, object>,
  delegate: DocumentLoader
): DocumentLoader {
  return async (url: string) => {
    if (loaded.has(url)) {
      return { document: loaded.get(url), documentUrl: url };
    }
    return delegate(url);
  };
}

/**
 * Classify an error raised by `checkStatus` itself. List loading and proof
 * verification happen before `checkStatus` runs, so only its own structural
 * errors (wrong list type, purpose mismatch, bad index) land here.
 */
function classifyStatusError(error: unknown): ProblemDetail[] {
  const err = error as { message?: string; cause?: { message?: string } };
  const errorMessage = err?.message || String(error);
  const causeMessage = err?.cause?.message || '';

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
    statusListErrorProblem(
      errorMessage || 'An error occurred while checking credential status.'
    )
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
 * Proof verification of each named BitstringStatusListCredential goes
 * through {@link dispatchProofVerification} against
 * `context.cryptoServices` — the same dispatch presentation and
 * credential proofs use. `@interop/vc-bitstring-status-list`
 * keeps ownership of purpose matching, validity dates, bitstring
 * decoding, and index reading.
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
      Record<string, unknown> | undefined;

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

    const statusType = statusTypeString(
      credentialStatusEntries(credential)[0]?.type
    );
    if (statusType && LEGACY_STATUS_TYPES.includes(statusType)) {
      return {
        status: 'skipped',
        reason: `Legacy status type "${statusType}" is not checked.`
      };
    }

    if (statusType !== 'BitstringStatusListEntry') {
      return {
        status: 'skipped',
        reason: `Status type "${String(statusType)}" is not BitstringStatusListEntry.`
      };
    }

    try {
      // Load and proof-verify every named list concurrently; report the
      // first failure in entry order.
      const lists = await Promise.all(
        statusListCredentialUrls(credential).map(
          async (
            url
          ): Promise<
            { url: string; document: object } | { problems: ProblemDetail[] }
          > => {
            const loaded = await loadStatusListCredential(
              url,
              context.documentLoader
            );
            if ('problems' in loaded) {
              return { problems: loaded.problems };
            }
            const dispatched = await dispatchProofVerification({
              services: context.cryptoServices,
              subject: { verifiableCredential: loaded.document },
              options: { documentLoader: context.documentLoader }
            });
            if (dispatched.kind !== 'verified') {
              return { problems: statusListProofProblems(dispatched) };
            }
            return { url, document: loaded.document };
          }
        )
      );

      const loaded = new Map<string, object>();
      for (const list of lists) {
        if ('problems' in list) {
          return { status: 'failure', problems: list.problems };
        }
        loaded.set(list.url, list.document);
      }

      const statusResult = await checkStatus({
        credential,
        documentLoader: preloadedLoader(loaded, context.documentLoader),
        verifyBitstringStatusListCredential: false,
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
      const problems = classifyStatusError(error);
      return {
        status: 'failure',
        problems
      };
    }
  }
};
