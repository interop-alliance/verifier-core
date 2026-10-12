import { VerificationCheck, CheckOutcome } from '../../types/check.js';
import { ProblemDetail } from '../../types/problem-detail.js';
import { VerificationSubject } from '../../types/subject.js';
import { VerificationContext } from '../../types/context.js';
import { ProblemTypes } from '../../problem-types.js';
import { credentialIssuerId } from '../../util/issuer-id.js';
import {
  checkedStatusListUrls,
  takeVerifiedStatusLists
} from './status-lists.js';

/**
 * Machine-readable `code` values carried on this check's `'skipped'`
 * outcomes. Branch on these rather than on the prose `reason`.
 */
export const STATUS_LIST_ISSUER_SKIP_CODES = {
  /** No `BitstringStatusListEntry` for revocation or suspension to check. */
  noListChecked: 'no-list-checked',
  /**
   * A checked entry's list was not verified before this check ran:
   * `status.bitstring` did not run in this pass, or never recorded it.
   */
  listNotVerified: 'list-not-verified'
} as const;

/**
 * Reports a status list that is not issued by the credential's issuer.
 *
 * Without this, a validly signed list from any DID decides revocation, so
 * whoever controls the list host can un-revoke a credential unseen. The
 * check compares the list's `issuer` id with the credential's by exact
 * string (a string issuer, or an issuer object's `id`), the same rule
 * `@interop/vc-bitstring-status-list` uses. A missing issuer on either
 * side counts as a mismatch.
 *
 * It runs after `status.bitstring` and takes the lists that check's
 * `verifyStatusListCredential` hook recorded during its run. The hook
 * verified each list's proof through the configured `cryptoServices`.
 * Whether that proof also binds the signing key to the list's claimed
 * `issuer` is up to the crypto service: the default
 * `DataIntegrityCryptoService` requires the issuer to match the controller
 * of the verification method, so with it a list's `issuer` is the proven
 * signer. A custom `CryptoService` that checks only the signature leaves
 * the list's `issuer` a self-claim, and this check then compares that
 * claim. When `status.bitstring` fails it is fatal and this check is
 * reported as not run. When it did not run at all, or never recorded a
 * list this check needs, the check is skipped with the
 * `listNotVerified` code from {@link STATUS_LIST_ISSUER_SKIP_CODES}.
 *
 * This is a warning (`fatal: false`): `verified` is unchanged. Some
 * status services sign every list with one DID of their own rather than
 * the issuing tenant's, so a mismatch is normal in those deployments. A
 * consumer that needs the binding enforced should treat
 * `STATUS_LIST_ISSUER_MISMATCH` as decisive.
 */
export const statusListIssuerCheck: VerificationCheck = {
  id: 'status.list-issuer',
  name: 'Status List Issuer Check',
  description:
    "Reports when a status list is not issued by the credential's issuer.",
  fatal: false,
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

    const urls = checkedStatusListUrls(credential);
    if (urls.length === 0) {
      return {
        status: 'skipped',
        reason: 'No status list was checked.',
        code: STATUS_LIST_ISSUER_SKIP_CODES.noListChecked
      };
    }

    const credentialIssuer = credentialIssuerId(credential);
    const lists = takeVerifiedStatusLists(context);
    const problems: ProblemDetail[] = [];
    for (const url of urls) {
      const list = lists.get(url);
      if (list === undefined) {
        return {
          status: 'skipped',
          reason: `The proof of status list ${url} was not verified before this check ran.`,
          code: STATUS_LIST_ISSUER_SKIP_CODES.listNotVerified
        };
      }
      const listIssuer = credentialIssuerId(list);
      if (listIssuer === undefined || listIssuer !== credentialIssuer) {
        problems.push({
          type: ProblemTypes.STATUS_LIST_ISSUER_MISMATCH,
          title: 'Status List Issuer Mismatch',
          detail: `The status list ${url} is issued by ${listIssuer ?? '(no issuer)'}, not by the credential's issuer ${credentialIssuer ?? '(no issuer)'}.`
        });
      }
    }

    if (problems.length > 0) {
      return { status: 'failure', problems };
    }

    return {
      status: 'success',
      message: "Every status list is issued by the credential's issuer."
    };
  }
};
