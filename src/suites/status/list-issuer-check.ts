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
   * A checked entry's list was not established before this check ran:
   * `status.bitstring` did not run in this pass, could not load the list,
   * or its proof did not verify.
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
 * claim.
 *
 * `status.bitstring` does not halt, so this check also runs after a
 * status failure. A list rejected only for its validity dates is recorded
 * too, since the dates are judged only once the proof verified. So a list
 * that marks the credential revoked, or has expired, is still checked for
 * who signed it. Every recorded list is compared, and a mismatch fails
 * the check. When some list was not recorded (`status.bitstring` did not
 * run in this pass, could not load it, or its proof did not verify) and
 * no recorded list mismatched, the check is skipped with the
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
    let unestablished = false;
    for (const url of urls) {
      const list = lists.get(url);
      if (list === undefined) {
        unestablished = true;
        continue;
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

    if (unestablished) {
      return {
        status: 'skipped',
        reason:
          'A status list could not be loaded or its proof did not verify; status.bitstring reports why.',
        code: STATUS_LIST_ISSUER_SKIP_CODES.listNotVerified
      };
    }

    return {
      status: 'success',
      message: "Every status list is issued by the credential's issuer."
    };
  }
};
