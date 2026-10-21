import { VerificationSuite } from '../../types/check.js';
import { bitstringStatusCheck } from './bitstring-status-check.js';
import { statusListIssuerCheck } from './list-issuer-check.js';

/**
 * Credential status verification suite.
 *
 * Sole owner of status verification (post-P-E, 2026-04-19). Checks
 * revocation and suspension status via BitstringStatusList with the
 * **fatal** {@link bitstringStatusCheck}, then reports a status list not
 * issued by the credential's issuer with the non-fatal
 * {@link statusListIssuerCheck}. The status check sets `halts: false`, so
 * the list issuer is reported after a status failure too.
 *
 * Both checks sit in the `cryptographic` phase although the issuer
 * comparison is a trust judgement: `status.list-issuer` reads the lists
 * `status.bitstring` verified in the same run, so it can only run in the
 * pass that runs `status.bitstring`. A `phases: ['trust']` pass never
 * reports it.
 *
 * Both checks are skipped when no entry is checked:
 * - Credential has no `credentialStatus`.
 * - Every entry is of another type (legacy `StatusList2021Entry` /
 *   `1EdTechRevocationList`, or unknown), or is a
 *   `BitstringStatusListEntry` for a purpose other than `revocation` or
 *   `suspension` (for example `refresh` or `message`). Their lists are
 *   not fetched, and the skip reason names them.
 */
export const statusSuite: VerificationSuite = {
  id: 'status',
  name: 'Credential Status',
  description:
    'Checks revocation and suspension status via BitstringStatusList.',
  phase: 'cryptographic',
  checks: [bitstringStatusCheck, statusListIssuerCheck]
};
