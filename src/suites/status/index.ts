import { VerificationSuite } from '../../types/check.js';
import { bitstringStatusCheck } from './bitstring-status-check.js';

/**
 * Credential status verification suite.
 *
 * Sole owner of status verification (post-P-E, 2026-04-19). Checks
 * revocation and suspension status via BitstringStatusList. The
 * underlying check is **fatal** — see {@link bitstringStatusCheck}
 * for the contract.
 *
 * Skipped when no entry is checked:
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
  checks: [bitstringStatusCheck]
};
