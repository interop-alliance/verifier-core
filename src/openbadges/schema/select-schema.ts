/**
 * Which vendored Open Badges schema applies to a credential.
 *
 * Chosen from the credential's OB type and VC version only. The credential's
 * own `credentialSchema` never takes part: an issuer could otherwise name a
 * permissive schema and skip the Open Badges one.
 */

import { CheckOutcome } from '../../types/check.js';
import { VerificationSubject } from '../../types/subject.js';
import { vcVersionOf } from '../../util/vc-contexts.js';
import {
  isEndorsementCredential,
  isOpenBadgeCredential
} from '../recognize.js';
import {
  VENDORED_OB_SCHEMAS,
  type VendoredObSchema
} from './json-schema/index.js';

export type ObType = VendoredObSchema['obType'];
export type VcVersion = VendoredObSchema['vcVersion'];

/**
 * The Open Badges type of a credential, or `null` for anything else. An
 * `OpenBadgeCredential` is checked first, so a credential carrying both types
 * is treated as an achievement credential.
 */
export function getObType(credential: unknown): ObType | null {
  if (isOpenBadgeCredential(credential)) {
    return 'OpenBadgeCredential';
  }
  if (isEndorsementCredential(credential)) {
    return 'EndorsementCredential';
  }
  return null;
}

/** The vendored schema for an OB type and VC version. */
function vendoredSchemaFor(
  obType: ObType,
  vcVersion: VcVersion
): VendoredObSchema {
  const found = VENDORED_OB_SCHEMAS.find(
    s => s.obType === obType && s.vcVersion === vcVersion
  );
  if (!found) {
    // Unreachable while all four schemas are vendored.
    throw new Error(
      `No vendored Open Badges schema for ${obType} / ${vcVersion}`
    );
  }
  return found;
}

/**
 * The subject's credential and the vendored schema that applies to it, or
 * the `'skipped'` outcome both schema checks return when none does: no
 * credential, not an Open Badges credential, or neither VC context.
 */
export function selectObSchema(subject: VerificationSubject):
  | {
      credential: Record<string, unknown>;
      obType: ObType;
      vcVersion: VcVersion;
      vendored: VendoredObSchema;
    }
  | CheckOutcome {
  const credential = subject.verifiableCredential as
    Record<string, unknown> | undefined;
  if (!credential) {
    return {
      status: 'skipped',
      reason: 'No verifiable credential found in subject.'
    };
  }
  const obType = getObType(credential);
  if (!obType) {
    return {
      status: 'skipped',
      reason:
        'Credential does not appear to be an OBv3 credential (OpenBadgeCredential or EndorsementCredential).'
    };
  }
  const vcVersion = vcVersionOf(credential['@context']);
  if (!vcVersion) {
    return {
      status: 'skipped',
      reason:
        'Credential has neither the VC 1.1 nor the VC 2.0 context, so no Open Badges schema applies.'
    };
  }
  return {
    credential,
    obType,
    vcVersion,
    vendored: vendoredSchemaFor(obType, vcVersion)
  };
}
