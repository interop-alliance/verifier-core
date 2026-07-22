import { VerificationCheck, CheckOutcome } from '../../types/check.js';
import { VerificationSubject } from '../../types/subject.js';
import { VerificationContext } from '../../types/context.js';

/**
 * Extract the issuer DID from a credential, handling both the string and
 * `{ id }` object forms of the `issuer` property.
 */
function getIssuerDid(credential: Record<string, unknown>): string | undefined {
  const issuer = credential.issuer as string | { id?: string } | undefined;
  if (typeof issuer === 'string') {
    return issuer;
  }
  if (issuer && typeof issuer === 'object' && typeof issuer.id === 'string') {
    return issuer.id;
  }
  return undefined;
}

/**
 * Build the issuer-details check.
 *
 * Unlike the built-in {@link ../registry/issuer-registry-check.ts registry
 * check} -- which returns a found/not-found verdict and reads registries off
 * the {@link VerificationContext} -- this check surfaces the full issuer
 * registry metadata (logo, legal name, homepage, registry org, etc.) on the
 * outcome's `payload` for a UI to consume. The lookup itself is injected as
 * `lookupDid` rather than read from the context, so the library never depends
 * on any concrete registry client.
 *
 * `TIssuer` is the element type of the returned `matchingIssuers` array; it
 * defaults to `unknown` and is inferred from the caller's `lookupDid` so an
 * app keeps its own richer issuer type end-to-end without this library
 * needing to model it.
 *
 * Non-fatal: an unrecognized issuer is informational, not a hard failure.
 *
 * Skipped when:
 * - No credential in the subject.
 * - The credential has no issuer DID.
 *
 * Success (always, once an issuer DID is present) with
 * `payload: { matchingIssuers }` and a found/not-found message.
 */
export function createIssuerDetailsCheck<TIssuer = unknown>(
  lookupDid: (did: string) => Promise<{ matchingIssuers: TIssuer[] }>
): VerificationCheck {
  return {
    id: 'trust.issuer-details',
    name: 'Issuer Registry Details',
    description:
      'Looks up rich issuer metadata for the credential issuer in the configured registries.',
    fatal: false,
    appliesTo: ['verifiableCredential'],
    execute: async (
      subject: VerificationSubject,
      _context: VerificationContext
    ): Promise<CheckOutcome> => {
      const credential = subject.verifiableCredential as
        Record<string, unknown> | undefined;

      if (!credential) {
        return {
          status: 'skipped',
          reason: 'No verifiable credential found in subject.'
        };
      }

      const issuerDid = getIssuerDid(credential);
      if (!issuerDid) {
        return {
          status: 'skipped',
          reason: 'Credential has no issuer DID.'
        };
      }

      const { matchingIssuers } = await lookupDid(issuerDid);
      const count = matchingIssuers.length;
      return {
        status: 'success',
        message:
          count > 0
            ? `Issuer found in ${count} registr${count === 1 ? 'y' : 'ies'}.`
            : 'Issuer not found in any configured registry.',
        payload: { matchingIssuers }
      };
    }
  };
}
