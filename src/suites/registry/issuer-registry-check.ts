import { VerificationCheck, CheckOutcome } from '../../types/check.js';
import { ProblemDetail } from '../../types/problem-detail.js';
import { VerificationSubject } from '../../types/subject.js';
import { VerificationContext } from '../../types/context.js';
import { ProblemTypes } from '../../problem-types.js';
import { errorMessage } from '../../util/error-message.js';
import { credentialIssuerId } from '../../util/issuer-id.js';

/** The noun for a count of registries, as the messages pluralize it. */
function registriesNoun(count: number): string {
  return count === 1 ? 'registry' : 'registries';
}

/**
 * Issuer registry check.
 *
 * Looks up the credential's issuer DID in known DID registries to determine
 * if the issuer is trusted/registered. This is a non-fatal informational check.
 *
 * Requires {@link VerificationContext.lookupIssuers} to be set — the
 * `Verifier` factory always populates it. Hand-built contexts that omit
 * it cause this check to skip.
 *
 * Skipped when:
 * - No registries provided in VerificationContext
 * - No `lookupIssuers` in VerificationContext
 *
 * Success when:
 * - Issuer found in at least one registry
 *
 * Failure when:
 * - Issuer not found in any registry that answered (`ISSUER_NOT_REGISTERED`).
 *   When some registries could not be checked, the detail says how many
 *   answered and a `REGISTRY_UNCHECKED` problem follows naming the rest
 * - Every registry could not be checked (`REGISTRY_UNCHECKED` only, since
 *   no registry answered and "not registered" was never established)
 *
 * Whenever the lookup ran, on success and on both of those failures, the
 * outcome carries a {@link RegistryCheckPayload}: the registries that
 * matched, with what each knows about the issuer, and the registries that
 * could not be checked. Read that rather than parsing the `message`.
 */
export const issuerRegistryCheck: VerificationCheck = {
  id: 'registry.issuer',
  name: 'Issuer Registry Check',
  description: 'Checks if the issuer DID appears in known DID registries.',
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

    // Skip if no registries in context (an explicitly empty list means the
    // caller opted out of registry lookup, e.g. for self-issued credentials)
    if (!context.registries || context.registries.length === 0) {
      return {
        status: 'skipped',
        reason: 'No registries configured in verification context.'
      };
    }

    const issuerDid = credentialIssuerId(credential);

    if (!issuerDid) {
      return {
        status: 'failure',
        problems: [
          {
            type: ProblemTypes.ISSUER_NOT_FOUND,
            title: 'Issuer Not Found',
            detail: 'Credential has no issuer or issuer ID is missing.'
          }
        ]
      };
    }

    const lookupIssuers = context.lookupIssuers;
    if (!lookupIssuers) {
      return {
        status: 'skipped',
        reason: 'No lookupIssuers in verification context.'
      };
    }

    try {
      const result = await lookupIssuers(issuerDid, context.registries);

      // Names are for the message only; the payload carries the registries
      // themselves, so a name containing ", " survives.
      const { found, ...payload } = result;
      const uncheckedNames = payload.uncheckedRegistries.map(
        registry => registry.name
      );

      const uncheckedCount = uncheckedNames.length;
      const uncheckedSummary = `${uncheckedCount} ${registriesNoun(uncheckedCount)} could not be checked: ${uncheckedNames.join(', ')}`;

      if (found) {
        const matchingNames = payload.matches.map(match => match.registry.name);
        const message =
          matchingNames.length === 1
            ? `Issuer found in registry: ${matchingNames[0]}`
            : `Issuer found in ${matchingNames.length} registries: ${matchingNames.join(', ')}`;

        // Include unchecked registries info if any
        const fullMessage =
          uncheckedCount > 0 ? `${message}. ${uncheckedSummary}` : message;

        return {
          status: 'success',
          message: fullMessage,
          payload
        };
      }

      // Every registry is queried when nothing is found, so equal counts
      // mean no registry answered at all (an injected lookup reporting more
      // is treated the same).
      if (uncheckedCount >= context.registries.length) {
        return {
          status: 'failure',
          problems: [
            {
              type: ProblemTypes.REGISTRY_UNCHECKED,
              title: 'Registry Unchecked',
              detail: `Issuer registration could not be determined: ${uncheckedSummary}`
            }
          ],
          payload
        };
      }

      // Issuer not found. Only the registries that answered establish that;
      // the REGISTRY_UNCHECKED problem below names the rest.
      const checkedCount = context.registries.length - uncheckedCount;
      const problems: ProblemDetail[] = [
        {
          type: ProblemTypes.ISSUER_NOT_REGISTERED,
          title: 'Issuer Not Registered',
          detail:
            uncheckedCount === 0
              ? `Issuer ${issuerDid} was not found in any known DID registry.`
              : `Issuer ${issuerDid} was not found in the ${checkedCount} ${registriesNoun(checkedCount)} that could be checked; ${uncheckedCount} could not be checked.`
        }
      ];

      if (uncheckedCount > 0) {
        problems.push({
          type: ProblemTypes.REGISTRY_UNCHECKED,
          title: 'Registry Unchecked',
          detail: uncheckedSummary
        });
      }

      return {
        status: 'failure',
        problems,
        payload
      };
    } catch (error) {
      // Error during registry lookup
      return {
        status: 'failure',
        problems: [
          {
            type: ProblemTypes.REGISTRY_ERROR,
            title: 'Registry Lookup Error',
            detail: errorMessage(
              error,
              'An error occurred while looking up issuer in registries.'
            )
          }
        ]
      };
    }
  }
};
