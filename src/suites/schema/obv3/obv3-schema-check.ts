import { Ajv2019, type ValidateFunction } from 'ajv/dist/2019.js';
import addFormats from 'ajv-formats';
import { VerificationCheck, CheckOutcome } from '../../../types/check.js';
import { ProblemDetail } from '../../../types/problem-detail.js';
import { VerificationSubject } from '../../../types/subject.js';
import { FetchJson, VerificationContext } from '../../../types/context.js';
import type { CacheService } from '../../../services/cache-service/cache-service.js';
import { ProblemTypes } from '../../../problem-types.js';
import { VC_CONTEXT_V1, VC_CONTEXT_V2 } from '../../../util/vc-contexts.js';
import { errorMessage } from '../../../util/error-message.js';
import {
  isOpenBadgeCredential,
  isEndorsementCredential
} from '../../../openbadges/recognize.js';
import { createCachedSchemaLoader, SCHEMA_TTL_MS } from '../schema-loader.js';

// OBv3 schema URLs
const OBV3_SCHEMA_V1_ACHIEVEMENT =
  'https://purl.imsglobal.org/spec/ob/v3p0/schema/json-ld/ob_v3p0_anyachievementcredential_schema.json';
const OBV3_SCHEMA_V1_ENDORSEMENT =
  'https://purl.imsglobal.org/spec/ob/v3p0/schema/json-ld/ob_v3p0_anyendorsementcredential_schema.json';
const OBV3_SCHEMA_V2_ACHIEVEMENT =
  'https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json';
const OBV3_SCHEMA_V2_ENDORSEMENT =
  'https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_endorsementcredential_schema.json';

/**
 * The published OBv3 schemas: the only URLs whose JSON is cached and whose
 * validators are kept for the life of a verifier. Any other `credentialSchema`
 * URL is issuer-chosen, and keeping those would grow both caches without
 * bound.
 *
 * Each URL maps to the one `{ $ref }` wrapper handed to AJV for it. AJV keys
 * its own schema cache by object identity, so a fresh wrapper per compile
 * would leave one entry behind for every failed compile.
 */
const KNOWN_OBV3_SCHEMA_REFS: ReadonlyMap<string, { $ref: string }> = new Map(
  [
    OBV3_SCHEMA_V1_ACHIEVEMENT,
    OBV3_SCHEMA_V1_ENDORSEMENT,
    OBV3_SCHEMA_V2_ACHIEVEMENT,
    OBV3_SCHEMA_V2_ENDORSEMENT
  ].map(url => [url, { $ref: url }])
);

/**
 * Compiled validators, kept for the life of one verifier.
 *
 * A compiled validator is a function, so it cannot go in a `CacheService`.
 * This check is a singleton shared by every verifier, and AJV binds
 * `loadSchema` at construction, so the AJV must be per verifier rather than
 * module-level. `createVerifier` builds one `fetchJson` per verifier, which
 * makes it the verifier's identity here. An entry is replaced when a context
 * arrives with a different `cacheService` (a caller driving `runSuites` with
 * its own contexts) or after {@link SCHEMA_TTL_MS} on the context clock, so a
 * republished schema is picked up on the same schedule as the cached JSON.
 *
 * A `JsonSchemaValidator` port built per verifier in `createVerifier` would
 * retire this map (see docs/architecture.md, Direction).
 */
const validatorCaches = new WeakMap<
  FetchJson,
  {
    ajv: Ajv2019;
    validators: Map<string, Promise<ValidateFunction>>;
    cacheService: CacheService | undefined;
    expiresAtMs: number;
  }
>();

function newAjv(context: VerificationContext): Ajv2019 {
  const loadSchema = createCachedSchemaLoader(
    context.fetchJson,
    context.cacheService,
    url => KNOWN_OBV3_SCHEMA_REFS.has(url)
  );
  const ajv = new Ajv2019({ allErrors: true, loadSchema });
  addFormats.default(ajv);
  return ajv;
}

function validatorCacheFor(context: VerificationContext) {
  const nowMs = context.now.getTime();
  const existing = validatorCaches.get(context.fetchJson);
  if (
    existing &&
    existing.cacheService === context.cacheService &&
    nowMs < existing.expiresAtMs
  ) {
    return existing;
  }
  const cache = {
    ajv: newAjv(context),
    validators: new Map<string, Promise<ValidateFunction>>(),
    cacheService: context.cacheService,
    expiresAtMs: nowMs + SCHEMA_TTL_MS
  };
  validatorCaches.set(context.fetchJson, cache);
  return cache;
}

/**
 * Resolve the validator for `schemaUrl`. A known OBv3 schema is compiled once
 * per verifier; any other URL gets a throwaway AJV, as before.
 *
 * The compile promise is memoised so concurrent first verifications share one
 * compile, and a rejected compile is dropped so the next call retries. The
 * retry must go through `compileAsync`: `getSchema` would find a root that
 * AJV registered before a nested `$ref` failed to load and rethrow the missing
 * reference without loading it.
 */
function resolveValidator(
  context: VerificationContext,
  schemaUrl: string
): Promise<ValidateFunction> {
  const ref = KNOWN_OBV3_SCHEMA_REFS.get(schemaUrl);
  if (!ref) {
    return newAjv(context).compileAsync({ $ref: schemaUrl });
  }

  const { ajv, validators } = validatorCacheFor(context);
  const existing = validators.get(schemaUrl);
  if (existing) {
    return existing;
  }

  const pending = ajv.compileAsync(ref);
  validators.set(schemaUrl, pending);
  pending.catch(() => {
    if (validators.get(schemaUrl) === pending) {
      validators.delete(schemaUrl);
    }
  });
  return pending;
}

/**
 * Determine VC version from contexts.
 */
function getVcVersion(credential: Record<string, unknown>): 'v1' | 'v2' | null {
  const contexts = credential['@context'];
  // String or array: the credential arrives as issued, not Zod-normalized
  // (see the invariant in `verifier.ts`).
  const list = Array.isArray(contexts) ? contexts : [contexts];

  const stringContexts = list.filter(
    (ctx): ctx is string => typeof ctx === 'string'
  );

  if (stringContexts.some(ctx => ctx.startsWith(VC_CONTEXT_V2))) {
    return 'v2';
  }
  if (stringContexts.some(ctx => ctx.startsWith(VC_CONTEXT_V1))) {
    return 'v1';
  }
  return null;
}

/**
 * Select the appropriate OBv3 schema URL.
 */
function selectObv3Schema(
  credential: Record<string, unknown>
): { schema: string | null; obType: string; source: string } | null {
  const credentialSchema = credential.credentialSchema as
    Array<{ id: string }> | { id: string } | undefined;

  // If credentialSchema is specified, use those URLs directly
  if (credentialSchema) {
    const schemas = Array.isArray(credentialSchema)
      ? credentialSchema
      : [credentialSchema];
    if (schemas.length > 0 && schemas[0]?.id) {
      return {
        schema: schemas[0].id,
        obType: '',
        source: 'Schema was listed in the credentialSchema property of the VC'
      };
    }
  }
  // fall through - no valid credentialSchema found

  const vcVersion = getVcVersion(credential);
  if (!vcVersion) {
    return null;
  }

  let schema: string | null = null;
  let obType = '';

  if (isOpenBadgeCredential(credential)) {
    obType = 'OpenBadgeCredential';
    schema =
      vcVersion === 'v1'
        ? OBV3_SCHEMA_V1_ACHIEVEMENT
        : OBV3_SCHEMA_V2_ACHIEVEMENT;
  } else if (isEndorsementCredential(credential)) {
    obType = 'EndorsementCredential';
    schema =
      vcVersion === 'v1'
        ? OBV3_SCHEMA_V1_ENDORSEMENT
        : OBV3_SCHEMA_V2_ENDORSEMENT;
  }

  if (!schema) {
    return null;
  }

  return {
    schema,
    obType,
    source: `Assumed based on vc.type: '${obType}' and vc version: '${vcVersion}'`
  };
}

/**
 * OBv3 schema validation check.
 *
 * Validates OpenBadgeCredential and EndorsementCredential against
 * the appropriate OBv3 JSON Schema.
 *
 * Skipped when:
 * - Credential type doesn't include OpenBadgeCredential or EndorsementCredential
 * - Credential doesn't have OBv3 context
 */
export const obv3SchemaCheck: VerificationCheck = {
  id: 'schema.obv3.json',
  name: 'OBv3 JSON Schema Validation',
  description: 'Validates OBv3 credentials against published JSON Schema.',
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

    // Check if this is an OBv3 credential
    const schemaInfo = selectObv3Schema(credential);

    if (!schemaInfo?.schema) {
      return {
        status: 'skipped',
        reason:
          'Credential does not appear to be an OBv3 credential (OpenBadgeCredential or EndorsementCredential).'
      };
    }

    try {
      const validate = await resolveValidator(context, schemaInfo.schema);
      // A shared validator's `errors` is overwritten by its next call, so it
      // is read straight after the call with nothing awaited in between.
      if (validate(credential)) {
        return {
          status: 'success',
          message: `OBv3 schema validation passed. Schema: ${schemaInfo.schema}. Source: ${schemaInfo.source}`
        };
      }

      const errorDetails =
        validate.errors
          ?.map(e => {
            const message = e.message || 'Validation error';
            return e.instancePath ? `${e.instancePath}: ${message}` : message;
          })
          .join('; ') || 'Unknown validation error';

      const problems: ProblemDetail[] = [
        {
          type: ProblemTypes.SCHEMA_VALIDATION_FAILED,
          title: 'Schema Validation Failed',
          detail: `Schema validation failed for ${schemaInfo.schema}: ${errorDetails}`
        }
      ];

      return {
        status: 'failure',
        problems
      };
    } catch (error) {
      // Error during validation (e.g., couldn't fetch schema)
      return {
        status: 'failure',
        problems: [
          {
            type: ProblemTypes.SCHEMA_VALIDATION_ERROR,
            title: 'Schema Validation Error',
            detail: errorMessage(
              error,
              'An error occurred during schema validation.'
            )
          }
        ]
      };
    }
  }
};
