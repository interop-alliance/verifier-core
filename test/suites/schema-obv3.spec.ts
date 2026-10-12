import { describe, it, expect } from 'vitest';
import { runSuites } from '../../src/run-suites.js';
import { obv3SchemaSuite } from '../../src/suites/schema/obv3/index.js';
import { buildTestContext } from '../factories/services/build-test-context.js';
import { VerificationSubject } from '../../src/types/subject.js';
import { CredentialFactory } from '../factories/data/credential-factory.js';
import { FakeFetchJson } from '../factories/services/fake-fetch-json.js';
import {
  FakeHttpGetService,
  httpGetResult,
  okJsonBody
} from '../factories/services/fake-http-get-service.js';
import { FakeCacheService } from '../factories/services/fake-cache-service.js';
import { fetchJsonFromHttpGet } from '../../src/util/fetch-json-from-http-get.js';
import { SCHEMA_TTL_MS } from '../../src/suites/schema/schema-loader.js';
import type { HttpGetResult } from '../../src/types/http.js';

const OBV3_V2_ACHIEVEMENT_SCHEMA_URL =
  'https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_achievementcredential_schema.json';

const OBV3_V2_ENDORSEMENT_SCHEMA_URL =
  'https://purl.imsglobal.org/spec/ob/v3p0/schema/json/ob_v3p0_endorsementcredential_schema.json';

function minimalSchema($id: string): Record<string, unknown> {
  return {
    $id,
    $schema: 'https://json-schema.org/draft/2019-09/schema',
    type: 'object',
    required: ['@context', 'type', 'issuer', 'credentialSubject'],
    additionalProperties: true,
    properties: {
      '@context': {},
      type: {},
      issuer: {},
      credentialSubject: {}
    }
  };
}

describe('OBv3 Schema Suite', () => {
  const createSubject = (credential: unknown): VerificationSubject => ({
    verifiableCredential: credential
  });

  describe('OBv3 schema check', () => {
    it('skips when credential is not OBv3-shaped', async () => {
      const cred = CredentialFactory({
        version: 'v1',
        credential: {
          type: ['VerifiableCredential'],
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://w3id.org/security/suites/ed25519-2020/v1'
          ]
        }
      });
      const context = buildTestContext({
        fetchJson: FakeFetchJson({})
      });
      const results = await runSuites(
        [obv3SchemaSuite],
        createSubject(cred),
        context
      );

      const schemaCheck = results.find(r => r.check === 'schema.obv3.json');
      expect(schemaCheck?.outcome.status).toBe('skipped');
    });

    it('validates OpenBadgeCredential when schema is served locally', async () => {
      const cred = CredentialFactory({ version: 'v2', credential: {} });
      const fetchJson = FakeFetchJson({
        [OBV3_V2_ACHIEVEMENT_SCHEMA_URL]: minimalSchema(
          OBV3_V2_ACHIEVEMENT_SCHEMA_URL
        )
      });
      const context = buildTestContext({ fetchJson });
      const results = await runSuites(
        [obv3SchemaSuite],
        createSubject(cred),
        context
      );

      const schemaCheck = results.find(r => r.check === 'schema.obv3.json');
      expect(schemaCheck?.outcome.status).toBe('success');
    });

    it('validates EndorsementCredential when schema is served locally', async () => {
      const cred = CredentialFactory({
        version: 'v2',
        credential: { type: ['VerifiableCredential', 'EndorsementCredential'] }
      });
      const fetchJson = FakeFetchJson({
        [OBV3_V2_ENDORSEMENT_SCHEMA_URL]: minimalSchema(
          OBV3_V2_ENDORSEMENT_SCHEMA_URL
        )
      });
      const context = buildTestContext({ fetchJson });
      const results = await runSuites(
        [obv3SchemaSuite],
        createSubject(cred),
        context
      );

      const schemaCheck = results.find(r => r.check === 'schema.obv3.json');
      expect(schemaCheck?.outcome.status).toBe('success');
    });

    it('fails AJV validation when credential is missing required fields', async () => {
      const cred = CredentialFactory({ version: 'v2', credential: {} });
      delete (cred as { credentialSubject?: unknown }).credentialSubject;

      const fetchJson = FakeFetchJson({
        [OBV3_V2_ACHIEVEMENT_SCHEMA_URL]: minimalSchema(
          OBV3_V2_ACHIEVEMENT_SCHEMA_URL
        )
      });
      const context = buildTestContext({ fetchJson });
      const results = await runSuites(
        [obv3SchemaSuite],
        createSubject(cred),
        context
      );

      const schemaCheck = results.find(r => r.check === 'schema.obv3.json');
      expect(schemaCheck?.outcome.status).toBe('failure');
      if (schemaCheck?.outcome.status === 'failure') {
        expect(schemaCheck.outcome.problems[0].type).toBe(
          'https://www.w3.org/TR/vc-data-model#SCHEMA_VALIDATION_FAILED'
        );
      }
    });

    it('uses credentialSchema id when specified', async () => {
      const customUrl = 'https://factory.test/custom-credential-schema.json';
      const cred = CredentialFactory({
        version: 'v2',
        credential: {
          credentialSchema: {
            id: customUrl,
            type: 'JsonSchemaValidator2018'
          }
        }
      });
      const fetchJson = FakeFetchJson({
        [customUrl]: minimalSchema(customUrl)
      });
      const context = buildTestContext({ fetchJson });
      const results = await runSuites(
        [obv3SchemaSuite],
        createSubject(cred),
        context
      );

      const schemaCheck = results.find(r => r.check === 'schema.obv3.json');
      expect(schemaCheck?.outcome.status).toBe('success');
    });

    it('uses first credentialSchema entry when property is an array', async () => {
      const customUrl = 'https://factory.test/array-first-schema.json';
      const cred = CredentialFactory({
        version: 'v2',
        credential: {
          credentialSchema: [
            { id: customUrl, type: 'JsonSchemaValidator2018' },
            {
              id: 'https://factory.test/ignored.json',
              type: 'JsonSchemaValidator2018'
            }
          ]
        }
      });
      const fetchJson = FakeFetchJson({
        [customUrl]: minimalSchema(customUrl)
      });
      const context = buildTestContext({ fetchJson });
      const results = await runSuites(
        [obv3SchemaSuite],
        createSubject(cred),
        context
      );

      const schemaCheck = results.find(r => r.check === 'schema.obv3.json');
      expect(schemaCheck?.outcome.status).toBe('success');
    });

    it('fails when schema URL cannot be fetched', async () => {
      const cred = CredentialFactory({ version: 'v2', credential: {} });
      const context = buildTestContext({
        fetchJson: FakeFetchJson({})
      });
      const results = await runSuites(
        [obv3SchemaSuite],
        createSubject(cred),
        context
      );

      const schemaCheck = results.find(r => r.check === 'schema.obv3.json');
      expect(schemaCheck?.outcome.status).toBe('failure');
      if (schemaCheck?.outcome.status === 'failure') {
        expect(schemaCheck.outcome.problems[0].type).toBe(
          'https://www.w3.org/TR/vc-data-model#SCHEMA_VALIDATION_ERROR'
        );
        expect(schemaCheck.outcome.problems[0].detail).toContain(
          'No fake response'
        );
      }
    });
  });

  describe('schema caching', () => {
    const KNOWN_URL = OBV3_V2_ACHIEVEMENT_SCHEMA_URL;
    const cred = CredentialFactory({ version: 'v2', credential: {} });

    /** A fake HTTP service serving `urlMap` (mutable, so a test can flip a URL) and a fetchJson over it. */
    const httpFor = (urlMap: Record<string, HttpGetResult>) => {
      const http = FakeHttpGetService(urlMap);
      return { http, urlMap, fetchJson: fetchJsonFromHttpGet(http) };
    };
    const servingKnownSchema = () =>
      httpFor({ [KNOWN_URL]: okJsonBody(minimalSchema(KNOWN_URL)) });

    const statusOf = async (
      credential: unknown,
      context: ReturnType<typeof buildTestContext>
    ) => {
      const results = await runSuites(
        [obv3SchemaSuite],
        createSubject(credential),
        context
      );
      return results.find(r => r.check === 'schema.obv3.json')?.outcome?.status;
    };

    it('compiles a known schema once per fetchJson, even without a cacheService', async () => {
      const { http, fetchJson } = servingKnownSchema();

      for (let i = 0; i < 3; i++) {
        const context = {
          ...buildTestContext({ fetchJson }),
          cacheService: undefined
        };
        expect(await statusOf(cred, context)).toBe('success');
      }

      expect(http.callsTo(KNOWN_URL)).toBe(1);
    });

    it('fetches an unknown credentialSchema URL on every run without caching it', async () => {
      const customUrl = 'https://factory.test/issuer-chosen-schema.json';
      const customCred = CredentialFactory({
        version: 'v2',
        credential: {
          credentialSchema: { id: customUrl, type: 'JsonSchemaValidator2018' }
        }
      });
      const { http, fetchJson } = httpFor({
        [customUrl]: okJsonBody(minimalSchema(customUrl))
      });
      const cacheService = FakeCacheService();

      for (let i = 0; i < 3; i++) {
        const context = buildTestContext({ fetchJson, cacheService });
        expect(await statusOf(customCred, context)).toBe('success');
      }

      expect(http.callsTo(customUrl)).toBe(3);
      expect(await cacheService.get(`schema:${customUrl}`)).toBeUndefined();
    });

    it('retries a known schema after a failed fetch instead of keeping the failure', async () => {
      const { urlMap, fetchJson } = httpFor({
        [KNOWN_URL]: httpGetResult(404, null)
      });
      const cacheService = FakeCacheService();

      const failed = await runSuites(
        [obv3SchemaSuite],
        createSubject(cred),
        buildTestContext({ fetchJson, cacheService })
      );
      const outcome = failed.find(r => r.check === 'schema.obv3.json')?.outcome;
      expect(outcome?.status).toBe('failure');
      if (outcome?.status === 'failure') {
        expect(outcome.problems[0].type).toBe(
          'https://www.w3.org/TR/vc-data-model#SCHEMA_VALIDATION_ERROR'
        );
      }

      urlMap[KNOWN_URL] = okJsonBody(minimalSchema(KNOWN_URL));
      expect(
        await statusOf(cred, buildTestContext({ fetchJson, cacheService }))
      ).toBe('success');
    });

    it('retries a nested $ref that failed to load, after AJV registered the root', async () => {
      const nestedUrl = 'https://factory.test/nested.json';
      const root = {
        ...minimalSchema(KNOWN_URL),
        properties: { issuer: { $ref: nestedUrl } }
      };
      const { http, urlMap, fetchJson } = httpFor({
        [KNOWN_URL]: okJsonBody(root),
        [nestedUrl]: httpGetResult(404, null)
      });
      // One cacheService for both runs, so the second run reuses the AJV that
      // already registered the root.
      const cacheService = FakeCacheService();

      expect(
        await statusOf(cred, buildTestContext({ fetchJson, cacheService }))
      ).toBe('failure');

      urlMap[nestedUrl] = okJsonBody({ $id: nestedUrl, type: 'object' });
      expect(
        await statusOf(cred, buildTestContext({ fetchJson, cacheService }))
      ).toBe('success');
      expect(http.callsTo(nestedUrl)).toBe(2);
    });

    it('recompiles a known schema once SCHEMA_TTL_MS has passed on the context clock', async () => {
      const { http, fetchJson } = servingKnownSchema();
      const start = new Date('2026-01-01T00:00:00Z');
      const verifyAt = (offsetMs: number) =>
        statusOf(cred, {
          ...buildTestContext({
            fetchJson,
            now: new Date(start.getTime() + offsetMs)
          }),
          cacheService: undefined
        });

      expect(await verifyAt(0)).toBe('success');
      expect(await verifyAt(SCHEMA_TTL_MS - 1)).toBe('success');
      expect(http.callsTo(KNOWN_URL)).toBe(1);

      expect(await verifyAt(SCHEMA_TTL_MS)).toBe('success');
      expect(http.callsTo(KNOWN_URL)).toBe(2);
    });

    it('reads and writes the cacheService of the current context, not the first one seen', async () => {
      const { http, fetchJson } = servingKnownSchema();
      const first = FakeCacheService();
      const second = FakeCacheService();
      const key = `schema:${KNOWN_URL}`;

      await statusOf(
        cred,
        buildTestContext({ fetchJson, cacheService: first })
      );
      expect(await first.get(key)).toBeDefined();
      expect(await second.get(key)).toBeUndefined();

      await statusOf(
        cred,
        buildTestContext({ fetchJson, cacheService: second })
      );
      expect(await second.get(key)).toBeDefined();
      expect(http.callsTo(KNOWN_URL)).toBe(2);
    });
  });

  describe('non-OBv3 credential types', () => {
    it('skips schema check for plain VC without OBv3 context', async () => {
      const cred = CredentialFactory({
        version: 'v1',
        credential: {
          type: ['VerifiableCredential'],
          '@context': [
            'https://www.w3.org/2018/credentials/v1',
            'https://w3id.org/security/suites/ed25519-2020/v1'
          ]
        }
      });
      const results = await runSuites(
        [obv3SchemaSuite],
        createSubject(cred),
        buildTestContext()
      );

      expect(results).toHaveLength(1);
      expect(results[0].outcome.status).toBe('skipped');
    });
  });
});
