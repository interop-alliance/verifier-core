import { describe, it, expect, beforeAll } from 'vitest';
import {
  createDID,
  logToJsonlString,
  signerFromDidKeySigner,
  type DIDLog
} from '@interop/did-method-webvh';
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key';
import { createSigner, eddsaRdfc2022 } from '@interop/ed25519-signature';
import { DataIntegrityProof } from '@interop/data-integrity-proof';
import { issue } from '@interop/vc';
import { didWebvhDriverWithHttpGet } from '../../src/util/did-webvh-driver-with-http-get.js';
import { documentLoaderFromHttpGet } from '../../src/util/document-loader-from-http-get.js';
import { signatureCheck } from '../../src/suites/proof/signature-check.js';
import { ProblemTypes } from '../../src/problem-types.js';
import { buildTestContext } from '../factories/services/build-test-context.js';
import {
  FakeHttpGetService,
  httpGetResult,
  okJsonBody
} from '../factories/services/fake-http-get-service.js';
import type { HttpGetResult } from '../../src/types/http.js';
import type { HttpGetService } from '../../src/services/http-get-service/http-get-service.js';

const LOG_URL = 'https://example.com/.well-known/did.jsonl';
const WITNESS_URL = 'https://example.com/.well-known/did-witness.json';

/**
 * Serves a DID log (as raw JSON Lines text, the shape `BuiltinHttpGetService`
 * returns for a multi-entry log) and a 404 for the witness file.
 */
function serviceFor(logResult: HttpGetResult) {
  return FakeHttpGetService({
    [LOG_URL]: logResult,
    [WITNESS_URL]: httpGetResult(404, 'Not Found')
  });
}

function jsonlResult(log: DIDLog): HttpGetResult {
  return httpGetResult(200, `${logToJsonlString(log)}\n`);
}

describe('didWebvhDriverWithHttpGet', () => {
  let did: string;
  let log: DIDLog;
  let vmId: string;
  let assertionKey: Ed25519VerificationKey;

  beforeAll(async () => {
    const updateKey = await Ed25519VerificationKey.generate();
    assertionKey = await Ed25519VerificationKey.generate();
    ({ did, log } = await createDID({
      address: 'example.com',
      signer: signerFromDidKeySigner(updateKey.didKeySigner()),
      updateKeys: [updateKey.publicKeyMultibase],
      verificationMethods: [
        {
          type: 'Multikey',
          publicKeyMultibase: assertionKey.publicKeyMultibase,
          purpose: 'assertionMethod'
        }
      ]
    }));
    const doc = log[log.length - 1].state as { assertionMethod: string[] };
    vmId = doc.assertionMethod[0];
  });

  it('resolves a did:webvh DID to its verified DID document', async () => {
    const service = serviceFor(jsonlResult(log));
    const driver = didWebvhDriverWithHttpGet(service);

    const doc = (await driver.get({ did })) as { assertionMethod?: string[] };

    expect(doc).toHaveProperty('id', did);
    expect(doc.assertionMethod).toEqual([vmId]);
    expect(service.callsTo(LOG_URL)).toBe(1);
  });

  it('accepts a single-entry log the HttpGetService already parsed as JSON', async () => {
    // A one-line did.jsonl is valid JSON, so `BuiltinHttpGetService` hands it
    // back parsed rather than as text.
    const driver = didWebvhDriverWithHttpGet(serviceFor(okJsonBody(log[0])));

    const doc = await driver.get({ did });

    expect(doc.id).toBe(did);
  });

  it('dereferences a DID URL fragment to its verification method', async () => {
    const driver = didWebvhDriverWithHttpGet(serviceFor(jsonlResult(log)));

    const vm = await driver.get({ url: vmId });

    expect(vm).toMatchObject({
      '@context': 'https://w3id.org/security/multikey/v1',
      id: vmId,
      type: 'Multikey',
      controller: did,
      publicKeyMultibase: assertionKey.publicKeyMultibase
    });
  });

  it('rejects a tampered log', async () => {
    const tampered = structuredClone(log);
    const state = tampered[0].state as {
      verificationMethod: Array<{ publicKeyMultibase: string }>;
    };
    const otherKey = await Ed25519VerificationKey.generate();
    state.verificationMethod[0].publicKeyMultibase =
      otherKey.publicKeyMultibase;
    const driver = didWebvhDriverWithHttpGet(serviceFor(jsonlResult(tampered)));

    await expect(driver.get({ did })).rejects.toThrow();
  });

  it('rejects when the log cannot be fetched', async () => {
    const driver = didWebvhDriverWithHttpGet(
      serviceFor(httpGetResult(404, 'Not Found'))
    );

    await expect(driver.get({ did })).rejects.toThrow();
  });

  it('is registered in the default document loader', async () => {
    const loader = documentLoaderFromHttpGet(serviceFor(jsonlResult(log)));

    const { document } = await loader(vmId);

    expect((document as { id: string }).id).toBe(vmId);
  });

  describe('credential signed by a did:webvh verification method', () => {
    let credential: unknown;

    beforeAll(async () => {
      // The assertion key signs as the did:webvh verification method.
      assertionKey.id = vmId;
      assertionKey.controller = did;
      const suite = new DataIntegrityProof({
        signer: createSigner(assertionKey),
        cryptosuite: eddsaRdfc2022
      });
      credential = await issue({
        credential: {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
          type: ['VerifiableCredential'],
          issuer: did,
          credentialSubject: { description: 'hi' }
        } as never,
        suite: suite as never,
        documentLoader: documentLoaderFromHttpGet(
          serviceFor(jsonlResult(log))
        ) as never
      });
    });

    async function verifyWith(httpGetService: HttpGetService) {
      return signatureCheck.execute(
        { verifiableCredential: credential as never },
        buildTestContext({ httpGetService })
      );
    }

    it('verifies end to end', async () => {
      const outcome = await verifyWith(serviceFor(jsonlResult(log)));

      expect(outcome.status).toBe('success');
    });

    it('fails verification against a tampered log', async () => {
      const tampered = structuredClone(log);
      (tampered[0] as { versionTime: string }).versionTime =
        '2020-01-01T00:00:00Z';

      const outcome = await verifyWith(serviceFor(jsonlResult(tampered)));

      expect(outcome.status).toBe('failure');
      if (outcome.status === 'failure') {
        // A log that fails verification is not an unreachable one.
        expect(outcome.problems[0].type).not.toBe(
          ProblemTypes.DID_WEB_UNRESOLVED
        );
      }
    });

    it.each<[string, HttpGetService]>([
      ['returns 404', serviceFor(httpGetResult(404, 'Not Found'))],
      ['returns 503', serviceFor(httpGetResult(503, 'Service Unavailable'))],
      [
        'fails in transport',
        {
          async get() {
            throw new TypeError('fetch failed');
          }
        }
      ]
    ])(
      'reports DID_WEB_UNRESOLVED when the log fetch %s',
      async (_, service) => {
        const outcome = await verifyWith(service);

        expect(outcome.status).toBe('failure');
        if (outcome.status === 'failure') {
          expect(outcome.problems[0].type).toBe(
            ProblemTypes.DID_WEB_UNRESOLVED
          );
          expect(outcome.problems[0].detail).toContain(did);
        }
      }
    );
  });
});
