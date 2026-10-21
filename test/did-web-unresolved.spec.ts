/**
 * A did:web issuer whose DID document cannot be fetched is reported as
 * DID_WEB_UNRESOLVED, not INVALID_SIGNATURE. The credential is signed against
 * a reachable document, then verified through a service that 404s or throws.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { issue, type VerifiableCredential } from '@interop/vc';
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key';
import { Ed25519Signature2020 } from '@interop/ed25519-signature';
import { createVerifier } from '../src/verifier.js';
import { defaultDocumentLoaderFor } from '../src/default-services.js';
import { ProblemTypes } from '../src/problem-types.js';
import type { HttpGetService } from '../src/services/http-get-service/http-get-service.js';
import type { CheckResult } from '../src/types/check.js';
import {
  credentialTemplate,
  ED25519_2020_CONTEXT
} from './factories/services/offline-signing.js';

const DID_WEB = 'did:web:example.com';
const DID_WEB_URL = 'https://example.com/.well-known/did.json';
const KEY_ID = `${DID_WEB}#key-1`;

describe('did:web issuer that cannot be resolved', () => {
  let signed: VerifiableCredential;

  beforeAll(async () => {
    const key = await Ed25519VerificationKey.generate({
      seed: new Uint8Array(32).fill(11),
      controller: DID_WEB,
      id: KEY_ID
    });
    const didDocument = {
      '@context': ['https://www.w3.org/ns/did/v1', ED25519_2020_CONTEXT],
      id: DID_WEB,
      verificationMethod: [await key.export({ publicKey: true })],
      assertionMethod: [KEY_ID],
      authentication: [KEY_ID]
    };
    const reachable: HttpGetService = {
      async get() {
        return { body: didDocument, headers: new Headers(), status: 200 };
      }
    };
    signed = await issue({
      credential: credentialTemplate(DID_WEB),
      suite: new Ed25519Signature2020({ signer: key.signer() }),
      documentLoader: defaultDocumentLoaderFor(reachable)
    });
  });

  async function signatureFailureType(
    httpGetService: HttpGetService
  ): Promise<string | undefined> {
    const result = await createVerifier({
      httpGetService,
      documentLoader: defaultDocumentLoaderFor(httpGetService)
    }).verifyCredential({ credential: signed, phases: ['cryptographic'] });

    expect(result.verified).toBe(false);
    const row = result.results.find(
      (r: CheckResult) => r.id === 'cryptographic.proof.signature'
    );
    expect(row?.outcome.status).toBe('failure');
    if (row?.outcome.status !== 'failure') {
      return undefined;
    }
    expect(row.outcome.problems).toHaveLength(1);
    return row.outcome.problems[0].type;
  }

  it('reports DID_WEB_UNRESOLVED when the DID document 404s', async () => {
    const type = await signatureFailureType({
      async get(url: string) {
        expect(url).toBe(DID_WEB_URL);
        return { body: 'Not Found', headers: new Headers(), status: 404 };
      }
    });

    expect(type).toBe(ProblemTypes.DID_WEB_UNRESOLVED);
    expect(type).not.toBe(ProblemTypes.INVALID_SIGNATURE);
  });

  it('reports DID_WEB_UNRESOLVED when the host throws', async () => {
    const type = await signatureFailureType({
      async get() {
        throw new TypeError('fetch failed');
      }
    });

    expect(type).toBe(ProblemTypes.DID_WEB_UNRESOLVED);
    expect(type).not.toBe(ProblemTypes.INVALID_SIGNATURE);
  });
});
