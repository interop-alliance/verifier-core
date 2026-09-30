/**
 * Acceptance evidence for status-list cryptosuite parity: the
 * `cryptoServices` injected into `createVerifier` are the only set that
 * governs BitstringStatusListCredential proof verification.
 *
 * Runs offline with real signatures. `did:key` resolves from the identifier
 * itself and every `@context` used here is bundled in
 * `@interop/security-document-loader`. The `httpGetService` throws
 * if anything reaches for the network.
 *
 * Pairing: the status list is signed with `Ed25519Signature2020`; the
 * subject credential is signed with `eddsa-rdfc-2022` so its proof is
 * verifiable under both service sets. The only variable between (a) and
 * (b) is whether the injected set includes `Ed25519Signature2020`.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { issue } from '@interop/vc';
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key';
import {
  Ed25519Signature2020,
  eddsaRdfc2022 as eddsaRdfc2022CryptoSuite
} from '@interop/ed25519-signature';
import { DataIntegrityProof } from '@interop/data-integrity-proof';
import {
  createCredential,
  createList
} from '@interop/vc-bitstring-status-list';
import { createVerifier } from '../src/verifier.js';
import { defaultDocumentLoaderFor } from '../src/default-services.js';
import { DataIntegrityCryptoService } from '../src/services/data-integrity-crypto.js';
import { ProblemTypes } from '../src/problem-types.js';
import type { DocumentLoader } from '../src/types/context.js';
import type { HttpGetService } from '../src/services/http-get-service/http-get-service.js';
import type { HttpGetResult } from '../src/types/http.js';
import { BitstringStatusEntry } from './factories/data/index.js';

const STATUS_LIST_URL = 'https://factory.test/status/parity-list';

const offlineHttpGetService: HttpGetService = {
  async get(url: string): Promise<HttpGetResult> {
    throw new Error(`test reached the network for ${url}`);
  }
};

const bundledLoader = defaultDocumentLoaderFor(offlineHttpGetService);

function subjectTemplate(
  issuerDid: string,
  statusListUrl: string
): Record<string, unknown> {
  return {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://w3id.org/security/data-integrity/v2'
    ],
    id: 'urn:uuid:status-list-cryptosuite-parity-subject',
    type: ['VerifiableCredential'],
    issuer: issuerDid,
    validFrom: '2020-01-01T00:00:00Z',
    credentialSubject: { id: 'did:example:subject' },
    credentialStatus: BitstringStatusEntry({
      statusListCredential: statusListUrl,
      statusListIndex: '0',
      statusPurpose: 'revocation'
    })
  };
}

describe('status list cryptosuite parity', () => {
  let signedStatusList: Record<string, unknown>;
  let signedSubject: Record<string, unknown>;
  let documentLoader: DocumentLoader;

  beforeAll(async () => {
    const key = await Ed25519VerificationKey.generate({
      seed: new Uint8Array(32).fill(11)
    });
    const issuerDid = `did:key:${key.fingerprint()}`;
    const signer = key.didKeySigner();

    const list = await createList({ length: 32 });
    const unsignedList = (await createCredential({
      id: STATUS_LIST_URL,
      list,
      statusPurpose: 'revocation'
    })) as unknown as Record<string, unknown>;
    unsignedList.issuer = issuerDid;
    unsignedList.validFrom = '2020-01-01T00:00:00Z';
    const listContext = unsignedList['@context'];
    unsignedList['@context'] = [
      ...(Array.isArray(listContext) ? listContext : [listContext]),
      'https://w3id.org/security/suites/ed25519-2020/v1'
    ];

    signedStatusList = (await issue({
      credential: unsignedList as never,
      suite: new Ed25519Signature2020({ signer }),
      documentLoader: bundledLoader
    })) as Record<string, unknown>;

    signedSubject = (await issue({
      credential: subjectTemplate(issuerDid, STATUS_LIST_URL) as never,
      suite: new DataIntegrityProof({
        signer,
        cryptosuite: eddsaRdfc2022CryptoSuite
      }),
      documentLoader: bundledLoader
    })) as Record<string, unknown>;

    documentLoader = async (url: string) => {
      if (url === STATUS_LIST_URL) {
        return {
          contextUrl: null,
          document: signedStatusList,
          documentUrl: url
        };
      }
      return bundledLoader(url);
    };
  });

  const eddsaOnly = () =>
    DataIntegrityCryptoService({
      suites: [
        new DataIntegrityProof({ cryptosuite: eddsaRdfc2022CryptoSuite })
      ]
    });

  const eddsaAndEd25519 = () =>
    DataIntegrityCryptoService({
      suites: [
        new Ed25519Signature2020(),
        new DataIntegrityProof({ cryptosuite: eddsaRdfc2022CryptoSuite })
      ]
    });

  function verifierWith(cryptoServices: ReturnType<typeof eddsaOnly>[]) {
    return createVerifier({
      httpGetService: offlineHttpGetService,
      documentLoader,
      cryptoServices,
      verbose: true
    });
  }

  it('(a) fails status.bitstring with STATUS_LIST_SIGNATURE_ERROR when the injected set lacks the list credential suite', async () => {
    const result = await verifierWith([eddsaOnly()]).verifyCredential({
      credential: signedSubject,
      phases: ['cryptographic']
    });

    const statusResult = result.results.find(
      r => r.check === 'status.bitstring'
    );
    expect(statusResult, 'status.bitstring result present').toBeDefined();
    expect(statusResult?.outcome.status).toBe('failure');
    if (statusResult?.outcome.status === 'failure') {
      expect(statusResult.outcome.problems[0].type).toBe(
        ProblemTypes.STATUS_LIST_SIGNATURE_ERROR
      );
    }

    const proofResult = result.results.find(r => r.check === 'proof.signature');
    expect(proofResult?.outcome.status).toBe('success');
  });

  it('(b) succeeds status.bitstring when the injected set includes the list credential suite', async () => {
    const result = await verifierWith([eddsaAndEd25519()]).verifyCredential({
      credential: signedSubject,
      phases: ['cryptographic']
    });

    const statusResult = result.results.find(
      r => r.check === 'status.bitstring'
    );
    expect(statusResult, 'status.bitstring result present').toBeDefined();
    expect(statusResult?.outcome.status).toBe('success');
    expect(result.verified).toBe(true);
  });
});
