/**
 * Acceptance evidence for status-list cryptosuite parity: the
 * `cryptoServices` injected into `createVerifier` are the only set that
 * governs BitstringStatusListCredential proof verification.
 *
 * Runs offline with real signatures; see
 * `test/factories/services/offline-signing.ts`.
 *
 * Pairing: the status list is signed with `Ed25519Signature2020`; the
 * subject credential is signed with `eddsa-rdfc-2022` so its proof is
 * verifiable under both service sets. The only variable between (a) and
 * (b) is whether the injected set includes `Ed25519Signature2020`.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { issue } from '@interop/vc';
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
import { FakeTimeService } from '../src/services/time-service/fake-time-service.js';
import { DataIntegrityCryptoService } from '../src/services/data-integrity-crypto.js';
import { ProblemTypes } from '../src/problem-types.js';
import type { DocumentLoader } from '../src/types/context.js';
import { BitstringStatusEntry } from './factories/data/index.js';
import {
  documentLoader as bundledLoader,
  ED25519_2020_CONTEXT,
  offlineHttpGetService,
  offlineSigner
} from './factories/services/offline-signing.js';

const STATUS_LIST_URL = 'https://factory.test/status/parity-list';
const EXPIRED_STATUS_LIST_URL = 'https://factory.test/status/expired-list';

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
  let signedSubjectWithExpiredList: Record<string, unknown>;
  let documentLoader: DocumentLoader;

  beforeAll(async () => {
    const { did: issuerDid, signer } = await offlineSigner(11);

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
      ED25519_2020_CONTEXT
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

    // A list from the subject's issuer whose validity has ended. vc's
    // `issue` does not check dates, so it signs without complaint.
    const signedExpiredStatusList = (await issue({
      credential: {
        ...unsignedList,
        id: EXPIRED_STATUS_LIST_URL,
        validUntil: '2021-01-01T00:00:00Z',
        credentialSubject: {
          ...(unsignedList.credentialSubject as Record<string, unknown>),
          id: `${EXPIRED_STATUS_LIST_URL}#list`
        }
      } as never,
      suite: new Ed25519Signature2020({ signer }),
      documentLoader: bundledLoader
    })) as Record<string, unknown>;

    signedSubjectWithExpiredList = (await issue({
      credential: subjectTemplate(issuerDid, EXPIRED_STATUS_LIST_URL) as never,
      suite: new DataIntegrityProof({
        signer,
        cryptosuite: eddsaRdfc2022CryptoSuite
      }),
      documentLoader: bundledLoader
    })) as Record<string, unknown>;

    const hosted: Record<string, Record<string, unknown>> = {
      [STATUS_LIST_URL]: signedStatusList,
      [EXPIRED_STATUS_LIST_URL]: signedExpiredStatusList
    };
    documentLoader = async (url: string) => {
      if (hosted[url]) {
        return { contextUrl: null, document: hosted[url], documentUrl: url };
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

  it('(c) reports an authentic but expired list as STATUS_LIST_EXPIRED, not as a bad signature', async () => {
    const result = await verifierWith([eddsaAndEd25519()]).verifyCredential({
      credential: signedSubjectWithExpiredList,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(false);
    const statusResult = result.results.find(
      r => r.check === 'status.bitstring'
    );
    expect(statusResult?.outcome.status).toBe('failure');
    if (statusResult?.outcome.status === 'failure') {
      expect(statusResult.outcome.problems[0].type).toBe(
        ProblemTypes.STATUS_LIST_EXPIRED
      );
      expect(statusResult.outcome.problems[0].detail).toContain(
        EXPIRED_STATUS_LIST_URL
      );
      expect(statusResult.outcome.problems[0].detail).toContain(
        'has expired. Validity ended at 2021-01-01T00:00:00Z (validUntil)'
      );
    }
  });

  it('(c2) judges the credential and its status list at one instant per verification', async () => {
    const seen: Date[] = [];
    const inner = eddsaAndEd25519();
    const capturing: typeof inner = {
      ...inner,
      verifyCredential: (credential, options) => {
        seen.push(options.now as Date);
        return inner.verifyCredential(credential, options);
      }
    };
    // `FakeTimeService` advances one millisecond per `dateNowMs()` call, so
    // instants read per check would differ.
    const verifier = createVerifier({
      httpGetService: offlineHttpGetService,
      documentLoader,
      cryptoServices: [capturing],
      timeService: FakeTimeService(),
      verbose: true
    });
    await verifier.verifyCredential({
      credential: signedSubject,
      phases: ['cryptographic']
    });

    expect(seen).toHaveLength(2);
    expect(seen[0]).toBeInstanceOf(Date);
    expect(seen[1]).toBe(seen[0]);
  });

  it('(d) judges the list at the verifier clock: the expired list verifies when the clock is inside its validity window', async () => {
    // The list is valid from 2020-01-01 until 2021-01-01.
    const verifier = createVerifier({
      httpGetService: offlineHttpGetService,
      documentLoader,
      cryptoServices: [eddsaAndEd25519()],
      timeService: FakeTimeService({
        baseDateMs: Date.parse('2020-06-01T00:00:00Z')
      }),
      verbose: true
    });
    const result = await verifier.verifyCredential({
      credential: signedSubjectWithExpiredList,
      phases: ['cryptographic']
    });

    const statusResult = result.results.find(
      r => r.check === 'status.bitstring'
    );
    expect(statusResult?.outcome.status).toBe('success');
    expect(result.verified).toBe(true);
  });
});
