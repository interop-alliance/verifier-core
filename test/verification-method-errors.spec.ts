/**
 * "The issuer's key setup is wrong" told apart from "the content was
 * altered", with real signatures and no network. The message pins live in
 * `test/services/classify-signature-error.spec.ts`.
 *
 * The did:web cases serve the issuer's DID document from a stub HTTP
 * service, so the controller document can list a key without authorizing it
 * for the proof purpose, or name a fragment the document does not have.
 * jsonld-signatures' own "not found" message has no end-to-end case: with the
 * installed jsonld, framing an unlisted method yields a bare context object
 * rather than null, so that branch never fires.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { issue, type VerifiableCredential } from '@interop/vc';
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key';
import {
  Ed25519Signature2020,
  eddsaRdfc2022
} from '@interop/ed25519-signature';
import { DataIntegrityProof } from '@interop/data-integrity-proof';
import { createVerifier } from '../src/verifier.js';
import { defaultDocumentLoaderFor } from '../src/default-services.js';
import { ProblemTypes } from '../src/problem-types.js';
import type { HttpGetService } from '../src/services/http-get-service/http-get-service.js';
import type { CheckResult } from '../src/types/check.js';
import {
  credentialTemplate,
  documentLoader,
  ED25519_2020_CONTEXT,
  expectProblem,
  offlineHttpGetService,
  offlineSigner,
  signatureResult
} from './factories/services/offline-signing.js';

const DID_WEB = 'did:web:example.com';
const DID_WEB_URL = 'https://example.com/.well-known/did.json';

function problemDetail(results: CheckResult[]): string | undefined {
  const outcome = signatureResult(results)?.outcome;
  return outcome?.status === 'failure' ? outcome.problems[0].detail : undefined;
}

/** Serves one did:web document; anything else is a test bug. */
function didWebHttpGetService(didDocument: unknown): HttpGetService {
  return {
    async get(url: string) {
      if (url !== DID_WEB_URL) {
        throw new Error(`test reached the network for ${url}`);
      }
      return { body: didDocument, headers: new Headers(), status: 200 };
    }
  };
}

describe('verification method errors (signed offline, did:key)', () => {
  let issuerControllerMismatch: Record<string, unknown>;
  let wrongKeyForMethod: Record<string, unknown>;
  let tampered: Record<string, unknown>;
  let unlistedFragment: Record<string, unknown>;

  beforeAll(async () => {
    const a = await offlineSigner(7);
    const b = await offlineSigner(8);

    // Issuer is DID A; signed with DID B's key, and the proof names B's
    // verification method. The signature itself verifies, but B is not A's
    // key.
    issuerControllerMismatch = (await issue({
      credential: credentialTemplate(a.did),
      suite: new Ed25519Signature2020({ signer: b.signer }),
      documentLoader
    })) as Record<string, unknown>;

    // Signed with B's key but the proof names A's verification method: the
    // bytes do not verify against the key the proof names.
    const proof = issuerControllerMismatch.proof as Record<string, unknown>;
    wrongKeyForMethod = {
      ...issuerControllerMismatch,
      proof: { ...proof, verificationMethod: a.signer.id }
    };

    const honest = (await issue({
      credential: {
        ...credentialTemplate(a.did),
        id: 'urn:uuid:verification-method-errors-tampered'
      },
      suite: new Ed25519Signature2020({ signer: a.signer }),
      documentLoader
    })) as Record<string, unknown>;
    tampered = {
      ...honest,
      credentialSubject: { id: 'did:example:someone-else' }
    };

    // A's key, but the proof names a fragment A's did:key document does not
    // have. The did:key driver rejects the fragment.
    const misnamed = await Ed25519VerificationKey.generate({
      seed: new Uint8Array(32).fill(7),
      controller: a.did,
      id: `${a.did}#not-a-key`
    });
    unlistedFragment = (await issue({
      credential: credentialTemplate(a.did),
      suite: new Ed25519Signature2020({ signer: misnamed.signer() }),
      documentLoader
    })) as Record<string, unknown>;
  });

  const verifier = () =>
    createVerifier({
      httpGetService: offlineHttpGetService,
      documentLoader,
      verbose: true
    });

  it('reports an issuer that is not the verification method controller as ISSUER_PROOF_MISMATCH', async () => {
    const result = await verifier().verifyCredential({
      credential: issuerControllerMismatch,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(false);
    expectProblem(
      result.results,
      ProblemTypes.ISSUER_PROOF_MISMATCH,
      'Issuer / Proof Mismatch'
    );
  });

  it("keeps a proof signed with another DID's key as INVALID_SIGNATURE", async () => {
    const result = await verifier().verifyCredential({
      credential: wrongKeyForMethod,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(false);
    expectProblem(
      result.results,
      ProblemTypes.INVALID_SIGNATURE,
      'Invalid Signature'
    );
  });

  it('reports a tampered credential as INVALID_SIGNATURE with the library message', async () => {
    const result = await verifier().verifyCredential({
      credential: tampered,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(false);
    expectProblem(
      result.results,
      ProblemTypes.INVALID_SIGNATURE,
      'Invalid Signature'
    );
    expect(problemDetail(result.results)).toBe('Invalid signature.');
  });

  it('reports a fragment the did:key document does not have as VERIFICATION_METHOD_ERROR', async () => {
    const result = await verifier().verifyCredential({
      credential: unlistedFragment,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(false);
    expectProblem(
      result.results,
      ProblemTypes.VERIFICATION_METHOD_ERROR,
      'Verification Method Error'
    );
    const vm = (unlistedFragment.proof as { verificationMethod: string })
      .verificationMethod;
    expect(problemDetail(result.results)).toBe(
      `Key "${vm}" not found in DID document.`
    );
  });
});

describe('verification method errors (signed offline, did:web)', () => {
  const keyId = `${DID_WEB}#key-1`;
  let key: Ed25519VerificationKey;

  beforeAll(async () => {
    key = await Ed25519VerificationKey.generate({
      seed: new Uint8Array(32).fill(9),
      controller: DID_WEB,
      id: keyId
    });
  });

  /** A DID document that lists the key but authorizes it for nothing. */
  function unauthorizingDocument(
    verificationMethod: unknown,
    keyContext: string
  ): Record<string, unknown> {
    return {
      '@context': ['https://www.w3.org/ns/did/v1', keyContext],
      id: DID_WEB,
      verificationMethod: [verificationMethod],
      assertionMethod: [],
      authentication: []
    };
  }

  /**
   * Serves `didDocument` for the issuer DID, issues `credential` with `suite`
   * against that document, and verifies the result. Every case here expects
   * `VERIFICATION_METHOD_ERROR`; the returned detail is what differs.
   */
  async function verifyDidWeb(
    didDocument: Record<string, unknown>,
    suite: Ed25519Signature2020 | DataIntegrityProof,
    credential: VerifiableCredential = credentialTemplate(DID_WEB)
  ): Promise<string | undefined> {
    const httpGetService = didWebHttpGetService(didDocument);
    const loader = defaultDocumentLoaderFor(httpGetService);
    const signed = await issue({ credential, suite, documentLoader: loader });

    const result = await createVerifier({
      httpGetService,
      documentLoader: loader,
      verbose: true
    }).verifyCredential({ credential: signed, phases: ['cryptographic'] });

    expect(result.verified).toBe(false);
    expectProblem(
      result.results,
      ProblemTypes.VERIFICATION_METHOD_ERROR,
      'Verification Method Error'
    );
    return problemDetail(result.results);
  }

  it('reports a fragment the DID document does not have as VERIFICATION_METHOD_ERROR', async () => {
    const unlisted = await Ed25519VerificationKey.generate({
      seed: new Uint8Array(32).fill(9),
      controller: DID_WEB,
      id: `${DID_WEB}#key-2`
    });

    const detail = await verifyDidWeb(
      {
        ...unauthorizingDocument(
          await key.export({ publicKey: true }),
          ED25519_2020_CONTEXT
        ),
        assertionMethod: [keyId]
      },
      new Ed25519Signature2020({ signer: unlisted.signer() })
    );

    expect(detail).toBe(
      `DID document entity with id "${DID_WEB}#key-2" not found.`
    );
  });

  it('reports a key not authorized for assertionMethod (Ed25519Signature2020) as VERIFICATION_METHOD_ERROR', async () => {
    const detail = await verifyDidWeb(
      unauthorizingDocument(
        await key.export({ publicKey: true }),
        ED25519_2020_CONTEXT
      ),
      new Ed25519Signature2020({ signer: key.signer() })
    );

    expect(detail).toMatch(
      /not authorized by controller for proof purpose "assertionMethod"\.$/
    );
  });

  it('reports a key not authorized for assertionMethod (eddsa-rdfc-2022) as VERIFICATION_METHOD_ERROR', async () => {
    const detail = await verifyDidWeb(
      unauthorizingDocument(
        await key.export({ publicKey: true }),
        'https://w3id.org/security/multikey/v1'
      ),
      new DataIntegrityProof({
        signer: key.signer(),
        cryptosuite: eddsaRdfc2022
      }),
      {
        ...credentialTemplate(DID_WEB),
        '@context': ['https://www.w3.org/ns/credentials/v2']
      }
    );

    expect(detail).toMatch(
      /not authorized by controller for proof purpose "assertionMethod"\.$/
    );
  });
});
