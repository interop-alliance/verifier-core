import { describe, it, expect } from 'vitest';
import { driver } from '@interop/did-method-key';
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key';
import { createSigner, eddsaRdfc2022 } from '@interop/ed25519-signature';
import * as EcdsaMultikey from '@interop/ecdsa-multikey';
import { ecdsaRdfc2019 } from '@interop/ecdsa-signature';
import { DataIntegrityProof } from '@interop/data-integrity-proof';
import { securityLoader } from '@interop/security-document-loader';
import { issue } from '@interop/vc';
import { runSuites } from '../../src/run-suites.js';
import { defaultCryptoServices } from '../../src/default-services.js';
import { proofSuite } from '../../src/suites/proof/index.js';
import { signatureCheck } from '../../src/suites/proof/signature-check.js';
import { buildTestContext } from '../factories/services/build-test-context.js';
import { VerificationSubject } from '../../src/types/subject.js';
import { CredentialFactory } from '../factories/data/credential-factory.js';
import { PresentationFactory } from '../factories/data/presentation-factory.js';
import { FakeCryptoService } from '../factories/services/fake-crypto-service.js';
import { ProblemTypes } from '../../src/problem-types.js';
import { v2WithValidStatus } from '../fixtures/v2-with-valid-status.js';

/** Generate a did:key and return its id, key id, and an eddsa signer. */
async function generateDidKey(): Promise<{
  did: string;
  keyId: string;
  // The signer is intentionally typed loosely; it is only handed back to
  // `createSigner`'s consumers in this test file.
  signer: ReturnType<typeof createSigner>;
}> {
  const keyPair = await Ed25519VerificationKey.generate();
  const didDriver = driver();
  didDriver.use({ keyPairClass: Ed25519VerificationKey });
  const { didDocument } = await didDriver.fromKeyPair({
    verificationKeyPair: keyPair
  });
  const did = didDocument.id as string;
  keyPair.controller = did;
  keyPair.id = `${did}#${keyPair.fingerprint()}`;
  return { did, keyId: keyPair.id, signer: createSigner(keyPair) };
}

/** Generate an ECDSA (P-256) did:key and return its id, key id, and signer. */
async function generateEcdsaDidKey(): Promise<{
  did: string;
  keyId: string;
  // The signer is intentionally typed loosely; ECDSA keypairs expose their own
  // `.signer()` (there is no `createSigner` equivalent in `@interop/ecdsa-signature`).
  signer: ReturnType<typeof createSigner>;
}> {
  const keyPair = await EcdsaMultikey.generate({ curve: 'P-256' });
  const didDriver = driver();
  const { didDocument } = await didDriver.fromKeyPair({
    verificationKeyPair: keyPair
  });
  const did = didDocument.id as string;
  const keyId = (didDocument.assertionMethod as string[])[0];
  keyPair.controller = did;
  keyPair.id = keyId;
  return {
    did,
    keyId,
    signer: keyPair.signer() as ReturnType<typeof createSigner>
  };
}

function subjectHasLinkedDataProof(subject: VerificationSubject): boolean {
  const doc = subject.verifiablePresentation ?? subject.verifiableCredential;
  if (doc === undefined || doc === null || typeof doc !== 'object') {
    return false;
  }
  const proof = (doc as Record<string, unknown>).proof;
  if (proof === undefined || proof === null) {
    return false;
  }
  if (Array.isArray(proof)) {
    return (
      proof.length > 0 && typeof proof[0] === 'object' && proof[0] !== null
    );
  }
  return typeof proof === 'object';
}

describe('Proof Verification Suite', () => {
  const createCredentialSubject = (
    credential: unknown
  ): VerificationSubject => ({
    verifiableCredential: credential
  });

  const createPresentationSubject = (
    presentation: unknown
  ): VerificationSubject => ({
    verifiablePresentation: presentation
  });

  describe('FakeCryptoService — credential', () => {
    it('returns success when service verifies', async () => {
      const context = buildTestContext({
        cryptoServices: [FakeCryptoService({ verified: true })]
      });
      const subject = createCredentialSubject(
        CredentialFactory({ version: 'v2', credential: {} })
      );
      const results = await runSuites([proofSuite], subject, context);

      expect(results).toHaveLength(1);
      expect(results[0].check).toBe('proof.signature');
      expect(results[0].outcome.status).toBe('success');
      if (results[0].outcome.status === 'success') {
        expect(results[0].outcome.message).toBe('Fake verification passed.');
      }
    });

    it('returns failure with injected problems when service rejects', async () => {
      const problems = [
        {
          type: 'https://www.w3.org/TR/vc-data-model#INVALID_SIGNATURE',
          title: 'Invalid Signature',
          detail: 'Tampered payload'
        }
      ];
      const context = buildTestContext({
        cryptoServices: [FakeCryptoService({ verified: false, problems })]
      });
      const subject = createCredentialSubject(
        CredentialFactory({ version: 'v2', credential: {} })
      );
      const results = await runSuites([proofSuite], subject, context);

      expect(results[0].outcome.status).toBe('failure');
      if (results[0].outcome.status === 'failure') {
        expect(results[0].outcome.problems).toEqual(problems);
      }
    });

    it('fails when no crypto service matches canVerify', async () => {
      const context = buildTestContext({
        cryptoServices: [
          FakeCryptoService({ canVerify: () => false, verified: true })
        ]
      });
      const subject = createCredentialSubject(
        CredentialFactory({ version: 'v2', credential: {} })
      );
      const results = await runSuites([proofSuite], subject, context);

      expect(results[0].outcome.status).toBe('failure');
      if (results[0].outcome.status === 'failure') {
        expect(results[0].outcome.problems[0].title).toBe(
          'No Applicable Crypto Service'
        );
      }
    });

    it('maps thrown errors to PROOF_VERIFICATION_ERROR', async () => {
      const context = buildTestContext({
        cryptoServices: [
          FakeCryptoService({
            throwInVerify: new Error('Crypto adapter exploded')
          })
        ]
      });
      const subject = createCredentialSubject(
        CredentialFactory({ version: 'v2', credential: {} })
      );
      const results = await runSuites([proofSuite], subject, context);

      expect(results[0].outcome.status).toBe('failure');
      if (results[0].outcome.status === 'failure') {
        expect(results[0].outcome.problems[0].type).toBe(
          'https://www.w3.org/TR/vc-data-model#PROOF_VERIFICATION_ERROR'
        );
        expect(results[0].outcome.problems[0].detail).toContain('exploded');
      }
    });
  });

  describe('FakeCryptoService — presentation', () => {
    it('verifies presentation when service returns success', async () => {
      const context = buildTestContext({
        cryptoServices: [FakeCryptoService({ verified: true })],
        challenge: 'factory-challenge'
      });
      const presentation = PresentationFactory();
      const subject = createPresentationSubject(presentation);
      const results = await runSuites([proofSuite], subject, context);

      expect(results).toHaveLength(1);
      expect(results[0].check).toBe('proof.signature');
      expect(results[0].outcome.status).toBe('success');
    });

    it('handles unsigned presentation when context allows it', async () => {
      const context = buildTestContext({
        cryptoServices: [FakeCryptoService({ verified: true })],
        unsignedPresentation: true
      });
      const presentation = PresentationFactory();
      delete (presentation as { proof?: unknown }).proof;

      const subject = createPresentationSubject(presentation);
      const results = await runSuites([proofSuite], subject, context);

      expect(results[0].outcome.status).toBe('success');
    });
  });

  describe('did:web-style resolution (orchestrated failure)', () => {
    it('surfaces HTTP-style failures from the crypto service', async () => {
      const problems = [
        {
          type: 'https://www.w3.org/TR/vc-data-model#HTTP_ERROR',
          title: 'HTTP Error',
          detail: 'did:web resolution failed'
        }
      ];
      const context = buildTestContext({
        cryptoServices: [FakeCryptoService({ verified: false, problems })]
      });
      const cred = CredentialFactory({
        version: 'v2',
        credential: {
          issuer: {
            id: 'did:web:nonexistent-domain-12345.example.com',
            name: 'X'
          }
        }
      });
      const subject = createCredentialSubject(cred);
      const results = await runSuites([proofSuite], subject, context);

      expect(results[0].outcome.status).toBe('failure');
      if (results[0].outcome.status === 'failure') {
        expect(results[0].outcome.problems[0].type).toBe(
          'https://www.w3.org/TR/vc-data-model#HTTP_ERROR'
        );
      }
    });
  });

  describe('JSON-LD / classification path via fake adapter', () => {
    it('returns structured failure for parsing-style errors', async () => {
      const problems = [
        {
          type: 'https://www.w3.org/TR/vc-data-model#PARSING_ERROR',
          title: 'JSON-LD Validation Error',
          detail: 'Invalid JSON-LD document'
        }
      ];
      const context = buildTestContext({
        cryptoServices: [FakeCryptoService({ verified: false, problems })]
      });
      const cred = CredentialFactory({
        version: 'v2',
        credential: { '@context': 'https://www.w3.org/ns/credentials/v2' }
      });
      const subject = createCredentialSubject(cred);
      const results = await runSuites([proofSuite], subject, context);

      expect(results[0].outcome.status).toBe('failure');
      if (results[0].outcome.status === 'failure') {
        expect(results[0].outcome.problems[0].type).toBe(
          'https://www.w3.org/TR/vc-data-model#PARSING_ERROR'
        );
      }
    });
  });

  describe('no subject', () => {
    it('skips check when neither credential nor presentation provided', async () => {
      const context = buildTestContext({
        cryptoServices: [FakeCryptoService({ verified: true })]
      });
      const subject: VerificationSubject = {};
      const results = await runSuites([proofSuite], subject, context);

      expect(results).toHaveLength(0);
    });

    it('fails when credential has no proof and adapter requires one', async () => {
      const context = buildTestContext({
        cryptoServices: [
          FakeCryptoService({
            canVerify: subjectHasLinkedDataProof,
            verified: true
          })
        ]
      });
      const cred = CredentialFactory({ version: 'v2', credential: {} });
      delete (cred as { proof?: unknown }).proof;

      const subject = createCredentialSubject(cred);
      const results = await runSuites([proofSuite], subject, context);

      expect(results).toHaveLength(1);
      expect(results[0].outcome.status).toBe('failure');
      if (results[0].outcome.status === 'failure') {
        expect(results[0].outcome.problems[0].title).toBe(
          'No Applicable Crypto Service'
        );
      }
    });
  });

  describe('signatureCheck', () => {
    it('succeeds for a VC with credentialStatus (real crypto; vc lib checkStatus requirement satisfied)', async () => {
      const ctx = buildTestContext({ cryptoServices: defaultCryptoServices() });
      const outcome = await signatureCheck.execute(
        { verifiableCredential: v2WithValidStatus },
        ctx
      );
      expect(outcome.status).toBe('success');
      expect(JSON.stringify(outcome)).not.toContain('checkStatus');
    });

    it('reports ISSUER_PROOF_MISMATCH when issuer differs from proof controller (real crypto)', async () => {
      // A cryptographically valid proof from one DID, on a credential that
      // names a different DID as its issuer. The signature itself verifies; it
      // is the proof-purpose validation that rejects the mismatch -- so the
      // problem must be surfaced as a mismatch, not as INVALID_SIGNATURE.
      const signerKey = await generateDidKey();
      const issuerKey = await generateDidKey();
      const documentLoader = securityLoader().build();
      const suite = new DataIntegrityProof({
        signer: signerKey.signer,
        cryptosuite: eddsaRdfc2022
      });
      const credential = await issue({
        credential: {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
          type: ['VerifiableCredential'],
          issuer: issuerKey.did,
          credentialSubject: { description: 'hi' }
        } as never,
        suite: suite as never,
        documentLoader: documentLoader as never
      });

      const ctx = buildTestContext({ cryptoServices: defaultCryptoServices() });
      const outcome = await signatureCheck.execute(
        { verifiableCredential: credential as never },
        ctx
      );

      expect(outcome.status).toBe('failure');
      if (outcome.status === 'failure') {
        expect(outcome.problems[0].type).toBe(
          ProblemTypes.ISSUER_PROOF_MISMATCH
        );
        expect(outcome.problems[0].detail).toContain(issuerKey.did);
      }
    });

    it('reports VERIFICATION_METHOD_UNRESOLVED when the proof DID method has no driver', async () => {
      // The default document loader registers did:key + did:web only. A proof
      // whose verification method is did:webvh can never be resolved, so the
      // signature is never actually checked -- this must surface as an
      // unresolved verification method, not a misleading INVALID_SIGNATURE.
      const credential = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential'],
        issuer: 'did:webvh:QmExampleScid:example.org',
        credentialSubject: { description: 'hi' },
        proof: {
          type: 'DataIntegrityProof',
          created: '2026-06-26T00:33:45Z',
          verificationMethod: 'did:webvh:QmExampleScid:example.org#key-1',
          cryptosuite: 'eddsa-rdfc-2022',
          proofPurpose: 'assertionMethod',
          proofValue:
            'z4CrgCcporr5zPR4gLAJLUPeb3Pk2znTJnKkup6DxiUeVgZiDsJz1ADtgJjkQ884TDHp97GNn42Y2seQHL48VyMhF'
        }
      };

      const ctx = buildTestContext({ cryptoServices: defaultCryptoServices() });
      const outcome = await signatureCheck.execute(
        { verifiableCredential: credential as never },
        ctx
      );

      expect(outcome.status).toBe('failure');
      if (outcome.status === 'failure') {
        expect(outcome.problems[0].type).toBe(
          ProblemTypes.VERIFICATION_METHOD_UNRESOLVED
        );
        expect(outcome.problems[0].detail).toContain(
          'did:webvh:QmExampleScid:example.org#key-1'
        );
      }
    });

    it('verifies an ecdsa-rdfc-2019 (P-256) did:key credential (real crypto)', async () => {
      // Exercises both halves of ECDSA support in the default services: the
      // `ecdsa-rdfc-2019` cryptosuite must be in `defaultCryptoSuites`, and the
      // default document loader must resolve the ecdsa did:key verification
      // method (the ECDSA multibase headers must be registered).
      const ecdsaKey = await generateEcdsaDidKey();
      const documentLoader = securityLoader().build();
      const suite = new DataIntegrityProof({
        signer: ecdsaKey.signer,
        cryptosuite: ecdsaRdfc2019
      });
      const credential = await issue({
        credential: {
          '@context': ['https://www.w3.org/ns/credentials/v2'],
          type: ['VerifiableCredential'],
          issuer: ecdsaKey.did,
          credentialSubject: { description: 'hi' }
        } as never,
        suite: suite as never,
        documentLoader: documentLoader as never
      });

      const ctx = buildTestContext({ cryptoServices: defaultCryptoServices() });
      const outcome = await signatureCheck.execute(
        { verifiableCredential: credential as never },
        ctx
      );

      expect(outcome.status).toBe('success');
    });
  });
});
