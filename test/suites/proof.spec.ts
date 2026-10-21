import { describe, it, expect, vi } from 'vitest';
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
import {
  signatureCheck,
  SIGNATURE_SKIP_CODES
} from '../../src/suites/proof/signature-check.js';
import { unsupportedProofsCheck } from '../../src/suites/proof/unsupported-proofs-check.js';
import {
  VALIDITY_PERIOD_SKIP_CODES,
  validityPeriodCheck
} from '../../src/suites/proof/validity-period-check.js';
import type { ProblemDetail } from '../../src/types/problem-detail.js';
import type { CryptoService } from '../../src/types/crypto-service.js';
import { buildTestContext } from '../factories/services/build-test-context.js';
import { notRunOutcome } from '../factories/index.js';
import { VerificationSubject } from '../../src/types/subject.js';
import type { CheckOutcome } from '../../src/types/check.js';
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

      expect(results.map(r => r.id)).toEqual([
        'cryptographic.proof.signature',
        'cryptographic.proof.unsupported-proofs',
        'cryptographic.proof.validity-period'
      ]);
      expect(results[0].outcome.status).toBe('success');
      if (results[0].outcome.status === 'success') {
        expect(results[0].outcome.message).toBe('Fake verification passed.');
      }
      expect(results[1].outcome).toEqual({
        status: 'success',
        message: 'Every proof was checked.'
      });
      expect(results[2].outcome.status).toBe('success');
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

    it('passes context.now to the crypto service as the verification instant', async () => {
      const now = new Date('2024-05-05T00:00:00Z');
      const service = FakeCryptoService({ verified: true });
      const spy = vi.spyOn(service, 'verifyCredential');
      const context = buildTestContext({ cryptoServices: [service], now });
      const subject = createCredentialSubject(
        CredentialFactory({ version: 'v2', credential: {} })
      );
      await runSuites([proofSuite], subject, context);

      expect(spy.mock.calls[0][1].now).toBe(now);
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

      // `proof.validity-period` applies to credentials only.
      expect(results.map(r => r.id)).toEqual([
        'cryptographic.proof.signature',
        'cryptographic.proof.unsupported-proofs'
      ]);
      expect(results[0].outcome.status).toBe('success');
      expect(results[1].outcome.status).toBe('success');
    });

    /**
     * Run the proof suite over a presentation whose `proof` is replaced by
     * `proof` (or removed when `undefined`), with a spy on the crypto service.
     */
    const runWithProof = async (
      proof: unknown,
      unsignedPresentation = false
    ) => {
      const service = FakeCryptoService({ verified: true });
      const verifySpy = vi.spyOn(service, 'verifyPresentation');
      const context = buildTestContext({
        cryptoServices: [service],
        unsignedPresentation
      });
      const presentation = PresentationFactory();
      if (proof === undefined) {
        delete (presentation as { proof?: unknown }).proof;
      } else {
        presentation.proof = proof as never;
      }
      const subject = createPresentationSubject(presentation);
      const results = await runSuites([proofSuite], subject, context);
      return { outcome: results[0].outcome, verifySpy };
    };

    const expectNotSigned = (outcome: CheckOutcome) => {
      expect(outcome.status).toBe('failure');
      if (outcome.status === 'failure') {
        expect(outcome.problems[0].title).toBe('Presentation Not Signed');
      }
    };

    it('skips an unsigned presentation when context allows it', async () => {
      const { outcome, verifySpy } = await runWithProof(undefined, true);

      expect(outcome).toMatchObject({
        status: 'skipped',
        code: SIGNATURE_SKIP_CODES.unsignedPresentation
      });
      expect(verifySpy).not.toHaveBeenCalled();
    });

    it('fails an unsigned presentation when context does not allow it', async () => {
      const { outcome, verifySpy } = await runWithProof(undefined);

      expectNotSigned(outcome);
      expect(verifySpy).not.toHaveBeenCalled();
    });

    // A stray non-object entry must not hide the proof next to it. Zod rejects
    // this shape at the `verifyPresentation` boundary; a subject built directly
    // (custom entry points, `runSuites` consumers) still reaches the check.
    it('verifies a proof array that has a stray null entry instead of skipping it', async () => {
      const { proof } = PresentationFactory();
      const { outcome, verifySpy } = await runWithProof([proof, null], true);

      expect(outcome.status).toBe('success');
      expect(verifySpy).toHaveBeenCalledOnce();
    });

    it('treats a presentation with an empty proof array as unsigned', async () => {
      const { outcome, verifySpy } = await runWithProof([]);

      expectNotSigned(outcome);
      expect(verifySpy).not.toHaveBeenCalled();
    });

    it('passes challenge and domain to the crypto service', async () => {
      const service = FakeCryptoService({ verified: true });
      const verifySpy = vi.spyOn(service, 'verifyPresentation');
      const context = buildTestContext({
        cryptoServices: [service],
        challenge: 'factory-challenge',
        domain: 'verifier.example'
      });

      const subject = createPresentationSubject(PresentationFactory());
      const results = await runSuites([proofSuite], subject, context);

      expect(results[0].outcome.status).toBe('success');
      expect(verifySpy).toHaveBeenCalledWith(
        subject.verifiablePresentation,
        expect.objectContaining({
          challenge: 'factory-challenge',
          domain: 'verifier.example'
        })
      );
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

    it('fails with No Proof when credential has no proof, before consulting crypto services', async () => {
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

      expect(results).toHaveLength(3);
      expect(results[0].outcome.status).toBe('failure');
      if (results[0].outcome.status === 'failure') {
        expect(results[0].outcome.problems[0].title).toBe('No Proof');
      }
      expect(results.slice(1).map(r => r.outcome)).toEqual([
        notRunOutcome('proof.signature'),
        notRunOutcome('proof.signature')
      ]);
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
      // The default document loader has no did:example driver, so the
      // signature is never actually checked. This must surface as an
      // unresolved verification method, not a misleading INVALID_SIGNATURE.
      const credential = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential'],
        issuer: 'did:example:123',
        credentialSubject: { description: 'hi' },
        proof: {
          type: 'DataIntegrityProof',
          created: '2026-06-26T00:33:45Z',
          verificationMethod: 'did:example:123#key-1',
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
        expect(outcome.problems[0].detail).toContain('did:example:123#key-1');
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

  describe('validityPeriodCheck', () => {
    const NOW = '2026-10-20T12:00:00.000Z';
    const run = (
      version: 'v1' | 'v2',
      dates: Record<string, unknown>,
      at: string = NOW
    ) =>
      validityPeriodCheck.execute(
        createCredentialSubject(
          CredentialFactory({ version, credential: dates })
        ),
        buildTestContext({ now: new Date(at) })
      );
    const problemTypes = (outcome: Awaited<ReturnType<typeof run>>) =>
      outcome.status === 'failure' ? outcome.problems.map(p => p.type) : [];

    it('is fatal, does not halt, and runs after the other proof checks', () => {
      expect(validityPeriodCheck.fatal).toBe(true);
      expect(validityPeriodCheck.halts).toBe(false);
      expect(proofSuite.checks.map(c => c.id)).toEqual([
        'proof.signature',
        'proof.unsupported-proofs',
        'proof.validity-period'
      ]);
    });

    it('reports a v2 credential past validUntil as expired', async () => {
      const outcome = await run('v2', {
        validFrom: '2020-01-01T00:00:00Z',
        validUntil: '2021-01-01T00:00:00Z'
      });

      expect(outcome).toEqual({
        status: 'failure',
        problems: [
          {
            type: ProblemTypes.CREDENTIAL_EXPIRED,
            title: 'Credential Expired',
            detail: `Validity ended at 2021-01-01T00:00:00Z (validUntil). Verified at ${NOW}.`
          }
        ]
      });
    });

    it('reports a v2 credential before validFrom as not yet valid', async () => {
      const outcome = await run('v2', { validFrom: '2099-01-01T00:00:00Z' });

      expect(problemTypes(outcome)).toEqual([
        ProblemTypes.CREDENTIAL_NOT_YET_VALID
      ]);
    });

    it('reports a v1 credential past expirationDate as expired', async () => {
      const outcome = await run('v1', {
        issuanceDate: '2020-01-01T00:00:00Z',
        expirationDate: '2021-01-01T00:00:00Z'
      });

      expect(problemTypes(outcome)).toEqual([ProblemTypes.CREDENTIAL_EXPIRED]);
      if (outcome.status === 'failure') {
        expect(outcome.problems[0].detail).toBe(
          `Validity ended at 2021-01-01T00:00:00Z (expirationDate). Verified at ${NOW}.`
        );
      }
    });

    it('reports a v1 credential before issuanceDate as not yet valid', async () => {
      const outcome = await run('v1', { issuanceDate: '2099-01-01T00:00:00Z' });

      expect(problemTypes(outcome)).toEqual([
        ProblemTypes.CREDENTIAL_NOT_YET_VALID
      ]);
    });

    it('reports both faults when both dates are wrong', async () => {
      const outcome = await run('v2', {
        validFrom: '2099-01-01T00:00:00Z',
        validUntil: '2021-01-01T00:00:00Z'
      });

      expect(problemTypes(outcome)).toEqual([
        ProblemTypes.CREDENTIAL_EXPIRED,
        ProblemTypes.CREDENTIAL_NOT_YET_VALID
      ]);
    });

    it('treats the end date itself as still valid, as the library does', async () => {
      const outcome = await run('v2', {
        validFrom: '2020-01-01T00:00:00Z',
        validUntil: NOW
      });

      expect(outcome).toEqual({
        status: 'success',
        message: 'The credential is within its validity period.'
      });
    });

    it('ignores v2 date names on a v1 credential, as the library does', async () => {
      const outcome = await run('v1', {
        issuanceDate: '2020-01-01T00:00:00Z',
        validUntil: '2021-01-01T00:00:00Z'
      });

      expect(outcome.status).toBe('success');
    });

    it('passes a credential that states no validity period', async () => {
      const credential = CredentialFactory({ version: 'v2' });
      delete credential.validFrom;
      const outcome = await validityPeriodCheck.execute(
        createCredentialSubject(credential),
        buildTestContext({ now: new Date(NOW) })
      );

      expect(outcome).toEqual({
        status: 'success',
        message: 'No validity period stated.'
      });
    });

    it('skips a credential whose first @context is not a VC context', async () => {
      const credential = CredentialFactory({
        version: 'v2',
        credential: {
          '@context': [
            'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json',
            'https://www.w3.org/ns/credentials/v2'
          ],
          validUntil: '2020-01-01T00:00:00Z'
        }
      });
      const outcome = await validityPeriodCheck.execute(
        createCredentialSubject(credential),
        buildTestContext({ now: new Date(NOW) })
      );

      expect(outcome).toMatchObject({
        status: 'skipped',
        code: VALIDITY_PERIOD_SKIP_CODES.unknownVersion
      });
    });

    it.each([
      ['a number', 20200101],
      ['prose', 'yesterday']
    ])('skips a credential whose validUntil is %s', async (_label, value) => {
      const outcome = await run('v2', { validUntil: value });

      expect(outcome).toMatchObject({
        status: 'skipped',
        reason: 'validUntil is not a date, so the validity period cannot be judged.',
        code: VALIDITY_PERIOD_SKIP_CODES.unparseableDate
      });
    });
  });

  describe('signatureCheck: validity-date rejections', () => {
    const expired = {
      type: ProblemTypes.CREDENTIAL_EXPIRED,
      title: 'Credential Expired',
      detail: 'Credential has expired.'
    };
    const run = (problems: ProblemDetail[], proofVerified?: boolean) =>
      signatureCheck.execute(
        createCredentialSubject(CredentialFactory({ version: 'v2' })),
        buildTestContext({
          cryptoServices: [
            FakeCryptoService({ verified: false, problems, proofVerified })
          ]
        })
      );

    it('reads a rejection the service marks proofVerified as a verified signature', async () => {
      const outcome = await run([expired], true);

      expect(outcome).toEqual({
        status: 'success',
        message: 'Signature verified successfully.'
      });
    });

    it('keeps a date-only rejection without proofVerified as a failure', async () => {
      const outcome = await run([expired]);

      expect(outcome).toEqual({ status: 'failure', problems: [expired] });
    });

    it('keeps a rejection that mixes a date problem with a signature problem as a failure', async () => {
      const invalid = {
        type: ProblemTypes.INVALID_SIGNATURE,
        title: 'Invalid Signature',
        detail: 'Invalid signature.'
      };
      const outcome = await run([expired, invalid]);

      expect(outcome).toEqual({
        status: 'failure',
        problems: [expired, invalid]
      });
    });
  });

  describe('unsupportedProofsCheck', () => {
    const supported = { type: 'Ed25519Signature2020' };
    const alsoSupported = {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-rdfc-2022'
    };
    const unsupported = { type: 'DataIntegrityProof', cryptosuite: 'bbs-2023' };

    /**
     * Rejects a lone bbs-2023 proof as unsupported and verifies any other,
     * recording every proof it is handed.
     */
    function bbsUnsupported(seen: unknown[]): CryptoService {
      const answer = async (document: unknown) => {
        const { proof } = document as { proof?: { cryptosuite?: string } };
        seen.push(proof);
        return proof?.cryptosuite === 'bbs-2023'
          ? {
              verified: false as const,
              problems: [
                {
                  type: ProblemTypes.PROOF_UNSUPPORTED,
                  title: 'Unsupported Proof',
                  detail: 'Not supported here.'
                }
              ]
            }
          : { verified: true as const };
      };
      return {
        canVerify: () => true,
        verifyCredential: answer,
        verifyPresentation: answer
      };
    }

    const withProof = (proof: unknown) =>
      createCredentialSubject(
        CredentialFactory({ version: 'v2', credential: { proof } })
      );

    it('is a non-fatal check between proof.signature and proof.validity-period', () => {
      expect(unsupportedProofsCheck.fatal).toBe(false);
      expect(proofSuite.checks.indexOf(unsupportedProofsCheck)).toBe(1);
    });

    it('warns about an unsupported proof beside a verified one, reusing the verification', async () => {
      const seen: unknown[] = [];
      const results = await runSuites(
        [proofSuite],
        withProof([supported, unsupported]),
        buildTestContext({ cryptoServices: [bbsUnsupported(seen)] })
      );

      expect(results[0].outcome.status).toBe('success');
      expect(results[1]).toMatchObject({
        id: 'cryptographic.proof.unsupported-proofs',
        fatal: false,
        outcome: {
          status: 'failure',
          problems: [
            {
              type: ProblemTypes.PROOF_UNSUPPORTED,
              title: 'Unsupported Proof',
              detail:
                'Proof 2 of 2 (DataIntegrityProof, bbs-2023): Not supported here.'
            }
          ]
        }
      });
      // One call per proof, shared by both checks.
      expect(seen).toEqual([supported, unsupported]);
    });

    it('succeeds when every proof of a set was checked', async () => {
      const outcome = await unsupportedProofsCheck.execute(
        withProof([supported, alsoSupported]),
        buildTestContext({ cryptoServices: [bbsUnsupported([])] })
      );

      expect(outcome).toEqual({
        status: 'success',
        message: 'Every proof was checked.'
      });
    });

    it('succeeds for a single proof', async () => {
      const outcome = await unsupportedProofsCheck.execute(
        withProof(supported),
        buildTestContext({ cryptoServices: [bbsUnsupported([])] })
      );

      expect(outcome).toEqual({
        status: 'success',
        message: 'Every proof was checked.'
      });
    });

    it('is not run when the only proofs are unsupported, since proof.signature fails', async () => {
      const results = await runSuites(
        [proofSuite],
        withProof([unsupported, { ...unsupported, id: 'urn:proof:2' }]),
        buildTestContext({ cryptoServices: [bbsUnsupported([])] })
      );

      expect(results[0].outcome).toEqual({
        status: 'failure',
        problems: [1, 2].map(n => ({
          type: ProblemTypes.PROOF_UNSUPPORTED,
          title: 'Unsupported Proof',
          detail: `Proof ${n} of 2 (DataIntegrityProof, bbs-2023): Not supported here.`
        }))
      });
      expect(results[1].outcome).toEqual(notRunOutcome('proof.signature'));
    });

    it('skips an unsigned presentation without asking the crypto service', async () => {
      const service = FakeCryptoService({ verified: true });
      const verifySpy = vi.spyOn(service, 'verifyPresentation');
      const presentation = PresentationFactory();
      delete (presentation as { proof?: unknown }).proof;

      const outcome = await unsupportedProofsCheck.execute(
        createPresentationSubject(presentation),
        buildTestContext({
          cryptoServices: [service],
          unsignedPresentation: true
        })
      );

      expect(outcome).toEqual({
        status: 'skipped',
        reason: 'The document has no proof.'
      });
      expect(verifySpy).not.toHaveBeenCalled();
    });
  });
});
