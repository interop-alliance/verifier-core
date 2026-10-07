/**
 * `challenge` and `domain` against the real default crypto service.
 *
 * The rule: a supplied challenge is always enforced. The presentation's proof
 * must then use the `authentication` purpose and carry that challenge (and the
 * domain, if one is passed), whatever `proofPurpose` the presentation claims.
 * With no challenge supplied, only the signature is checked. A domain without
 * a challenge fails before any crypto runs.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { signPresentation, type VerifiableCredential } from '@interop/vc';
import jsonLdSignatures from '@interop/jsonld-signatures';
import { Ed25519Signature2020 } from '@interop/ed25519-signature';
import type { ISigner } from '@interop/data-integrity-core';
import { createVerifier } from '../src/verifier.js';
import { ProblemTypes } from '../src/problem-types.js';
import type { CheckResult } from '../src/types/check.js';
import {
  documentLoader,
  expectProblem,
  expectSignatureSuccess,
  offlineHolder,
  offlineHttpGetService,
  signatureResult,
  tamper,
  unsignedPresentation
} from './factories/services/offline-signing.js';

const { purposes } = jsonLdSignatures;

/** The proof is valid but does not bind to this request. */
function expectPurposeMismatch(results: CheckResult[], title: string): void {
  expectProblem(results, ProblemTypes.PROOF_PURPOSE_MISMATCH, title);
}

function expectInvalidSignature(results: CheckResult[]): void {
  expectProblem(results, ProblemTypes.INVALID_SIGNATURE, 'Invalid Signature');
}

function expectChallengeRequired(results: CheckResult[]): void {
  expectProblem(
    results,
    ProblemTypes.PROOF_VERIFICATION_ERROR,
    'Challenge Required'
  );
}

describe('challenge enforcement with the default crypto service', () => {
  let signer: ISigner;
  let holderDid: string;
  let signedCredential: VerifiableCredential;

  beforeAll(async () => {
    ({ signer, did: holderDid, signedCredential } = await offlineHolder(5));
  });

  const verify = (
    presentation: unknown,
    options: {
      challenge?: string;
      domain?: string;
      unsignedPresentation?: boolean;
    } = {}
  ) =>
    createVerifier({
      httpGetService: offlineHttpGetService,
      documentLoader,
      verbose: true
    }).verifyPresentation({
      presentation,
      ...options,
      phases: ['cryptographic']
    });

  const unsigned = (verifiableCredential = signedCredential) =>
    unsignedPresentation(verifiableCredential, holderDid);

  const signedForAuthentication = async (
    challenge: string,
    domain?: string,
    presentation = unsigned()
  ) =>
    (await signPresentation({
      presentation: presentation as never,
      suite: new Ed25519Signature2020({ signer }),
      challenge,
      domain,
      documentLoader
    })) as Record<string, unknown>;

  const signedForAssertion = async () =>
    (await signPresentation({
      presentation: unsigned() as never,
      suite: new Ed25519Signature2020({ signer }),
      purpose: new purposes.AssertionProofPurpose(),
      documentLoader
    })) as Record<string, unknown>;

  it('fails an assertionMethod presentation when a challenge is supplied', async () => {
    const presentation = await signedForAssertion();
    expect((presentation.proof as Record<string, unknown>).proofPurpose).toBe(
      'assertionMethod'
    );

    const result = await verify(presentation, { challenge: 'x' });

    expect(result.verified).toBe(false);
    expectPurposeMismatch(result.presentationResults, 'Proof Purpose Mismatch');
  });

  it('fails an authentication presentation signed for a different challenge', async () => {
    const result = await verify(await signedForAuthentication('a'), {
      challenge: 'b'
    });

    expect(result.verified).toBe(false);
    expectPurposeMismatch(result.presentationResults, 'Challenge Mismatch');
  });

  it('rejects an empty-string challenge before any check runs', async () => {
    const result = await verify(await signedForAuthentication('a'), {
      challenge: ''
    });

    expect(result.verified).toBe(false);
    expectChallengeRequired(result.presentationResults);
    expect(result.presentationResults).toHaveLength(1);
    expect(result.credentialResults).toHaveLength(0);
    expect(result.summary[0]?.verified).toBe(false);
  });

  it('fails a document that is not a VerifiablePresentation', async () => {
    const presentation = await signedForAuthentication('a');
    presentation.type = ['NotAPresentation'];

    const result = await verify(presentation, { challenge: 'a' });

    expect(result.verified).toBe(false);
    const outcome = signatureResult(result.presentationResults)?.outcome;
    expect(outcome?.status).toBe('failure');
    if (outcome?.status === 'failure') {
      expect(outcome.problems[0].detail).toContain(
        '"type" must include "VerifiablePresentation"'
      );
    }
  });

  it('verifies an authentication presentation with the matching challenge', async () => {
    const result = await verify(await signedForAuthentication('a'), {
      challenge: 'a'
    });

    expect(result.verified).toBe(true);
    expectSignatureSuccess(result.presentationResults);
  });

  describe('domain', () => {
    it('verifies when the challenge and the domain match', async () => {
      const result = await verify(
        await signedForAuthentication('a', 'd.example'),
        { challenge: 'a', domain: 'd.example' }
      );

      expect(result.verified).toBe(true);
    });

    it('fails when the domain differs', async () => {
      const result = await verify(
        await signedForAuthentication('a', 'd.example'),
        { challenge: 'a', domain: 'other.example' }
      );

      expect(result.verified).toBe(false);
      expectPurposeMismatch(result.presentationResults, 'Domain Mismatch');
    });

    it('verifies when no domain is expected', async () => {
      const result = await verify(
        await signedForAuthentication('a', 'd.example'),
        { challenge: 'a' }
      );

      expect(result.verified).toBe(true);
    });

    it('fails with Challenge Required when a domain is passed without a challenge', async () => {
      const result = await verify(
        await signedForAuthentication('a', 'd.example'),
        { domain: 'd.example' }
      );

      expect(result.verified).toBe(false);
      expectChallengeRequired(result.presentationResults);
    });

    // The option check runs at the call boundary, so it does not depend on
    // whether the presentation carries a proof.
    it('fails with Challenge Required for an unsigned presentation too', async () => {
      const result = await verify(unsigned(), {
        domain: 'd.example',
        unsignedPresentation: true
      });

      expect(result.verified).toBe(false);
      expectChallengeRequired(result.presentationResults);
    });
  });

  it('verifies an authentication presentation on its signature when no challenge is supplied', async () => {
    const result = await verify(await signedForAuthentication('a'));

    expect(result.verified).toBe(true);
    expectSignatureSuccess(result.presentationResults);
  });

  it('verifies an authentication proof that carries no challenge when none is supplied', async () => {
    const presentation = await signPresentation({
      presentation: unsigned() as never,
      suite: new Ed25519Signature2020({ signer }),
      purpose: new purposes.ControllerProofPurpose({ term: 'authentication' }),
      documentLoader
    });
    const proof = (presentation as Record<string, unknown>).proof as Record<
      string,
      unknown
    >;
    expect(proof.proofPurpose).toBe('authentication');
    expect(proof.challenge).toBeUndefined();

    const result = await verify(presentation);

    expect(result.verified).toBe(true);
    expectSignatureSuccess(result.presentationResults);
  });

  it('verifies an assertionMethod presentation when no challenge is supplied', async () => {
    const result = await verify(await signedForAssertion());

    expect(result.verified).toBe(true);
    expectSignatureSuccess(result.presentationResults);
  });

  it('judges the presentation proof apart from a forged embedded credential', async () => {
    const forged = { ...signedCredential, name: 'Forged Credential' };
    const presentation = await signedForAuthentication(
      'a',
      undefined,
      unsigned(forged)
    );

    const result = await verify(presentation, { challenge: 'a' });

    expectSignatureSuccess(result.presentationResults);
    expect(result.credentialResults[0]?.verified).toBe(false);
    expect(result.verified).toBe(false);
  });

  // The fork scans every proof in a proof set when no challenge is supplied.
  // An assertion proof first must not let the authentication proof go
  // unchecked.
  describe('[assertion, authentication] proof set', () => {
    const signedWithBothProofs = async () => {
      const asserted = await signedForAssertion();
      const both = await signedForAuthentication('a', undefined, asserted);
      const proofs = both.proof as Array<Record<string, unknown>>;
      expect(proofs.map(p => p.proofPurpose)).toEqual([
        'assertionMethod',
        'authentication'
      ]);
      return both;
    };

    /** Same proof set with the authentication proof's signature broken. */
    const withTamperedAuthentication = async () => {
      const presentation = await signedWithBothProofs();
      const [assertion, authentication] = presentation.proof as Array<
        Record<string, unknown>
      >;
      presentation.proof = [assertion, tamper(authentication)];
      return presentation;
    };

    it('verifies with the matching caller challenge', async () => {
      const result = await verify(await signedWithBothProofs(), {
        challenge: 'a'
      });

      expect(result.verified).toBe(true);
      expectSignatureSuccess(result.presentationResults);
    });

    it('fails with a different caller challenge', async () => {
      const result = await verify(await signedWithBothProofs(), {
        challenge: 'b'
      });

      expect(result.verified).toBe(false);
      expectPurposeMismatch(result.presentationResults, 'Challenge Mismatch');
    });

    it('verifies on the signatures when no challenge is supplied', async () => {
      const result = await verify(await signedWithBothProofs());

      expect(result.verified).toBe(true);
      expectSignatureSuccess(result.presentationResults);
    });

    it('verifies two authentication proofs with different challenges when none is supplied', async () => {
      const first = await signedForAuthentication('a');
      const both = await signedForAuthentication('b', undefined, first);
      expect((both.proof as unknown[]).length).toBe(2);

      const result = await verify(both);

      expect(result.verified).toBe(true);
      expectSignatureSuccess(result.presentationResults);
    });

    it('fails a tampered authentication proof when no challenge is supplied', async () => {
      const result = await verify(await withTamperedAuthentication());

      expect(result.verified).toBe(false);
      expectInvalidSignature(result.presentationResults);
    });

    it('fails a tampered authentication proof with a caller challenge', async () => {
      const result = await verify(await withTamperedAuthentication(), {
        challenge: 'a'
      });

      expect(result.verified).toBe(false);
      expectInvalidSignature(result.presentationResults);
    });
  });
});
