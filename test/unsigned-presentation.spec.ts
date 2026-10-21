/**
 * `unsignedPresentation` against the real default crypto service.
 *
 * The rule: a presentation must be signed unless the caller passes
 * `unsignedPresentation: true`, and a proof that is present is always verified,
 * whatever the flag says. `@interop/vc` reads its own `unsignedPresentation` as
 * "skip the presentation proof", so forwarding the caller's flag let a tampered
 * holder signature verify.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { signPresentation, type VerifiableCredential } from '@interop/vc';
import { Ed25519Signature2020 } from '@interop/ed25519-signature';
import type { ISigner } from '@interop/data-integrity-core';
import { createVerifier } from '../src/verifier.js';
import { ProblemTypes } from '../src/problem-types.js';
import { SIGNATURE_SKIP_CODES } from '../src/suites/proof/signature-check.js';
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

const CHALLENGE = 'test-challenge';

describe('unsignedPresentation with the default crypto service', () => {
  let signer: ISigner;
  let holderDid: string;
  let signedCredential: VerifiableCredential;

  beforeAll(async () => {
    ({ signer, did: holderDid, signedCredential } = await offlineHolder(3));
  });

  const verify = (presentation: unknown, unsigned?: boolean) =>
    createVerifier({
      httpGetService: offlineHttpGetService,
      documentLoader
    }).verifyPresentation({
      presentation,
      challenge: CHALLENGE,
      unsignedPresentation: unsigned,
      phases: ['cryptographic']
    });

  const unsigned = (verifiableCredential = signedCredential) =>
    unsignedPresentation(verifiableCredential, holderDid);

  const signed = async () =>
    (await signPresentation({
      presentation: unsigned() as never,
      suite: new Ed25519Signature2020({ signer }),
      challenge: CHALLENGE,
      documentLoader
    })) as Record<string, unknown>;

  it('skips the signature of an unsigned presentation when the flag is set', async () => {
    const result = await verify(unsigned(), true);

    expect(result.verified).toBe(true);
    expect(signatureResult(result.presentationResults)?.outcome).toMatchObject({
      status: 'skipped',
      code: SIGNATURE_SKIP_CODES.unsignedPresentation
    });
    expect(result.credentialResults[0]?.verified).toBe(true);
  });

  it('fails an unsigned presentation when the flag is unset', async () => {
    const result = await verify(unsigned());

    expect(result.verified).toBe(false);
    expectProblem(
      result.presentationResults,
      ProblemTypes.PROOF_VERIFICATION_ERROR,
      'Presentation Not Signed'
    );
  });

  it('still verifies a tampered presentation proof when the flag is set', async () => {
    const presentation = await signed();
    presentation.proof = tamper(presentation.proof as Record<string, unknown>);

    const result = await verify(presentation, true);

    expect(result.verified).toBe(false);
    expectProblem(
      result.presentationResults,
      ProblemTypes.INVALID_SIGNATURE,
      'Invalid Signature'
    );
  });

  it('verifies a signed presentation normally when the flag is set', async () => {
    const result = await verify(await signed(), true);

    expect(result.verified).toBe(true);
    expectSignatureSuccess(result.presentationResults);
  });

  it('fails an unsigned presentation wrapping a forged credential', async () => {
    const forged = { ...signedCredential, name: 'Forged Credential' };

    const result = await verify(unsigned(forged), true);

    expect(result.verified).toBe(false);
    expect(result.credentialResults[0]?.verified).toBe(false);
  });
});
