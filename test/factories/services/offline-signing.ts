/**
 * Offline real-crypto harness for signature tests.
 *
 * `did:key` resolves from the identifier itself and every `@context` used
 * here is bundled, so Ed25519 signatures are genuinely checked without a
 * network call. {@link offlineHttpGetService} throws if anything reaches for
 * one.
 */

import { expect } from 'vitest';
import {
  issue,
  createPresentation,
  type VerifiableCredential
} from '@interop/vc';
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key';
import { Ed25519Signature2020 } from '@interop/ed25519-signature';
import type { ISigner } from '@interop/data-integrity-core';
import { defaultDocumentLoaderFor } from '../../../src/default-services.js';
import type { HttpGetService } from '../../../src/services/http-get-service/http-get-service.js';
import type { CheckResult } from '../../../src/types/check.js';

/** Fails loudly rather than silently reaching the network. */
export const offlineHttpGetService: HttpGetService = {
  async get(url: string): Promise<never> {
    throw new Error(`test reached the network for ${url}`);
  }
};

export const documentLoader = defaultDocumentLoaderFor(offlineHttpGetService);

export const ED25519_2020_CONTEXT =
  'https://w3id.org/security/suites/ed25519-2020/v1';

/**
 * A fixed-seed did:key signer. The seed keeps the DID and the signatures
 * stable across runs. The signer's `id` is the key's verification method.
 */
export async function offlineSigner(
  seed: number
): Promise<{ did: string; signer: ISigner }> {
  const key = await Ed25519VerificationKey.generate({
    seed: new Uint8Array(32).fill(seed)
  });
  return { did: `did:key:${key.fingerprint()}`, signer: key.didKeySigner() };
}

/** A minimal VC 2.0 credential issued by `issuerDid`. */
export function credentialTemplate(issuerDid: string): VerifiableCredential {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2', ED25519_2020_CONTEXT],
    id: 'urn:uuid:5d2b7c1e-4a8f-4e3b-9c61-2f0a8d7e1b34',
    type: ['VerifiableCredential'],
    issuer: issuerDid,
    validFrom: '2020-01-01T00:00:00Z',
    name: 'Example Credential',
    credentialSubject: { id: 'did:example:subject' }
  };
}

/**
 * A fixed-seed did:key holder with a credential it issued to itself, built
 * from `template` (default {@link credentialTemplate}) and signed with
 * Ed25519Signature2020.
 */
export async function offlineHolder(
  seed: number,
  template: (issuerDid: string) => VerifiableCredential = credentialTemplate
): Promise<{
  did: string;
  signer: ISigner;
  signedCredential: VerifiableCredential;
}> {
  const { did, signer } = await offlineSigner(seed);
  const signedCredential = await issue({
    credential: template(did),
    suite: new Ed25519Signature2020({ signer }),
    documentLoader
  });
  return { did, signer, signedCredential };
}

/**
 * An unsigned presentation wrapping `verifiableCredential`. The VC 2.0
 * context scopes proof terms such as `challenge` under `DataIntegrityProof`,
 * so the Ed25519Signature2020 suite context is appended for safe-mode
 * canonicalization.
 */
export function unsignedPresentation(
  verifiableCredential: VerifiableCredential,
  holder: string
): Record<string, unknown> {
  const presentation = createPresentation({
    verifiableCredential,
    holder
  }) as Record<string, unknown>;
  presentation['@context'] = [
    ...(presentation['@context'] as string[]),
    ED25519_2020_CONTEXT
  ];
  return presentation;
}

/** Replace the tail of a proof's `proofValue` so its signature no longer verifies. */
export function tamper(
  proof: Record<string, unknown>
): Record<string, unknown> {
  const proofValue = proof.proofValue as string;
  return { ...proof, proofValue: `${proofValue.slice(0, -4)}AAAA` };
}

export function signatureResult(
  results: CheckResult[]
): CheckResult | undefined {
  return results.find(r => r.id === 'cryptographic.proof.signature');
}

/** The presentation's own proof failed with the given problem. */
export function expectProblem(
  results: CheckResult[],
  type: string,
  title: string
): void {
  const outcome = signatureResult(results)?.outcome;
  expect(outcome?.status).toBe('failure');
  if (outcome?.status === 'failure') {
    expect(outcome.problems).toHaveLength(1);
    expect(outcome.problems[0].type).toBe(type);
    expect(outcome.problems[0].title).toBe(title);
  }
}

export function expectSignatureSuccess(results: CheckResult[]): void {
  expect(signatureResult(results)?.outcome.status).toBe('success');
}
