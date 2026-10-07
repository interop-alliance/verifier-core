/**
 * Regression coverage for the invariant documented at the top of
 * `src/verifier.ts`: the verifier must check the credential as issued, not a
 * Zod-rewritten copy.
 *
 * Runs offline with real Ed25519 cryptography; see
 * `test/factories/services/offline-signing.ts`.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { signPresentation, type VerifiableCredential } from '@interop/vc';
import { Ed25519Signature2020 } from '@interop/ed25519-signature';
import type { ISigner } from '@interop/data-integrity-core';
import { createVerifier } from '../src/verifier.js';
import { parseCredential } from '../src/schemas/credential.js';
import {
  documentLoader,
  ED25519_2020_CONTEXT,
  offlineHolder,
  offlineHttpGetService,
  unsignedPresentation
} from './factories/services/offline-signing.js';

/**
 * The issuer image `caption` is the load-bearing field: it is signed, and it is
 * the key the old schema dropped.
 */
const credentialTemplate = (issuerDid: string): VerifiableCredential => ({
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json',
    ED25519_2020_CONTEXT
  ],
  id: 'urn:uuid:5b0e2f5a-6a1d-4a58-9c2e-2f6d3c9a7b41',
  type: ['VerifiableCredential', 'OpenBadgeCredential'],
  issuer: {
    id: issuerDid,
    type: ['Profile'],
    name: 'Example Corp',
    image: {
      id: 'https://example.test/logo.png',
      type: 'Image',
      caption: 'Example Corp logo'
    }
  },
  validFrom: '2020-01-01T00:00:00Z',
  name: 'Teamwork Badge',
  credentialSubject: {
    type: ['AchievementSubject'],
    achievement: {
      id: 'https://example.test/achievements/teamwork',
      type: ['Achievement'],
      name: 'Teamwork',
      description: 'Works well with others.',
      criteria: {
        type: 'Criteria',
        narrative: 'Nominated by peers and confirmed by management.'
      }
    }
  }
});

describe('signed bytes survive verification', () => {
  let signedCredential: VerifiableCredential;
  let issuerDid: string;
  let signer: ISigner;

  beforeAll(async () => {
    ({
      did: issuerDid,
      signer,
      signedCredential
    } = await offlineHolder(7, credentialTemplate));
  });

  const verifier = () =>
    createVerifier({
      httpGetService: offlineHttpGetService,
      documentLoader
    });

  it('verifies a credential whose issuer image carries a caption', async () => {
    const result = await verifier().verifyCredential({
      credential: signedCredential,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(true);
  });

  it('verifies the same credential inside a presentation', async () => {
    const unsigned = unsignedPresentation(signedCredential, issuerDid);
    const presentation = await signPresentation({
      presentation: unsigned as never,
      suite: new Ed25519Signature2020({ signer }),
      challenge: 'test-challenge',
      documentLoader
    });

    const result = await verifier().verifyPresentation({
      presentation: presentation as never,
      challenge: 'test-challenge',
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(true);
    expect(result.credentialResults[0]?.verified).toBe(true);
  });

  it('returns the credential as issued, so a second pass can re-verify it', async () => {
    // Consumers may re-verify `verifiableCredential` in a later pass. A
    // rewritten copy fails there even though the first pass succeeded.
    const result = await verifier().verifyCredential({
      credential: signedCredential,
      phases: ['cryptographic']
    });

    expect(result.verifiableCredential).toEqual(signedCredential);

    const second = await verifier().verifyCredential({
      credential: result.verifiableCredential,
      phases: ['cryptographic']
    });
    expect(second.verified).toBe(true);
  });

  it('does not rewrite string-valued @context and type into arrays', async () => {
    // `JsonLdField` normalizes scalars to arrays. That is fine for internal
    // reasoning but must not reach what gets canonicalized.
    const scalarShaped = {
      '@context': 'https://www.w3.org/ns/credentials/v2',
      type: 'VerifiableCredential',
      issuer: { id: issuerDid },
      validFrom: '2020-01-01T00:00:00Z',
      credentialSubject: { id: 'did:example:subject' },
      proof: {
        type: 'Ed25519Signature2020',
        created: '2020-01-01T00:00:00Z',
        verificationMethod: signer.id,
        proofPurpose: 'assertionMethod',
        proofValue: 'z00000000000000000000000000000000000000000000000000000'
      }
    };

    const result = await verifier().verifyCredential({
      credential: scalarShaped,
      phases: ['cryptographic']
    });

    const returned = result.verifiableCredential as Record<string, unknown>;
    expect(returned['@context']).toBe('https://www.w3.org/ns/credentials/v2');
    expect(returned.type).toBe('VerifiableCredential');
  });
});

describe('parseCredential preserves signed fields', () => {
  it('keeps caption and unknown keys on issuer.image', () => {
    const credential = credentialTemplate('did:example:issuer');
    (credential.issuer as { image: Record<string, unknown> }).image.foo =
      'extension';
    const parsed = parseCredential(credential);

    expect(parsed.success).toBe(true);
    const issuer = (parsed as { data: { issuer: Record<string, unknown> } })
      .data.issuer;
    expect(issuer.image).toEqual({
      id: 'https://example.test/logo.png',
      type: 'Image',
      caption: 'Example Corp logo',
      foo: 'extension'
    });
  });

  it('does not rewrite issuer.image.type from a string into an array', () => {
    const credential = credentialTemplate('did:example:issuer');
    const parsed = parseCredential(credential);

    expect(parsed.success).toBe(true);
    const issuer = (parsed as { data: { issuer: Record<string, unknown> } })
      .data.issuer;
    expect((issuer.image as { type: unknown }).type).toBe('Image');
  });

  it('accepts an array-valued issuer.image.type', () => {
    const credential = credentialTemplate('did:example:issuer');
    (credential.issuer as { image: Record<string, unknown> }).image.type = [
      'Image'
    ];

    const parsed = parseCredential(credential);
    expect(parsed.success).toBe(true);
    const issuer = (parsed as { data: { issuer: Record<string, unknown> } })
      .data.issuer;
    expect((issuer.image as { type: unknown }).type).toEqual(['Image']);
  });
});
