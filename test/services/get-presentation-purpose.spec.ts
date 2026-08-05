import { describe, it, expect } from 'vitest';
import jsonLdSignatures from '@interop/jsonld-signatures';
import { getPresentationPurpose } from '../../src/services/data-integrity-crypto.js';

const { purposes } = jsonLdSignatures;

const assertionProof = {
  type: 'DataIntegrityProof',
  proofPurpose: 'assertionMethod',
  verificationMethod: 'did:key:zAssertion#zAssertion'
};

const authenticationProof = {
  type: 'DataIntegrityProof',
  proofPurpose: 'authentication',
  challenge: 'test-challenge',
  domain: 'https://example.com',
  verificationMethod: 'did:key:zAuth#zAuth'
};

describe('getPresentationPurpose', () => {
  it('selects AuthenticationProofPurpose for a single authentication proof', () => {
    const purpose = getPresentationPurpose(
      { proof: authenticationProof },
      'test-challenge'
    );

    expect(purpose).toBeInstanceOf(purposes.AuthenticationProofPurpose);
  });

  it('selects AssertionProofPurpose for a single assertion proof', () => {
    const purpose = getPresentationPurpose(
      { proof: assertionProof },
      'test-challenge'
    );

    expect(purpose).toBeInstanceOf(purposes.AssertionProofPurpose);
    expect(purpose).not.toBeInstanceOf(purposes.AuthenticationProofPurpose);
  });

  it('selects AuthenticationProofPurpose when authentication comes first', () => {
    const purpose = getPresentationPurpose(
      { proof: [authenticationProof, assertionProof] },
      'test-challenge'
    );

    expect(purpose).toBeInstanceOf(purposes.AuthenticationProofPurpose);
  });

  // Regression: deriving the purpose from `proof[0]` alone let a presentation
  // whose first proof is an attacker-minted assertion proof verify under
  // AssertionProofPurpose, which skips (never signature-checks) the
  // authentication proof that binds the response to the challenge/domain.
  it('selects AuthenticationProofPurpose when authentication comes last', () => {
    const purpose = getPresentationPurpose(
      { proof: [assertionProof, authenticationProof] },
      'test-challenge'
    );

    expect(purpose).toBeInstanceOf(purposes.AuthenticationProofPurpose);
  });

  it('recognizes the authenticationMethod purpose anywhere in the proof set', () => {
    const purpose = getPresentationPurpose(
      {
        proof: [
          assertionProof,
          assertionProof,
          { ...authenticationProof, proofPurpose: 'authenticationMethod' }
        ]
      },
      'test-challenge'
    );

    expect(purpose).toBeInstanceOf(purposes.AuthenticationProofPurpose);
  });

  it('selects AssertionProofPurpose when no proof is an authentication proof', () => {
    const purpose = getPresentationPurpose(
      { proof: [assertionProof, assertionProof] },
      'test-challenge'
    );

    expect(purpose).toBeInstanceOf(purposes.AssertionProofPurpose);
    expect(purpose).not.toBeInstanceOf(purposes.AuthenticationProofPurpose);
  });

  it('falls back to AssertionProofPurpose with no proof at all', () => {
    expect(getPresentationPurpose({}, null)).toBeInstanceOf(
      purposes.AssertionProofPurpose
    );
    expect(getPresentationPurpose({ proof: [] }, null)).toBeInstanceOf(
      purposes.AssertionProofPurpose
    );
  });
});
