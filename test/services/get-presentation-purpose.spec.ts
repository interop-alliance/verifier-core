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
  challenge: 'proof-challenge',
  domain: 'https://example.com',
  verificationMethod: 'did:key:zAuth#zAuth'
};

/** Narrow to an AuthenticationProofPurpose so its fields can be read. */
function expectAuthentication(
  purpose: unknown
): InstanceType<typeof purposes.AuthenticationProofPurpose> {
  expect(purpose).toBeInstanceOf(purposes.AuthenticationProofPurpose);
  return purpose as InstanceType<typeof purposes.AuthenticationProofPurpose>;
}

function expectAssertion(purpose: unknown): void {
  expect(purpose).toBeInstanceOf(purposes.AssertionProofPurpose);
  expect(purpose).not.toBeInstanceOf(purposes.AuthenticationProofPurpose);
}

/**
 * A plain `ControllerProofPurpose` with the `authentication` term: checks the
 * signature and the key's `authentication` authorization, but no challenge or
 * domain.
 */
function expectSignatureOnlyAuthentication(purpose: unknown): void {
  expect(purpose).toBeInstanceOf(purposes.ControllerProofPurpose);
  expect(purpose).not.toBeInstanceOf(purposes.AuthenticationProofPurpose);
  expect(purpose).not.toBeInstanceOf(purposes.AssertionProofPurpose);
  expect((purpose as { term: string }).term).toBe('authentication');
  expect(purpose).not.toHaveProperty('challenge');
  expect(purpose).not.toHaveProperty('domain');
}

describe('getPresentationPurpose', () => {
  describe('with a caller challenge', () => {
    it('uses the caller challenge for an authentication proof', () => {
      const purpose = expectAuthentication(
        getPresentationPurpose({ proof: authenticationProof }, 'caller')
      );

      expect(purpose.challenge).toBe('caller');
      expect(purpose.domain).toBeUndefined();
    });

    // A supplied challenge is the caller asking for replay protection, so an
    // assertion proof cannot opt out of it.
    it('selects AuthenticationProofPurpose for an assertion proof', () => {
      const purpose = expectAuthentication(
        getPresentationPurpose({ proof: assertionProof }, 'caller')
      );

      expect(purpose.challenge).toBe('caller');
    });

    it('selects AuthenticationProofPurpose for an assertion-only proof set', () => {
      expectAuthentication(
        getPresentationPurpose(
          { proof: [assertionProof, assertionProof] },
          'caller'
        )
      );
    });

    it('passes the caller domain', () => {
      const purpose = expectAuthentication(
        getPresentationPurpose(
          { proof: authenticationProof },
          'caller',
          'verifier.example'
        )
      );

      expect(purpose.challenge).toBe('caller');
      expect(purpose.domain).toBe('verifier.example');
    });

    it('uses the caller challenge for an [assertion, authentication] proof set', () => {
      const purpose = expectAuthentication(
        getPresentationPurpose(
          { proof: [assertionProof, authenticationProof] },
          'caller'
        )
      );

      expect(purpose.challenge).toBe('caller');
    });
  });

  describe('without a caller challenge', () => {
    it('checks a single authentication proof on its signature only', () => {
      expectSignatureOnlyAuthentication(
        getPresentationPurpose({ proof: authenticationProof }, null)
      );
    });

    it('selects AssertionProofPurpose for a single assertion proof', () => {
      expectAssertion(getPresentationPurpose({ proof: assertionProof }, null));
    });

    it('selects the authentication term when authentication comes first', () => {
      expectSignatureOnlyAuthentication(
        getPresentationPurpose(
          { proof: [authenticationProof, assertionProof] },
          undefined
        )
      );
    });

    // Regression: deriving the purpose from `proof[0]` alone let a presentation
    // whose first proof is an attacker-minted assertion proof verify under
    // AssertionProofPurpose, which skips (never signature-checks) the
    // authentication proof that binds the response to the challenge/domain.
    it('selects the authentication term when authentication comes last', () => {
      expectSignatureOnlyAuthentication(
        getPresentationPurpose(
          { proof: [assertionProof, authenticationProof] },
          null
        )
      );
    });

    it('recognizes the authenticationMethod purpose anywhere in the proof set', () => {
      expectSignatureOnlyAuthentication(
        getPresentationPurpose(
          {
            proof: [
              assertionProof,
              assertionProof,
              { ...authenticationProof, proofPurpose: 'authenticationMethod' }
            ]
          },
          null
        )
      );
    });

    // Without a caller challenge there is nothing to compare against, so
    // proofs carrying different challenges, or none, are not judged on them.
    it('does not pin any proof challenge', () => {
      const { challenge: _omitted, ...noChallenge } = authenticationProof;
      expectSignatureOnlyAuthentication(
        getPresentationPurpose(
          {
            proof: [
              noChallenge,
              { ...authenticationProof, challenge: 'second' },
              { ...authenticationProof, challenge: 'third' }
            ]
          },
          null
        )
      );
    });

    it('ignores the caller domain', () => {
      expectSignatureOnlyAuthentication(
        getPresentationPurpose(
          { proof: authenticationProof },
          null,
          'verifier.example'
        )
      );
    });

    it('selects AssertionProofPurpose when no proof is an authentication proof', () => {
      expectAssertion(
        getPresentationPurpose(
          { proof: [assertionProof, assertionProof] },
          null
        )
      );
    });

    it('falls back to AssertionProofPurpose with no proof at all', () => {
      expectAssertion(getPresentationPurpose({}, null));
      expectAssertion(getPresentationPurpose({ proof: [] }, null));
    });
  });
});
