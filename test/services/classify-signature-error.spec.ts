import { describe, it, expect } from 'vitest';
import { classifySignatureError } from '../../src/services/data-integrity-crypto.js';
import { ProblemTypes } from '../../src/problem-types.js';

const NOW = new Date('2026-01-01T00:00:00Z');

/** The `VerificationError` wrapper every failed verification arrives in. */
function wrapped(...errors: unknown[]): unknown {
  return Object.assign(new Error('Verification error(s).'), { errors });
}

describe('classifySignatureError', () => {
  it('surfaces sub-error messages from an aggregate jsonld-signatures error', () => {
    const problems = classifySignatureError(
      wrapped(new Error('Invalid signature.'), {
        error: new Error('Public key not found.')
      }),
      undefined,
      NOW
    );

    expect(problems).toHaveLength(1);
    expect(problems[0].type).toBe(ProblemTypes.INVALID_SIGNATURE);
    expect(problems[0].detail).toBe(
      'Invalid signature.; Public key not found.'
    );
    expect(problems[0].detail).not.toContain('Verification error(s)');
  });

  it('deduplicates repeated sub-error messages', () => {
    const problems = classifySignatureError(
      wrapped(new Error('Invalid signature.'), new Error('Invalid signature.')),
      undefined,
      NOW
    );

    expect(problems[0].detail).toBe('Invalid signature.');
  });

  it('keeps the plain message for a non-aggregate error', () => {
    const problems = classifySignatureError(
      new Error('Something specific went wrong.'),
      undefined,
      NOW
    );

    expect(problems[0].detail).toBe('Something specific went wrong.');
  });

  it('falls back to a generic detail when no message is available', () => {
    const problems = classifySignatureError(undefined, undefined, NOW);

    expect(problems[0].detail).toBe('The signature is not valid.');
  });

  it('reports a date rejection as CREDENTIAL_EXPIRED and keeps the signature verdict out of it', () => {
    const problems = classifySignatureError(
      new Error('Credential has expired.'),
      { validUntil: '2011-01-01T00:00:00Z' },
      NOW
    );

    expect(problems).toEqual([
      {
        type: ProblemTypes.CREDENTIAL_EXPIRED,
        title: 'Credential Expired',
        detail:
          'Validity ended at 2011-01-01T00:00:00Z (validUntil). Verified at 2026-01-01T00:00:00.000Z.'
      }
    ]);
  });

  it('finds the date rejection among aggregate sub-errors', () => {
    const problems = classifySignatureError(
      wrapped(
        new Error(
          'The current date time (2026-01-01T00:00:00.000Z) is before "validFrom" (2099-01-01T00:00:00Z).'
        )
      ),
      { validFrom: '2099-01-01T00:00:00Z' },
      NOW
    );

    expect(problems[0].type).toBe(ProblemTypes.CREDENTIAL_NOT_YET_VALID);
    expect(problems[0].detail).toBe(
      'Validity starts at 2099-01-01T00:00:00Z (validFrom). Verified at 2026-01-01T00:00:00.000Z.'
    );
  });

  it('skips sub-errors that carry no message instead of throwing', () => {
    const problems = classifySignatureError(
      wrapped(null, 'not an error', 42, {}, new Error('Invalid signature.')),
      undefined,
      NOW
    );

    expect(problems).toHaveLength(1);
    expect(problems[0].type).toBe(ProblemTypes.INVALID_SIGNATURE);
    expect(problems[0].detail).toBe('Invalid signature.');
  });
});

/**
 * Pins the message text `@interop/jsonld-signatures` writes for a
 * verification method that resolved but cannot back the proof. An upgrade
 * that rewords one should fail here rather than silently fall back to
 * `INVALID_SIGNATURE`. The same text is matched by the
 * digitalcredentials/verifier-core fork.
 */
describe('classifySignatureError: verification method faults', () => {
  const NOT_AUTHORIZED =
    'Verification method "did:example:123#key-1" not authorized by controller for proof purpose "assertionMethod".';
  const NOT_FOUND = 'Verification method did:example:123#key-1 not found.';
  const ID_NOT_STRING = 'Verification method ID "undefined" must be a string.';

  const libraryMessages: Array<[string, string]> = [
    ["ControllerProofPurpose's not-authorized", NOT_AUTHORIZED],
    [
      "ControllerProofPurpose's not-authorized, for authentication",
      'Verification method "did:example:123#key-1" not authorized by controller for proof purpose "authentication".'
    ],
    ["ControllerProofPurpose's id-must-be-a-string", ID_NOT_STRING],
    ["LinkedDataSignature's not-found", NOT_FOUND]
  ];

  for (const [source, message] of libraryMessages) {
    it(`classifies ${source} as VERIFICATION_METHOD_ERROR`, () => {
      const problems = classifySignatureError(
        wrapped(new Error(message)),
        undefined,
        NOW
      );

      expect(problems).toEqual([
        {
          type: ProblemTypes.VERIFICATION_METHOD_ERROR,
          title: 'Verification Method Error',
          detail: message
        }
      ]);
    });
  }

  it('keeps the issuer / controller mismatch as ISSUER_PROOF_MISMATCH', () => {
    const problems = classifySignatureError(
      wrapped(
        new Error(
          'Credential issuer must match the verification method controller.'
        )
      ),
      { issuer: 'did:example:issuer' },
      NOW
    );

    expect(problems[0].type).toBe(ProblemTypes.ISSUER_PROOF_MISMATCH);
    expect(problems[0].detail).toContain('did:example:issuer');
  });

  it('keeps every fault of a proof set beside the other failures', () => {
    const problems = classifySignatureError(
      wrapped(
        new Error('Invalid signature.'),
        new Error(NOT_FOUND),
        new Error(NOT_AUTHORIZED)
      ),
      undefined,
      NOW
    );

    expect(problems).toEqual([
      {
        type: ProblemTypes.VERIFICATION_METHOD_ERROR,
        title: 'Verification Method Error',
        detail: NOT_FOUND
      },
      {
        type: ProblemTypes.VERIFICATION_METHOD_ERROR,
        title: 'Verification Method Error',
        detail: NOT_AUTHORIZED
      },
      {
        type: ProblemTypes.INVALID_SIGNATURE,
        title: 'Invalid Signature',
        detail: 'Invalid signature.'
      }
    ]);
  });

  it('does not match a message that merely mentions a verification method', () => {
    const problems = classifySignatureError(
      wrapped(
        new Error('Verification method did:example:123#key-1 has been revoked.')
      ),
      undefined,
      NOW
    );

    expect(problems[0].type).toBe(ProblemTypes.INVALID_SIGNATURE);
  });
});
