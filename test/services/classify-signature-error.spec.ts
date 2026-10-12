import { describe, it, expect } from 'vitest';
import { classifySignatureError } from '../../src/services/data-integrity-crypto.js';
import { ProblemTypes } from '../../src/problem-types.js';

const NOW = new Date('2026-01-01T00:00:00Z');

describe('classifySignatureError', () => {
  it('surfaces sub-error messages from an aggregate jsonld-signatures error', () => {
    const aggregate = Object.assign(new Error('Verification error(s).'), {
      errors: [
        new Error('Invalid signature.'),
        { error: new Error('Public key not found.') }
      ]
    });

    const problems = classifySignatureError(aggregate, undefined, NOW);

    expect(problems).toHaveLength(1);
    expect(problems[0].type).toBe(ProblemTypes.INVALID_SIGNATURE);
    expect(problems[0].detail).toBe(
      'Invalid signature.; Public key not found.'
    );
    expect(problems[0].detail).not.toContain('Verification error(s)');
  });

  it('deduplicates repeated sub-error messages', () => {
    const aggregate = Object.assign(new Error('Verification error(s).'), {
      errors: [new Error('Invalid signature.'), new Error('Invalid signature.')]
    });

    const problems = classifySignatureError(aggregate, undefined, NOW);

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
    const aggregate = Object.assign(new Error('Verification error(s).'), {
      errors: [
        new Error(
          'The current date time (2026-01-01T00:00:00.000Z) is before "validFrom" (2099-01-01T00:00:00Z).'
        )
      ]
    });

    const problems = classifySignatureError(
      aggregate,
      { validFrom: '2099-01-01T00:00:00Z' },
      NOW
    );

    expect(problems[0].type).toBe(ProblemTypes.CREDENTIAL_NOT_YET_VALID);
    expect(problems[0].detail).toBe(
      'Validity starts at 2099-01-01T00:00:00Z (validFrom). Verified at 2026-01-01T00:00:00.000Z.'
    );
  });
});
