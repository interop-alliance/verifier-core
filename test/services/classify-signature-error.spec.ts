import { describe, it, expect } from 'vitest';
import { classifySignatureError } from '../../src/services/data-integrity-crypto.js';
import { ProblemTypes } from '../../src/problem-types.js';

describe('classifySignatureError', () => {
  it('surfaces sub-error messages from an aggregate jsonld-signatures error', () => {
    const aggregate = Object.assign(new Error('Verification error(s).'), {
      errors: [
        new Error('Invalid signature.'),
        { error: new Error('Public key not found.') }
      ]
    });

    const problems = classifySignatureError(aggregate, undefined);

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

    const problems = classifySignatureError(aggregate, undefined);

    expect(problems[0].detail).toBe('Invalid signature.');
  });

  it('keeps the plain message for a non-aggregate error', () => {
    const problems = classifySignatureError(
      new Error('Something specific went wrong.'),
      undefined
    );

    expect(problems[0].detail).toBe('Something specific went wrong.');
  });

  it('falls back to a generic detail when no message is available', () => {
    const problems = classifySignatureError(undefined, undefined);

    expect(problems[0].detail).toBe('The signature is not valid.');
  });
});
