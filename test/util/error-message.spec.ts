import { describe, it, expect } from 'vitest';
import { errorMessage } from '../../src/util/error-message.js';

describe('errorMessage', () => {
  it('uses the message of an Error', () => {
    expect(errorMessage(new Error('boom'), 'fallback')).toBe('boom');
  });

  it('uses a thrown string as is', () => {
    expect(errorMessage('boom', 'fallback')).toBe('boom');
  });

  it('uses the string message of an error-like object that is not an Error', () => {
    const crossRealm = Object.create(null) as { message: string };
    crossRealm.message = 'boom';
    expect(errorMessage(crossRealm, 'fallback')).toBe('boom');
  });

  it('falls back for other values', () => {
    expect(errorMessage(undefined, 'fallback')).toBe('fallback');
    expect(errorMessage(42, 'fallback')).toBe('fallback');
    expect(errorMessage({ message: 7 }, 'fallback')).toBe('fallback');
  });
});
