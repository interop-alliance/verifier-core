import { describe, it, expect } from 'vitest';
import {
  DEFAULT_TTL_MS,
  parseCacheControlMaxAge,
  resolveTtl,
  ttlFromValidUntil
} from '../../../src/services/registry-handlers/cache-ttl.js';

describe('parseCacheControlMaxAge', () => {
  it('returns undefined when header missing', () => {
    expect(parseCacheControlMaxAge(new Headers())).toBeUndefined();
  });

  it('parses max-age in seconds to ms', () => {
    const headers = new Headers({ 'cache-control': 'public, max-age=3600' });
    expect(parseCacheControlMaxAge(headers)).toBe(3600 * 1000);
  });

  it('is case insensitive', () => {
    const headers = new Headers({ 'cache-control': 'Max-Age=60' });
    expect(parseCacheControlMaxAge(headers)).toBe(60 * 1000);
  });

  it('returns undefined for invalid max-age', () => {
    const headers = new Headers({ 'cache-control': 'max-age=abc' });
    expect(parseCacheControlMaxAge(headers)).toBeUndefined();
  });
});

describe('ttlFromValidUntil', () => {
  const nowMs = Date.parse('2030-01-01T00:00:00Z');

  it('returns ms from nowMs until a future instant', () => {
    expect(ttlFromValidUntil('2030-01-01T00:00:05Z', nowMs)).toBe(5000);
  });

  it('returns undefined for a past instant', () => {
    expect(ttlFromValidUntil('2029-12-31T23:59:59Z', nowMs)).toBeUndefined();
  });

  it('returns undefined for an invalid or missing value', () => {
    expect(ttlFromValidUntil('not-a-date', nowMs)).toBeUndefined();
    expect(ttlFromValidUntil(undefined, nowMs)).toBeUndefined();
    expect(ttlFromValidUntil(42, nowMs)).toBeUndefined();
  });
});

describe('resolveTtl', () => {
  it('uses first positive finite value', () => {
    expect(resolveTtl(undefined, 100, 200)).toBe(100);
  });

  it('skips non-positive values', () => {
    expect(resolveTtl(0, -1, 500)).toBe(500);
  });

  it('falls back to DEFAULT_TTL_MS', () => {
    expect(resolveTtl(undefined, undefined)).toBe(DEFAULT_TTL_MS);
  });
});
