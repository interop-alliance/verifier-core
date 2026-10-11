import { afterEach, describe, it, expect, vi } from 'vitest';
import {
  decodeBase64UrlJson,
  jwtDecodePayload
} from '../../../src/services/registry-handlers/jwt-payload-decode.js';
import { encodeJson } from '../../factories/oidf/sign-entity-statement.js';

describe('jwtDecodePayload', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('decodes a minimal JWT payload', () => {
    const payload = { sub: 'user', n: 1 };
    const jwt = `eyJhbGciOiJub25lIn0.${encodeJson(payload)}.sig`;
    expect(jwtDecodePayload(jwt)).toEqual(payload);
  });

  it('decodes without Buffer, as in browsers and React Native', () => {
    const payload = { sub: 'did:web:example.org', name: 'Ünïcode' };
    const segment = encodeJson(payload);
    vi.stubGlobal('Buffer', undefined);
    expect(jwtDecodePayload(`h.${segment}.s`)).toEqual(payload);
  });

  it('throws on malformed JWT', () => {
    expect(() => jwtDecodePayload('not-a-jwt')).toThrow(/Invalid JWT/);
  });
});

describe('decodeBase64UrlJson', () => {
  it('decodes unpadded base64url containing - and _', () => {
    // Bytes whose base64 contains + and / (and so - and _ in base64url).
    const payload = { bytes: '\u{FBFF}\u{FFBF}' };
    const segment = encodeJson(payload);
    expect(segment).not.toMatch(/=/);
    expect(decodeBase64UrlJson(segment)).toEqual(payload);
  });

  it('throws on a padded segment', () => {
    expect(() => decodeBase64UrlJson(`${encodeJson({ a: 1 })}==`)).toThrow();
  });

  it('throws on input that is not base64url', () => {
    expect(() => decodeBase64UrlJson('a')).toThrow();
  });

  it('throws on a segment that is not JSON', () => {
    expect(() => decodeBase64UrlJson('bm90LWpzb24')).toThrow();
  });
});
