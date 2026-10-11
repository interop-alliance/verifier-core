import { describe, it, expect } from 'vitest';
import { registryCacheKey } from '../../src/util/registry-cache-key.js';
import type { EntityIdentityRegistry } from '../../src/types/registry.js';

describe('registryCacheKey', () => {
  const dccLegacy: EntityIdentityRegistry = {
    name: 'Test Legacy',
    type: 'dcc-legacy',
    url: 'https://example.com/registry.json'
  };

  const oidf: EntityIdentityRegistry = {
    name: 'Test OIDF',
    type: 'oidf',
    trustAnchorEC: 'https://trust.example.com/.well-known/openid-federation'
  };

  const vcRecognition: EntityIdentityRegistry = {
    name: 'Test VC',
    type: 'vc-recognition',
    url: 'https://example.com/vc.json',
    acceptedIssuers: ['did:web:issuer.example.com']
  };

  it('produces same hash for same registries in same order', () => {
    const key1 = registryCacheKey([dccLegacy, oidf]);
    const key2 = registryCacheKey([dccLegacy, oidf]);
    expect(key1).toBe(key2);
  });

  it('produces same hash for same registries in different order', () => {
    const key1 = registryCacheKey([dccLegacy, oidf, vcRecognition]);
    const key2 = registryCacheKey([vcRecognition, dccLegacy, oidf]);
    expect(key1).toBe(key2);
  });

  it('produces different hash for different registries', () => {
    const key1 = registryCacheKey([dccLegacy]);
    const key2 = registryCacheKey([oidf]);
    expect(key1).not.toBe(key2);
  });

  it('produces different hash for same type but different names', () => {
    const reg1: EntityIdentityRegistry = { ...dccLegacy, name: 'Legacy A' };
    const reg2: EntityIdentityRegistry = { ...dccLegacy, name: 'Legacy B' };
    const key1 = registryCacheKey([reg1]);
    const key2 = registryCacheKey([reg2]);
    expect(key1).not.toBe(key2);
  });

  it('produces different hash for same name but different URLs', () => {
    const reg1: EntityIdentityRegistry = { ...dccLegacy, url: 'https://a.com' };
    const reg2: EntityIdentityRegistry = { ...dccLegacy, url: 'https://b.com' };
    const key1 = registryCacheKey([reg1]);
    const key2 = registryCacheKey([reg2]);
    expect(key1).not.toBe(key2);
  });

  it('returns a string', () => {
    const key = registryCacheKey([dccLegacy]);
    expect(typeof key).toBe('string');
    expect(key.length).toBeGreaterThan(0);
  });

  it('uses the registry ids themselves, not a 32-bit hash', () => {
    const key = registryCacheKey([dccLegacy, oidf, vcRecognition]);
    expect(key).toContain(dccLegacy.url);
    expect(key).toContain(oidf.trustAnchorEC);
    expect(key).toContain(vcRecognition.url);
  });

  it('is the JSON encoding of the sorted [type, name, url] triples', () => {
    expect(registryCacheKey([oidf, dccLegacy])).toBe(
      JSON.stringify([
        JSON.stringify(['dcc-legacy', dccLegacy.name, dccLegacy.url]),
        JSON.stringify(['oidf', oidf.name, oidf.trustAnchorEC])
      ])
    );
  });

  it('keeps lists apart even when a name contains separator characters', () => {
    // With plain `type:name:url` ids joined by `|`, these two lists would
    // produce the same string.
    const a: EntityIdentityRegistry = {
      ...dccLegacy,
      name: 'A',
      url: 'https://a.example|dcc-legacy:B:https://b.example'
    };
    const b1: EntityIdentityRegistry = {
      ...dccLegacy,
      name: 'A',
      url: 'https://a.example'
    };
    const b2: EntityIdentityRegistry = {
      ...dccLegacy,
      name: 'B',
      url: 'https://b.example'
    };
    expect(registryCacheKey([a])).not.toBe(registryCacheKey([b1, b2]));
  });

  it('keys vc-recognition registries by acceptedIssuers too', () => {
    const a: EntityIdentityRegistry = {
      ...vcRecognition,
      acceptedIssuers: ['did:web:a.example']
    };
    const b: EntityIdentityRegistry = {
      ...vcRecognition,
      acceptedIssuers: ['did:web:b.example']
    };
    expect(registryCacheKey([a])).not.toBe(registryCacheKey([b]));
  });

  it('ignores acceptedIssuers order', () => {
    const a: EntityIdentityRegistry = {
      ...vcRecognition,
      acceptedIssuers: ['did:web:a.example', 'did:web:b.example']
    };
    const b: EntityIdentityRegistry = {
      ...vcRecognition,
      acceptedIssuers: ['did:web:b.example', 'did:web:a.example']
    };
    expect(registryCacheKey([a])).toBe(registryCacheKey([b]));
  });

  it('handles empty array', () => {
    const key1 = registryCacheKey([]);
    const key2 = registryCacheKey([]);
    expect(key1).toBe(key2);
    expect(typeof key1).toBe('string');
  });
});
