import { beforeAll, describe, expect, it } from 'vitest';
import { verifyJws } from '../../../src/services/registry-handlers/jws-verify.js';
import {
  encodeJson,
  generateSigningKey,
  jwkSet,
  signJws,
  type TestSigningKey
} from '../../factories/oidf/sign-entity-statement.js';

const payload = { iss: 'https://ta.example', sub: 'did:key:abc', n: 1 };

/** Replace one segment of a compact JWS. */
function withSegment(jws: string, index: number, segment: string): string {
  const parts = jws.split('.');
  parts[index] = segment;
  return parts.join('.');
}

describe('verifyJws', () => {
  let es256: TestSigningKey;
  let eddsa: TestSigningKey;
  let otherEs256: TestSigningKey;

  beforeAll(async () => {
    es256 = await generateSigningKey('ES256');
    eddsa = await generateSigningKey('EdDSA');
    otherEs256 = await generateSigningKey('ES256', 'other-key');
  });

  it('verifies an ES256 JWS', async () => {
    const jws = await signJws({ key: es256, payload });
    expect(await verifyJws(jws, jwkSet(es256))).toEqual({
      valid: true,
      payload
    });
  });

  it('verifies an EdDSA JWS', async () => {
    const jws = await signJws({ key: eddsa, payload });
    expect(await verifyJws(jws, jwkSet(eddsa))).toEqual({
      valid: true,
      payload
    });
  });

  it('rejects a tampered payload', async () => {
    const jws = await signJws({ key: es256, payload });
    const tampered = withSegment(jws, 1, encodeJson({ ...payload, n: 2 }));
    expect(await verifyJws(tampered, jwkSet(es256))).toEqual({
      valid: false,
      reason: 'signature did not verify'
    });
  });

  it('rejects a tampered signature', async () => {
    const jws = await signJws({ key: eddsa, payload });
    const other = await signJws({ key: eddsa, payload: { other: true } });
    const tampered = withSegment(jws, 2, other.split('.')[2]);
    expect(await verifyJws(tampered, jwkSet(eddsa))).toEqual({
      valid: false,
      reason: 'signature did not verify'
    });
  });

  it('rejects a JWS signed by a key outside the set', async () => {
    const jws = await signJws({ key: otherEs256, payload });
    expect(await verifyJws(jws, jwkSet(es256))).toEqual({
      valid: false,
      reason: 'signature did not verify'
    });
  });

  it('tries every key when the header kid matches none', async () => {
    const jws = await signJws({
      key: eddsa,
      payload,
      header: { kid: 'sandbox-ta-1' }
    });
    expect(await verifyJws(jws, jwkSet(eddsa))).toEqual({
      valid: true,
      payload
    });
  });

  it('finds the matching key among several', async () => {
    const jws = await signJws({ key: es256, payload });
    const result = await verifyJws(jws, jwkSet(otherEs256, eddsa, es256));
    expect(result.valid).toBe(true);
  });

  it('rejects RS256 as an unsupported alg', async () => {
    const jws = await signJws({
      key: es256,
      payload,
      header: { alg: 'RS256' }
    });
    expect(await verifyJws(jws, jwkSet(es256))).toEqual({
      valid: false,
      reason: 'unsupported alg'
    });
  });

  it('rejects alg none', async () => {
    const unsigned = `${encodeJson({ alg: 'none' })}.${encodeJson(payload)}.c2ln`;
    expect(await verifyJws(unsigned, jwkSet(es256))).toEqual({
      valid: false,
      reason: 'unsupported alg'
    });
  });

  it('rejects a JWS with two segments', async () => {
    const jws = await signJws({ key: es256, payload });
    const [header, body] = jws.split('.');
    expect(await verifyJws(`${header}.${body}`, jwkSet(es256))).toEqual({
      valid: false,
      reason: 'malformed JWS'
    });
  });

  it('rejects an empty signature segment', async () => {
    const jws = await signJws({ key: es256, payload });
    expect(await verifyJws(withSegment(jws, 2, ''), jwkSet(es256))).toEqual({
      valid: false,
      reason: 'malformed JWS'
    });
  });

  it('rejects a header that is not JSON', async () => {
    const jws = await signJws({ key: es256, payload });
    expect(
      await verifyJws(withSegment(jws, 0, 'bm90LWpzb24'), jwkSet(es256))
    ).toEqual({ valid: false, reason: 'malformed JWS' });
  });

  it('rejects a padded signature segment as malformed', async () => {
    const jws = await signJws({ key: es256, payload });
    const [, , signature] = jws.split('.');
    expect(
      await verifyJws(withSegment(jws, 2, `${signature}=`), jwkSet(es256))
    ).toEqual({ valid: false, reason: 'malformed JWS' });
  });

  it.each([
    ['missing', undefined],
    ['not an object', 'keys'],
    ['keys not an array', { keys: {} }]
  ])('rejects a JWK Set that is %s', async (_label, jwks) => {
    const jws = await signJws({ key: es256, payload });
    expect(await verifyJws(jws, jwks)).toEqual({
      valid: false,
      reason: 'no JWK Set'
    });
  });

  it('rejects any crit header member', async () => {
    const jws = await signJws({
      key: es256,
      payload,
      header: { crit: ['b64'], b64: false }
    });
    expect(await verifyJws(jws, jwkSet(es256))).toEqual({
      valid: false,
      reason: 'unsupported crit'
    });
  });

  it('ignores typ unless one is required', async () => {
    const jws = await signJws({ key: es256, payload, header: { typ: 'JWT' } });
    expect((await verifyJws(jws, jwkSet(es256))).valid).toBe(true);
  });

  it('requires the given typ when one is required', async () => {
    const jwks = jwkSet(es256);
    const typed = await signJws({
      key: es256,
      payload,
      header: { typ: 'x+jwt' }
    });
    expect((await verifyJws(typed, jwks, { typ: 'x+jwt' })).valid).toBe(true);

    const other = await signJws({
      key: es256,
      payload,
      header: { typ: 'JWT' }
    });
    expect(await verifyJws(other, jwks, { typ: 'x+jwt' })).toEqual({
      valid: false,
      reason: 'unexpected typ'
    });

    const untyped = await signJws({
      key: es256,
      payload,
      header: { typ: undefined }
    });
    expect(await verifyJws(untyped, jwks, { typ: 'x+jwt' })).toEqual({
      valid: false,
      reason: 'unexpected typ'
    });
  });

  it('falls back to compatible keys when the kid names an incompatible key', async () => {
    // The header kid names the OKP key, which cannot verify ES256; the EC key
    // under another kid is still tried.
    const jws = await signJws({
      key: es256,
      payload,
      header: { kid: eddsa.kid }
    });
    expect(await verifyJws(jws, jwkSet(eddsa, otherEs256, es256))).toEqual({
      valid: true,
      payload
    });
  });

  it('skips a key whose kty does not fit the alg', async () => {
    const jws = await signJws({ key: es256, payload });
    // Same kid, but an OKP key cannot verify ES256, so it is never tried.
    const mislabelled = { ...eddsa.jwk, kid: es256.kid };
    expect(await verifyJws(jws, { keys: [mislabelled] })).toEqual({
      valid: false,
      reason: 'signature did not verify'
    });
    expect(
      (await verifyJws(jws, { keys: [mislabelled, es256.jwk] })).valid
    ).toBe(true);
  });

  it('skips a key the library cannot import', async () => {
    const jws = await signJws({ key: es256, payload });
    const broken = {
      kty: 'EC',
      crv: 'P-256',
      kid: es256.kid,
      x: 'AA',
      y: 'AA'
    };
    expect((await verifyJws(jws, { keys: [broken, es256.jwk] })).valid).toBe(
      true
    );
  });

  it('skips a broken EdDSA key and verifies with the good one', async () => {
    const jws = await signJws({ key: eddsa, payload });
    const broken = { kty: 'OKP', crv: 'Ed25519', kid: eddsa.kid, x: 'AA' };
    expect((await verifyJws(jws, { keys: [broken, eddsa.jwk] })).valid).toBe(
      true
    );
  });
});
