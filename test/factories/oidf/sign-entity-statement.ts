import * as EcdsaMultikey from '@interop/ecdsa-multikey';
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key';
import { base64urlnopad } from '@scure/base';

type Signer = {
  sign: (opts: { data: Uint8Array }) => Promise<Uint8Array>;
};

/** A freshly generated test key: a signer and its public JWK. */
export type TestSigningKey = {
  alg: 'ES256' | 'EdDSA';
  kid: string;
  signer: Signer;
  /** Public JWK, `kid` included. */
  jwk: Record<string, unknown>;
};

/** Generate an ES256 (P-256) or EdDSA (Ed25519) key with a public JWK. */
export async function generateSigningKey(
  alg: 'ES256' | 'EdDSA',
  kid = `${alg.toLowerCase()}-key`
): Promise<TestSigningKey> {
  if (alg === 'ES256') {
    const keyPair = await EcdsaMultikey.generate({ curve: 'P-256' });
    const jwk = await EcdsaMultikey.toJwk({ keyPair });
    return { alg, kid, signer: keyPair.signer(), jwk: { ...jwk, kid } };
  }
  const keyPair = await Ed25519VerificationKey.generate();
  const { publicKeyJwk } = await keyPair.toJsonWebKey();
  return {
    alg,
    kid,
    signer: keyPair.didKeySigner(),
    jwk: { ...publicKeyJwk, kid }
  };
}

/** A JWK Set holding the given keys' public JWKs. */
export function jwkSet(...keys: TestSigningKey[]): { keys: unknown[] } {
  return { keys: keys.map(key => key.jwk) };
}

/** Unpadded base64url of bytes or of a UTF-8 string. */
export const base64url = (input: Uint8Array | string): string =>
  base64urlnopad.encode(
    typeof input === 'string' ? new TextEncoder().encode(input) : input
  );

/** Unpadded base64url of a JSON value. */
export const encodeJson = (value: unknown): string =>
  base64url(JSON.stringify(value));

/** The header `typ` of an OIDF entity statement. */
export const ENTITY_STATEMENT_TYP = 'entity-statement+jwt';

/**
 * Sign `payload` as a compact JWS with `key`. The header defaults to
 * `{ alg: key.alg, kid: key.kid, typ: ENTITY_STATEMENT_TYP }`; `header`
 * overrides or adds members (`undefined` removes one).
 */
export async function signJws({
  key,
  payload,
  header = {}
}: {
  key: TestSigningKey;
  payload: unknown;
  header?: Record<string, unknown>;
}): Promise<string> {
  const encodedHeader = encodeJson({
    alg: key.alg,
    kid: key.kid,
    typ: ENTITY_STATEMENT_TYP,
    ...header
  });
  const encodedPayload = encodeJson(payload);
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = await key.signer.sign({
    data: new TextEncoder().encode(signingInput)
  });
  return `${signingInput}.${base64url(signature)}`;
}

/** Seconds since the epoch at `nowMs`, offset by `deltaSeconds`. */
export const epochSeconds = (deltaSeconds = 0, nowMs = Date.now()): number =>
  Math.floor(nowMs / 1000) + deltaSeconds;

export const ONE_DAY_SECONDS = 24 * 60 * 60;

/** A trust anchor's self-describing entity configuration payload. */
export function entityConfigurationPayload({
  entityId,
  jwks,
  fetchEndpoint,
  exp
}: {
  entityId: string;
  jwks: unknown;
  fetchEndpoint: string;
  exp: number;
}): Record<string, unknown> {
  return {
    iss: entityId,
    sub: entityId,
    iat: exp - ONE_DAY_SECONDS,
    exp,
    jwks,
    metadata: {
      federation_entity: {
        name: 'Trust Anchor',
        federation_fetch_endpoint: fetchEndpoint
      }
    }
  };
}

/** A trust anchor's subordinate statement payload about `did`. */
export function subordinateStatementPayload({
  entityId,
  did,
  exp
}: {
  entityId: string;
  did: string;
  exp: number;
}): Record<string, unknown> {
  return {
    iss: entityId,
    sub: did,
    iat: exp - ONE_DAY_SECONDS,
    exp,
    metadata: { federation_entity: { organization_name: 'Issuer' } }
  };
}
