import { fromJwk } from '@interop/ecdsa-multikey';
import type { JWK } from '@interop/ecdsa-multikey';
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key';
import { base64urlnopad } from '@scure/base';
import { decodeBase64UrlJson } from './jwt-payload-decode.js';

/** Outcome of {@link verifyJws}: the verified payload, or why it failed. */
export type JwsResult =
  | { valid: true; payload: Record<string, unknown> }
  | { valid: false; reason: string };

type SupportedAlg = 'ES256' | 'EdDSA';

type Jwk = Record<string, unknown>;

/**
 * Verify a compact JWS against a JWK Set, using the key packages the
 * verifier already ships (ES256 via `@interop/ecdsa-multikey`, EdDSA via
 * `@interop/ed25519-verification-key`), so it runs in Node, browsers and
 * React Native. The ES256 path verifies through WebCrypto, so React Native
 * needs a WebCrypto polyfill for it.
 *
 * Only keys compatible with `alg` are considered. Among those, the keys
 * whose `kid` matches the header are tried first. If none matches, every
 * compatible key is tried instead, because some live registries (Credential
 * Engine) sign with a header `kid` that names none of their published keys.
 *
 * A header with a `crit` member is rejected: this verifier understands no
 * critical extension, and RFC 7515 s4.1.11 requires rejecting a JWS whose
 * critical extensions are not understood. When `typ` is given, the header
 * must carry exactly that `typ`.
 *
 * Never throws: every failure is `{ valid: false }`.
 *
 * @param jws - Compact serialization, `header.payload.signature`.
 * @param jwks - A JWK Set (`{ keys: [...] }`); anything else fails.
 * @param options.typ - Required header `typ`; when omitted, `typ` is not checked.
 */
export async function verifyJws(
  jws: string,
  jwks: unknown,
  { typ }: { typ?: string } = {}
): Promise<JwsResult> {
  const parts = jws.split('.');
  if (parts.length !== 3 || parts.some(part => part.length === 0)) {
    return { valid: false, reason: 'malformed JWS' };
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  let header: unknown;
  let payload: unknown;
  let signature: Uint8Array;
  try {
    header = decodeBase64UrlJson(encodedHeader);
    payload = decodeBase64UrlJson(encodedPayload);
    signature = base64urlnopad.decode(encodedSignature);
  } catch {
    return { valid: false, reason: 'malformed JWS' };
  }
  if (!isObject(header) || !isObject(payload)) {
    return { valid: false, reason: 'malformed JWS' };
  }

  if (header.crit !== undefined) {
    return { valid: false, reason: 'unsupported crit' };
  }
  if (typ !== undefined && header.typ !== typ) {
    return { valid: false, reason: 'unexpected typ' };
  }

  const alg = header.alg;
  if (alg !== 'ES256' && alg !== 'EdDSA') {
    return { valid: false, reason: 'unsupported alg' };
  }

  const keys = jwkSetKeys(jwks);
  if (!keys) {
    return { valid: false, reason: 'no JWK Set' };
  }

  const compatible = keys.filter(key => isCompatible(key, alg));
  const byKid = compatible.filter(key => key.kid === header.kid);
  const candidates = byKid.length > 0 ? byKid : compatible;

  const data = new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`);
  for (const jwk of candidates) {
    try {
      if (await verifyWithJwk(alg, jwk, data, signature)) {
        return { valid: true, payload };
      }
    } catch {
      // A key the library cannot import is skipped, not fatal: another key
      // in the set may still verify.
    }
  }
  return { valid: false, reason: 'signature did not verify' };
}

async function verifyWithJwk(
  alg: SupportedAlg,
  jwk: Jwk,
  data: Uint8Array,
  signature: Uint8Array
): Promise<boolean> {
  // Only the public members are passed, so a JWK Set that carelessly
  // includes a private `d` never has it imported.
  if (alg === 'ES256') {
    // `key_ops` tells `fromJwk` this is a signing key; without it the key is
    // imported for key agreement and cannot verify.
    const keyPair = await fromJwk({
      jwk: {
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y,
        key_ops: ['verify']
      } as JWK
    });
    return keyPair.verifier().verify({ data, signature });
  }
  const keyPair = await Ed25519VerificationKey.fromJsonWebKey({
    type: 'JsonWebKey',
    publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: String(jwk.x) }
  });
  return keyPair.verifier().verify({ data, signature });
}

function isCompatible(jwk: Jwk, alg: SupportedAlg): boolean {
  if (alg === 'ES256') {
    return jwk.kty === 'EC' && jwk.crv === 'P-256';
  }
  return jwk.kty === 'OKP' && jwk.crv === 'Ed25519';
}

function jwkSetKeys(jwks: unknown): Jwk[] | undefined {
  if (!isObject(jwks) || !Array.isArray(jwks.keys)) {
    return undefined;
  }
  return jwks.keys.filter(isObject);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
