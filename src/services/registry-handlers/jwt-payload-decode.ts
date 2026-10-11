/**
 * Portable base64url and JWT payload decoding.
 *
 * These helpers decode only; they establish nothing about who signed a
 * token. Callers that need trust verify the signature with `verifyJws`
 * from `./jws-verify.js`. Decoding uses `@scure/base` and `TextDecoder`,
 * so it works in browsers and React Native as well as Node.
 */

import { base64urlnopad } from '@scure/base';

/**
 * Decode one unpadded base64url segment as UTF-8 JSON. Throws on invalid
 * base64url, invalid UTF-8 or invalid JSON.
 */
export function decodeBase64UrlJson<T = unknown>(segment: string): T {
  const json = new TextDecoder('utf-8', { fatal: true }).decode(
    base64urlnopad.decode(segment)
  );
  return JSON.parse(json) as T;
}

/**
 * Decode a JWT's payload segment without verifying its signature.
 * Throws if the token has no payload segment or the payload is not JSON.
 */
export const jwtDecodePayload = <T = unknown>(jwt: string): T => {
  const parts = jwt.split('.');
  if (parts.length < 2) {
    throw new Error('Invalid JWT: expected header and payload segments');
  }
  return decodeBase64UrlJson<T>(parts[1]);
};
