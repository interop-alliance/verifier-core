import { isPlainObject } from './json-shape.js';

/**
 * The id of a credential's `issuer`: the string itself, or the object's
 * `id`. An empty string, a non-string id, or any other shape has no id.
 */
function issuerId(issuer: unknown): string | undefined {
  if (typeof issuer === 'string') {
    return issuer.length > 0 ? issuer : undefined;
  }
  if (isPlainObject(issuer)) {
    const { id } = issuer;
    return typeof id === 'string' && id.length > 0 ? id : undefined;
  }
  return undefined;
}

/**
 * The id of `credential.issuer`: the string itself, or the object's `id`.
 * An empty string, a non-string id, or any other shape has no id. This is
 * the single rule for reading an issuer, shared by the registry, trust,
 * status, and crypto code.
 */
export function credentialIssuerId(
  credential: Record<string, unknown>
): string | undefined {
  return issuerId(credential.issuer);
}
