/**
 * Predicates for reading untrusted JSON defensively. Nothing here
 * assumes the input has been normalised: a JSON-LD term such as
 * `@context` or `type` may be a string or an array, and any property
 * may hold a value of the wrong shape.
 */

/** A non-null, non-array object. */
export function isPlainObject(
  value: unknown
): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The string values of a JSON-LD term that may be a single string or
 * an array (`@context`, `type`). Anything else contributes nothing.
 */
export function stringValues(value: unknown): string[] {
  if (typeof value === 'string') {
    return [value];
  }
  if (Array.isArray(value)) {
    return value.filter((v): v is string => typeof v === 'string');
  }
  return [];
}

/**
 * A string that `new URL()` accepts. This is the test `@interop/vc`
 * applies to ids, and it accepts DIDs and URNs (`did:...`,
 * `urn:uuid:...`).
 */
export function isUrl(value: unknown): value is string {
  if (typeof value !== 'string') {
    return false;
  }
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}
