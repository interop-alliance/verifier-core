import { z } from 'zod';
import { isPlainObject, stringValues } from '../util/json-shape.js';

/**
 * The gate failure for an enveloped (VC-JOSE-COSE) input, or `undefined`
 * when `input` is not an object whose `type` includes `envelopedType`.
 * This verifier handles embedded proofs only, so an
 * `EnvelopedVerifiableCredential` or `EnvelopedVerifiablePresentation`
 * is rejected before any suite runs, with a message that names the
 * reason instead of a structural one.
 */
export function rejectEnveloped(
  input: unknown,
  envelopedType: string,
  message: string
): z.SafeParseError<unknown> | undefined {
  if (
    !isPlainObject(input) ||
    !stringValues(input.type).includes(envelopedType)
  ) {
    return undefined;
  }
  return {
    success: false,
    error: new z.ZodError([{ code: 'custom', path: ['type'], message }])
  };
}
