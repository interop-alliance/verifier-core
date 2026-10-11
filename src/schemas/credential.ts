import { z } from 'zod';
import { IssuerSchema } from './issuer.js';
import { withMessage } from './messages.js';
import { rejectEnveloped } from './enveloped.js';

/** One `@context` entry: a URL string or an inline context object. */
const ContextEntrySchema = z.union([z.string(), z.record(z.unknown())]);

/** `@context` as a single entry or an array of entries. */
export const ContextSchema = z.union(
  [ContextEntrySchema, z.array(ContextEntrySchema)],
  withMessage(
    '"@context" is required and must be a string, a context object, or an array of them.'
  )
);

/** `type` as a single string or an array of strings. */
export const TypeSchema = z.union(
  [z.string(), z.array(z.string())],
  withMessage('"type" is required and must be a string or an array of strings.')
);

/**
 * The minimal envelope a credential needs before any suite runs:
 * `@context`, `type`, `issuer` and `credentialSubject`, in shapes the
 * pipeline can read. Every other property passes through untouched.
 *
 * This is deliberately not a VC Data Model validator. Structural
 * requirements are judged by the `core.vc-structure` check, which
 * reports each violation with a JSON Pointer.
 */
export const CredentialSchema = z
  .object(
    {
      '@context': ContextSchema,
      type: TypeSchema,
      issuer: IssuerSchema,
      credentialSubject: z.union(
        [z.record(z.unknown()), z.array(z.record(z.unknown()))],
        withMessage(
          '"credentialSubject" is required and must be an object or an array of objects.'
        )
      )
    },
    withMessage('The credential must be a JSON object.')
  )
  .passthrough();
export type VerifiableCredential = z.infer<typeof CredentialSchema>;

/**
 * Apply the minimal envelope gate that `verifyCredential` runs before
 * any suite. It checks only that `@context`, `type`, `issuer` and
 * `credentialSubject` are present and readable (see
 * {@link CredentialSchema}), and rejects enveloped credentials
 * (`EnvelopedVerifiableCredential`, i.e. VC-JOSE-COSE), which this
 * verifier does not support.
 *
 * This is not a VC Data Model validator: a credential that passes may
 * still fail `core.vc-structure`. The parsed `data` is for inspection
 * only; `verifyCredential` verifies the caller's original object.
 *
 * Returns the zod result (success or error). Callers decide how to
 * handle failures.
 */
export function parseCredential(
  input: unknown
): z.SafeParseReturnType<unknown, VerifiableCredential> {
  return (
    rejectEnveloped(
      input,
      'EnvelopedVerifiableCredential',
      'Enveloped credentials (VC-JOSE-COSE) are not supported by this verifier.'
    ) ?? CredentialSchema.safeParse(input)
  );
}
