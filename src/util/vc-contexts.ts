import { stringValues } from './json-shape.js';

export const VC_CONTEXT_V1 = 'https://www.w3.org/2018/credentials/v1';
export const VC_CONTEXT_V2 = 'https://www.w3.org/ns/credentials/v2';

export function isVcContext(value: unknown): boolean {
  return value === VC_CONTEXT_V1 || value === VC_CONTEXT_V2;
}

/** The first `@context` entry: the value itself when it is not an array. */
export function firstContextEntry(context: unknown): unknown {
  return Array.isArray(context) ? context[0] : context;
}

/**
 * Whether `@context` includes either VC context anywhere. Inline
 * context objects (JSON-LD context definitions) are ignored.
 */
export function includesVcContext(context: unknown): boolean {
  return stringValues(context).some(isVcContext);
}
