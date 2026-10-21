import { describe, it, expect } from 'vitest';
import { vcVersionOf } from '../../src/util/vc-contexts.js';

const OB_CONTEXT = 'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json';
const V1 = 'https://www.w3.org/2018/credentials/v1';
const V2 = 'https://www.w3.org/ns/credentials/v2';

describe('vcVersionOf', () => {
  it('reads the version from the first @context entry', () => {
    expect(vcVersionOf([V2, OB_CONTEXT])).toBe('v2');
    expect(vcVersionOf([V1, OB_CONTEXT])).toBe('v1');
    expect(vcVersionOf(V2)).toBe('v2');
  });

  it('lets the first entry decide when a VC context follows another', () => {
    // As in `core.vc-structure` and `proof.validity-period`: a later VC
    // context does not make this a v2 credential.
    expect(vcVersionOf([V1, OB_CONTEXT, V2])).toBe('v1');
    expect(vcVersionOf([OB_CONTEXT, V2])).toBeNull();
  });

  it('does not accept a URL that merely starts with a VC context', () => {
    expect(vcVersionOf([`${V2}-draft`])).toBeNull();
    expect(vcVersionOf([`${V1}.1`])).toBeNull();
  });

  it('returns null when @context is missing or not a string', () => {
    expect(vcVersionOf(undefined)).toBeNull();
    expect(vcVersionOf([{ '@vocab': 'x' }])).toBeNull();
  });
});
