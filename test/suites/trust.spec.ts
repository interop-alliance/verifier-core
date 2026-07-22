import { describe, it, expect } from 'vitest';
import { runSuites } from '../../src/run-suites.js';
import { createIssuerDetailsSuite } from '../../src/suites/trust/index.js';
import { buildTestContext } from '../factories/services/build-test-context.js';
import { CredentialFactory } from '../factories/data/credential-factory.js';
import { VerificationSubject } from '../../src/types/subject.js';

/** Stub `lookupDid` returning a fixed set of matching issuers. */
const StubLookupDid =
  (matchingIssuers: Array<{ id: string; name?: string }>) =>
  async (
    _did: string
  ): Promise<{ matchingIssuers: typeof matchingIssuers }> => ({
    matchingIssuers
  });

describe('Trust (Issuer Details) Suite', () => {
  const baseContext = buildTestContext();

  const createSubject = (credential: unknown): VerificationSubject => ({
    verifiableCredential: credential
  });

  it('succeeds with the matching issuers on the payload when found', async () => {
    const suite = createIssuerDetailsSuite({
      lookupDid: StubLookupDid([
        { id: 'did:key:zIssuer', name: 'Acme Registry' }
      ])
    });
    const subject = createSubject(
      CredentialFactory({ version: 'v2', credential: {} })
    );
    const results = await runSuites([suite], subject, baseContext);

    expect(results).toHaveLength(1);
    expect(results[0].check).toBe('trust.issuer-details');
    expect(results[0].outcome.status).toBe('success');
    if (results[0].outcome.status === 'success') {
      expect(results[0].outcome.message).toContain('found in 1 registry');
      expect(results[0].outcome.payload).toEqual({
        matchingIssuers: [{ id: 'did:key:zIssuer', name: 'Acme Registry' }]
      });
    }
  });

  it('reports plural registries when more than one matches', async () => {
    const suite = createIssuerDetailsSuite({
      lookupDid: StubLookupDid([{ id: 'did:key:zA' }, { id: 'did:key:zB' }])
    });
    const results = await runSuites(
      [suite],
      createSubject(CredentialFactory({ version: 'v2', credential: {} })),
      baseContext
    );

    expect(results[0].outcome.status).toBe('success');
    if (results[0].outcome.status === 'success') {
      expect(results[0].outcome.message).toContain('found in 2 registries');
    }
  });

  it('succeeds with a not-found message when no issuers match', async () => {
    const suite = createIssuerDetailsSuite({ lookupDid: StubLookupDid([]) });
    const results = await runSuites(
      [suite],
      createSubject(CredentialFactory({ version: 'v2', credential: {} })),
      baseContext
    );

    expect(results[0].outcome.status).toBe('success');
    if (results[0].outcome.status === 'success') {
      expect(results[0].outcome.message).toContain('not found in any');
      expect(results[0].outcome.payload).toEqual({ matchingIssuers: [] });
    }
  });

  it('handles the issuer expressed as a plain string', async () => {
    const suite = createIssuerDetailsSuite({
      lookupDid: StubLookupDid([{ id: 'did:key:zIssuer' }])
    });
    const cred = CredentialFactory({
      version: 'v2',
      credential: {
        issuer: 'did:key:z6MknNQD1WHLGGraFi6zcbGevuAgkVfdyCdtZnQTGWVVvR5Q'
      }
    });
    const results = await runSuites([suite], createSubject(cred), baseContext);

    expect(results[0].check).toBe('trust.issuer-details');
    expect(results[0].outcome.status).toBe('success');
  });

  it('skips when the credential has no issuer DID', async () => {
    const suite = createIssuerDetailsSuite({
      lookupDid: StubLookupDid([{ id: 'did:key:zIssuer' }])
    });
    const cred = CredentialFactory({ version: 'v2', credential: {} });
    delete (cred as { issuer?: unknown }).issuer;

    const results = await runSuites([suite], createSubject(cred), baseContext);

    expect(results[0].outcome.status).toBe('skipped');
    if (results[0].outcome.status === 'skipped') {
      expect(results[0].outcome.reason).toContain('no issuer DID');
    }
  });

  it('is skipped via appliesTo filter when no credential provided', async () => {
    const suite = createIssuerDetailsSuite({
      lookupDid: StubLookupDid([{ id: 'did:key:zIssuer' }])
    });
    const results = await runSuites([suite], {}, baseContext);

    expect(results).toHaveLength(0);
  });
});
