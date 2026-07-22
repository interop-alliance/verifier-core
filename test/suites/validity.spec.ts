import { describe, it, expect } from 'vitest';
import { runSuites } from '../../src/run-suites.js';
import {
  expirationSuite,
  EXPIRED_PROBLEM_TYPE
} from '../../src/suites/validity/index.js';
import { buildTestContext } from '../factories/services/build-test-context.js';
import { FakeTimeService } from '../../src/services/time-service/fake-time-service.js';
import { CredentialFactory } from '../factories/data/credential-factory.js';
import { VerificationSubject } from '../../src/types/subject.js';
import { VerificationContext } from '../../src/types/context.js';

describe('Validity (Expiration) Suite', () => {
  const baseContext = buildTestContext();

  const createSubject = (credential: unknown): VerificationSubject => ({
    verifiableCredential: credential
  });

  const contextAt = (isoNow: string): VerificationContext => ({
    ...baseContext,
    timeService: FakeTimeService({ baseDateMs: new Date(isoNow).getTime() })
  });

  it('succeeds when the credential is within its validity period', async () => {
    const subject = createSubject(
      CredentialFactory({
        version: 'v2',
        credential: { validUntil: '2023-01-01T00:00:00Z' }
      })
    );
    const results = await runSuites(
      [expirationSuite],
      subject,
      contextAt('2020-01-01T00:00:00Z')
    );

    expect(results).toHaveLength(1);
    expect(results[0].check).toBe('validity.expiration');
    expect(results[0].outcome.status).toBe('success');
  });

  it('fails with EXPIRED problem type when validUntil is in the past', async () => {
    const subject = createSubject(
      CredentialFactory({
        version: 'v2',
        credential: { validUntil: '2020-01-01T00:00:00Z' }
      })
    );
    const results = await runSuites(
      [expirationSuite],
      subject,
      contextAt('2023-01-01T00:00:00Z')
    );

    expect(results).toHaveLength(1);
    expect(results[0].outcome.status).toBe('failure');
    if (results[0].outcome.status === 'failure') {
      expect(results[0].outcome.problems[0].type).toBe(EXPIRED_PROBLEM_TYPE);
      expect(results[0].outcome.problems[0].detail).toContain('2020-01-01');
    }
  });

  it('reads "now" from the injected clock rather than the real wall clock', async () => {
    // validUntil (2023) is in the past relative to the real wall clock but in
    // the future relative to the injected fake clock (2020); a success proves
    // the check consulted the injected clock.
    const subject = createSubject(
      CredentialFactory({
        version: 'v2',
        credential: { validUntil: '2023-01-01T00:00:00Z' }
      })
    );
    const results = await runSuites(
      [expirationSuite],
      subject,
      contextAt('2020-01-01T00:00:00Z')
    );

    expect(results[0].outcome.status).toBe('success');
  });

  it('falls back to VC 1.x expirationDate when validUntil is absent', async () => {
    const cred = CredentialFactory({
      version: 'v1',
      credential: { expirationDate: '2020-01-01T00:00:00Z' }
    });

    const results = await runSuites(
      [expirationSuite],
      createSubject(cred),
      contextAt('2023-01-01T00:00:00Z')
    );

    expect(results[0].outcome.status).toBe('failure');
    if (results[0].outcome.status === 'failure') {
      expect(results[0].outcome.problems[0].type).toBe(EXPIRED_PROBLEM_TYPE);
    }
  });

  it('falls back to Date.now() when no time service is configured', async () => {
    const subject = createSubject(
      CredentialFactory({
        version: 'v2',
        credential: { validUntil: '2999-01-01T00:00:00Z' }
      })
    );
    const results = await runSuites([expirationSuite], subject, baseContext);

    expect(results[0].outcome.status).toBe('success');
  });

  it('skips when the credential has no expiration date', async () => {
    const cred = CredentialFactory({ version: 'v2', credential: {} });
    delete (cred as { validUntil?: unknown }).validUntil;

    const results = await runSuites(
      [expirationSuite],
      createSubject(cred),
      contextAt('2023-01-01T00:00:00Z')
    );

    expect(results[0].outcome.status).toBe('skipped');
    if (results[0].outcome.status === 'skipped') {
      expect(results[0].outcome.reason).toContain('no expiration date');
    }
  });

  it('skips when the expiration date is not a valid date', async () => {
    const subject = createSubject(
      CredentialFactory({
        version: 'v2',
        credential: { validUntil: 'not-a-date' }
      })
    );
    const results = await runSuites(
      [expirationSuite],
      subject,
      contextAt('2023-01-01T00:00:00Z')
    );

    expect(results[0].outcome.status).toBe('skipped');
    if (results[0].outcome.status === 'skipped') {
      expect(results[0].outcome.reason).toContain('not a valid date');
    }
  });

  it('is skipped via appliesTo filter when no credential provided', async () => {
    const results = await runSuites(
      [expirationSuite],
      {},
      contextAt('2023-01-01T00:00:00Z')
    );

    expect(results).toHaveLength(0);
  });
});
