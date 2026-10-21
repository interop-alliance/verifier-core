/**
 * Acceptance evidence for telling an out-of-date credential apart from a
 * forged one, and for the clock that decides which it is. An authentic
 * credential outside its validity period passes `proof.signature` and
 * fails `proof.validity-period`, which is fatal but does not halt, so the
 * checks after it still run.
 *
 * Runs offline with real signatures; see
 * `test/factories/services/offline-signing.ts`.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { issue } from '@interop/vc';
import { Ed25519Signature2020 } from '@interop/ed25519-signature';
import { createVerifier } from '../src/verifier.js';
import { FakeTimeService } from '../src/services/time-service/fake-time-service.js';
import { ProblemTypes } from '../src/problem-types.js';
import type { CheckResult, VerificationSuite } from '../src/types/check.js';
import type { ProblemDetail } from '../src/types/problem-detail.js';
import {
  documentLoader,
  ED25519_2020_CONTEXT,
  offlineHttpGetService,
  offlineSigner,
  signatureResult
} from './factories/services/offline-signing.js';
import { v1Expired } from './fixtures/v1-expired.js';
import { v2Expired } from './fixtures/v2-expired.js';
import { notRunOutcome } from './factories/index.js';

/** Far enough ahead that no plausible test clock has reached it. */
const FUTURE = '2099-01-01T00:00:00Z';

function v2Template(issuerDid: string): Record<string, unknown> {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2', ED25519_2020_CONTEXT],
    id: 'urn:uuid:credential-validity-dates-v2',
    type: ['VerifiableCredential'],
    issuer: issuerDid,
    validFrom: FUTURE,
    credentialSubject: { id: 'did:example:subject' }
  };
}

function v1Template(issuerDid: string): Record<string, unknown> {
  return {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
      ED25519_2020_CONTEXT
    ],
    id: 'urn:uuid:credential-validity-dates-v1',
    type: ['VerifiableCredential'],
    issuer: issuerDid,
    issuanceDate: FUTURE,
    credentialSubject: { id: 'did:example:subject' }
  };
}

function row(results: CheckResult[], id: string): CheckResult | undefined {
  const found = results.find(r => r.id === id);
  expect(found, `${id} result present`).toBeDefined();
  return found;
}

function signatureProblem(results: CheckResult[]): ProblemDetail | undefined {
  const outcome = signatureResult(results)?.outcome;
  expect(outcome, 'proof.signature result present').toBeDefined();
  expect(outcome?.status).toBe('failure');
  return outcome?.status === 'failure' ? outcome.problems[0] : undefined;
}

/** The validity-period problem, once the signature itself verified. */
function validityProblem(results: CheckResult[]): ProblemDetail | undefined {
  expect(signatureResult(results)?.outcome.status).toBe('success');
  const outcome = row(results, 'cryptographic.proof.validity-period')?.outcome;
  expect(outcome?.status).toBe('failure');
  return outcome?.status === 'failure' ? outcome.problems[0] : undefined;
}

function notRunRows(results: CheckResult[]): CheckResult[] {
  return results.filter(
    r => r.outcome.status === 'skipped' && r.outcome.haltedBy !== undefined
  );
}

const NOT_RUN_AFTER_SIGNATURE = notRunOutcome('proof.signature');

describe('credential validity dates', () => {
  let futureV2: Record<string, unknown>;
  let futureV1: Record<string, unknown>;
  let tampered: Record<string, unknown>;
  let tamperedExpiredV2: Record<string, unknown>;
  let tamperedExpiredV1: Record<string, unknown>;

  beforeAll(async () => {
    const { did: issuerDid, signer } = await offlineSigner(21);
    const suite = new Ed25519Signature2020({ signer });

    // `issue` does not compare dates, so it signs a credential whose
    // validity has not begun without complaint.
    futureV2 = (await issue({
      credential: v2Template(issuerDid) as never,
      suite,
      documentLoader
    })) as Record<string, unknown>;

    futureV1 = (await issue({
      credential: v1Template(issuerDid) as never,
      suite,
      documentLoader
    })) as Record<string, unknown>;

    // Currently valid when signed, then edited: the one case that really
    // is a bad signature.
    const valid = (await issue({
      credential: {
        ...v2Template(issuerDid),
        id: 'urn:uuid:credential-validity-dates-tampered',
        validFrom: '2020-01-01T00:00:00Z'
      } as never,
      suite,
      documentLoader
    })) as Record<string, unknown>;
    tampered = {
      ...valid,
      credentialSubject: { id: 'did:example:someone-else' }
    };

    // Expired and edited: the proof is bad and the dates are past. The
    // library must report the proof, which it checks first.
    const expiredV2 = (await issue({
      credential: {
        ...v2Template(issuerDid),
        id: 'urn:uuid:credential-validity-dates-tampered-expired-v2',
        validFrom: '2010-01-01T00:00:00Z',
        validUntil: '2011-01-01T00:00:00Z'
      } as never,
      suite,
      documentLoader
    })) as Record<string, unknown>;
    tamperedExpiredV2 = {
      ...expiredV2,
      credentialSubject: { id: 'did:example:someone-else' }
    };

    const expiredV1 = (await issue({
      credential: {
        ...v1Template(issuerDid),
        id: 'urn:uuid:credential-validity-dates-tampered-expired-v1',
        issuanceDate: '2010-01-01T00:00:00Z',
        expirationDate: '2011-01-01T00:00:00Z'
      } as never,
      suite,
      documentLoader
    })) as Record<string, unknown>;
    tamperedExpiredV1 = {
      ...expiredV1,
      credentialSubject: { id: 'did:example:someone-else' }
    };
  });

  const verifier = (baseDateMs?: number) =>
    createVerifier({
      httpGetService: offlineHttpGetService,
      documentLoader,
      timeService:
        baseDateMs === undefined ? undefined : FakeTimeService({ baseDateMs })
    });

  it('reports a v2 credential whose validFrom is in the future as CREDENTIAL_NOT_YET_VALID', async () => {
    const result = await verifier().verifyCredential({
      credential: futureV2,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(false);
    const problem = validityProblem(result.results);
    expect(problem?.type).toBe(ProblemTypes.CREDENTIAL_NOT_YET_VALID);
    expect(problem?.title).toBe('Credential Not Yet Valid');
    expect(problem?.detail).toContain(
      `Validity starts at ${FUTURE} (validFrom)`
    );
  });

  it('reports a v1 credential whose issuanceDate is in the future as CREDENTIAL_NOT_YET_VALID', async () => {
    const result = await verifier().verifyCredential({
      credential: futureV1,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(false);
    const problem = validityProblem(result.results);
    expect(problem?.type).toBe(ProblemTypes.CREDENTIAL_NOT_YET_VALID);
    expect(problem?.detail).toContain(
      `Validity starts at ${FUTURE} (issuanceDate)`
    );
  });

  it('reports an expired v2 credential as CREDENTIAL_EXPIRED on proof.validity-period, naming both instants', async () => {
    const result = await verifier().verifyCredential({
      credential: v2Expired,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(false);
    const problem = validityProblem(result.results);
    expect(problem?.type).toBe(ProblemTypes.CREDENTIAL_EXPIRED);
    expect(problem?.title).toBe('Credential Expired');
    expect(problem?.detail).toContain(
      `Validity ended at ${String(v2Expired.validUntil)} (validUntil)`
    );
    expect(problem?.detail).toContain('Verified at ');
  });

  it('reports an expired v1 credential as CREDENTIAL_EXPIRED on proof.validity-period', async () => {
    const result = await verifier().verifyCredential({
      credential: v1Expired,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(false);
    const problem = validityProblem(result.results);
    expect(problem?.type).toBe(ProblemTypes.CREDENTIAL_EXPIRED);
    expect(problem?.detail).toContain(
      `Validity ended at ${String(v1Expired.expirationDate)} (expirationDate)`
    );
  });

  it('still runs the status, registry and caller-added checks after an expired credential', async () => {
    const extra: VerificationSuite = {
      id: 'extra',
      name: 'Extra',
      phase: 'semantic',
      checks: [
        {
          id: 'extra.ran',
          name: 'Ran',
          execute: async () => ({ status: 'success', message: 'Ran.' })
        }
      ]
    };
    const result = await verifier().verifyCredential({
      credential: v2Expired,
      additionalSuites: [extra]
    });

    expect(result.verified).toBe(false);
    expect(validityProblem(result.results)?.type).toBe(
      ProblemTypes.CREDENTIAL_EXPIRED
    );
    expect(notRunRows(result.results)).toEqual([]);
    expect(row(result.results, 'cryptographic.status.bitstring')).toBeDefined();
    expect(row(result.results, 'trust.registry.issuer')).toBeDefined();
    expect(row(result.results, 'semantic.extra.ran')?.outcome).toEqual({
      status: 'success',
      message: 'Ran.'
    });
    expect(result.summary.find(s => s.suite === 'proof')?.fatalFailureAt).toBe(
      'cryptographic.proof.validity-period'
    );
  });

  it('still reports a tampered credential as INVALID_SIGNATURE', async () => {
    const result = await verifier().verifyCredential({
      credential: tampered,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(false);
    expect(signatureProblem(result.results)?.type).toBe(
      ProblemTypes.INVALID_SIGNATURE
    );
    expect(
      row(result.results, 'cryptographic.proof.validity-period')?.outcome
    ).toEqual(NOT_RUN_AFTER_SIGNATURE);
  });

  // The ordering guard. `proof.signature` reads a date-only rejection as a
  // verified signature because the library checks dates only after the
  // proof. If an upgrade of `@interop/vc` ever checked dates first, a
  // tampered, expired credential would read as merely expired; these fail
  // instead.
  for (const [version, credential] of [
    ['v2', () => tamperedExpiredV2],
    ['v1', () => tamperedExpiredV1]
  ] as const) {
    it(`reports a tampered, expired ${version} credential as a bad signature, not as expired`, async () => {
      const result = await verifier().verifyCredential({
        credential: credential(),
        phases: ['cryptographic']
      });

      expect(result.verified).toBe(false);
      expect(signatureProblem(result.results)?.type).toBe(
        ProblemTypes.INVALID_SIGNATURE
      );
      expect(
        row(result.results, 'cryptographic.proof.validity-period')?.outcome
      ).toEqual(NOT_RUN_AFTER_SIGNATURE);
    });
  }

  it('honours the verifier clock: an expired v2 fixture verifies when the clock is inside its validity window', async () => {
    // v2Expired is valid from 2010-01-01 until 2011-01-01.
    const result = await verifier(
      Date.parse('2010-06-01T00:00:00Z')
    ).verifyCredential({
      credential: v2Expired,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(true);
    expect(signatureResult(result.results)?.outcome.status).toBe('success');
  });

  it('honours the verifier clock for a v1 fixture too', async () => {
    // v1Expired was issued at 15:06:31Z and expired at 16:23:24Z on
    // 2025-01-09.
    const result = await verifier(
      Date.parse('2025-01-09T16:00:00Z')
    ).verifyCredential({
      credential: v1Expired,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(true);
    expect(signatureResult(result.results)?.outcome.status).toBe('success');
  });

  it('compares dates exactly: one second past validUntil is CREDENTIAL_EXPIRED', async () => {
    // Inside the 300 s clock-skew window `@interop/vc` would allow on its
    // own. The verifier passes a zero skew so the library agrees with
    // `proof.validity-period`.
    const result = await verifier(
      Date.parse(String(v2Expired.validUntil)) + 1000
    ).verifyCredential({
      credential: v2Expired,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(false);
    expect(validityProblem(result.results)?.type).toBe(
      ProblemTypes.CREDENTIAL_EXPIRED
    );
  });

  it('compares dates exactly: one second before validFrom is CREDENTIAL_NOT_YET_VALID', async () => {
    const result = await verifier(
      Date.parse(String(v2Expired.validFrom)) - 1000
    ).verifyCredential({
      credential: v2Expired,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(false);
    expect(validityProblem(result.results)?.type).toBe(
      ProblemTypes.CREDENTIAL_NOT_YET_VALID
    );
  });

  it('a clock set before validFrom makes a currently valid credential CREDENTIAL_NOT_YET_VALID', async () => {
    const result = await verifier(
      Date.parse('2009-01-01T00:00:00Z')
    ).verifyCredential({
      credential: v2Expired,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(false);
    expect(validityProblem(result.results)?.type).toBe(
      ProblemTypes.CREDENTIAL_NOT_YET_VALID
    );
  });
});
