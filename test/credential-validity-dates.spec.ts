/**
 * Acceptance evidence for telling an out-of-date credential apart from a
 * forged one, and for the clock that decides which it is.
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
import type { CheckResult } from '../src/types/check.js';
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

function signatureProblem(results: CheckResult[]): ProblemDetail | undefined {
  const outcome = signatureResult(results)?.outcome;
  expect(outcome, 'proof.signature result present').toBeDefined();
  expect(outcome?.status).toBe('failure');
  return outcome?.status === 'failure' ? outcome.problems[0] : undefined;
}

describe('credential validity dates', () => {
  let futureV2: Record<string, unknown>;
  let futureV1: Record<string, unknown>;
  let tampered: Record<string, unknown>;

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
  });

  const verifier = (baseDateMs?: number) =>
    createVerifier({
      httpGetService: offlineHttpGetService,
      documentLoader,
      timeService:
        baseDateMs === undefined ? undefined : FakeTimeService({ baseDateMs }),
      verbose: true
    });

  it('reports a v2 credential whose validFrom is in the future as CREDENTIAL_NOT_YET_VALID', async () => {
    const result = await verifier().verifyCredential({
      credential: futureV2,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(false);
    const problem = signatureProblem(result.results);
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
    const problem = signatureProblem(result.results);
    expect(problem?.type).toBe(ProblemTypes.CREDENTIAL_NOT_YET_VALID);
    expect(problem?.detail).toContain(
      `Validity starts at ${FUTURE} (issuanceDate)`
    );
  });

  it('reports an expired v2 credential as CREDENTIAL_EXPIRED, naming both instants', async () => {
    const result = await verifier().verifyCredential({
      credential: v2Expired,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(false);
    const problem = signatureProblem(result.results);
    expect(problem?.type).toBe(ProblemTypes.CREDENTIAL_EXPIRED);
    expect(problem?.title).toBe('Credential Expired');
    expect(problem?.detail).toContain(
      `Validity ended at ${String(v2Expired.validUntil)} (validUntil)`
    );
    expect(problem?.detail).toContain('Verified at ');
  });

  it('reports an expired v1 credential as CREDENTIAL_EXPIRED', async () => {
    const result = await verifier().verifyCredential({
      credential: v1Expired,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(false);
    const problem = signatureProblem(result.results);
    expect(problem?.type).toBe(ProblemTypes.CREDENTIAL_EXPIRED);
    expect(problem?.detail).toContain(
      `Validity ended at ${String(v1Expired.expirationDate)} (expirationDate)`
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
  });

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
    // own. The verifier passes a zero skew so this agrees with
    // `validity.expiration`.
    const result = await verifier(
      Date.parse(String(v2Expired.validUntil)) + 1000
    ).verifyCredential({
      credential: v2Expired,
      phases: ['cryptographic']
    });

    expect(result.verified).toBe(false);
    expect(signatureProblem(result.results)?.type).toBe(
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
    expect(signatureProblem(result.results)?.type).toBe(
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
    expect(signatureProblem(result.results)?.type).toBe(
      ProblemTypes.CREDENTIAL_NOT_YET_VALID
    );
  });
});
