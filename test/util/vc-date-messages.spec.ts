import { describe, it, expect } from 'vitest';
import { _checkCredential } from '@interop/vc';
import {
  classifyDateRejection,
  dateRejectionProblem
} from '../../src/util/vc-date-messages.js';
import { ProblemTypes } from '../../src/problem-types.js';

const NOW = new Date('2026-01-01T00:00:00Z');

const V2 = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  type: ['VerifiableCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { id: 'did:example:subject' }
};

const V1 = {
  '@context': ['https://www.w3.org/2018/credentials/v1'],
  type: ['VerifiableCredential'],
  issuer: 'did:example:issuer',
  issuanceDate: '2020-01-01T00:00:00Z',
  credentialSubject: { id: 'did:example:subject' }
};

/** The error `@interop/vc` rejects `credential` with at `NOW`. */
function libraryRejection(credential: Record<string, unknown>): unknown {
  try {
    _checkCredential({ credential: credential as never, now: NOW });
  } catch (e) {
    return e;
  }
  throw new Error('expected @interop/vc to reject the credential');
}

function named(name: string, message: string): Error {
  const error = new Error(message);
  error.name = name;
  return error;
}

const EXPIRED_V2 =
  'The current date time (2026-01-01T00:00:00.000Z) is after "validUntil" (2011-01-01T00:00:00Z).';

describe('vc-date-messages', () => {
  it.each([
    [
      'The current date time (2026-01-01T00:00:00.000Z) is after "validUntil" (2011-01-01T00:00:00Z).',
      'expired'
    ],
    ['Credential has expired.', 'expired'],
    [
      'The current date time (2026-01-01T00:00:00.000Z) is before "validFrom" (2099-01-01T00:00:00Z).',
      'not-yet-valid'
    ],
    [
      'The current date time (2026-01-01T00:00:00.000Z) is before the "issuanceDate" (2099-01-01T00:00:00Z).',
      'not-yet-valid'
    ]
  ])('classifies a plain Error %j as %s', (message, expected) => {
    expect(classifyDateRejection(new Error(message))).toBe(expected);
  });

  /**
   * Contract with `@interop/vc`: the classifier matches the library's
   * message text, so each of its four date rejections is produced here from
   * the library itself. A reworded message fails this test rather than
   * silently turning expired credentials into signature failures.
   */
  describe('recognises the messages the installed @interop/vc produces', () => {
    it.each([
      [
        'v2 validUntil passed',
        { ...V2, validUntil: '2011-01-01T00:00:00Z' },
        'expired'
      ],
      [
        'v1 expirationDate passed',
        { ...V1, expirationDate: '2021-01-01T00:00:00Z' },
        'expired'
      ],
      [
        'v2 validFrom ahead',
        { ...V2, validFrom: '2099-01-01T00:00:00Z' },
        'not-yet-valid'
      ],
      [
        'v1 issuanceDate ahead',
        { ...V1, issuanceDate: '2099-01-01T00:00:00Z' },
        'not-yet-valid'
      ]
    ])('%s', (_name, credential, expected) => {
      expect(classifyDateRejection(libraryRejection(credential))).toBe(
        expected
      );
    });
  });

  it('does not classify a signature failure as a date rejection', () => {
    expect(
      classifyDateRejection(new Error('Invalid signature.'))
    ).toBeUndefined();
  });

  describe('matches strictly', () => {
    it('rejects a bare message string', () => {
      expect(classifyDateRejection(EXPIRED_V2)).toBeUndefined();
    });

    it('rejects a VerificationError carrying the message', () => {
      expect(
        classifyDateRejection(named('VerificationError', EXPIRED_V2))
      ).toBeUndefined();
    });

    it('rejects an Error carrying errors[]', () => {
      expect(
        classifyDateRejection(
          Object.assign(new Error(EXPIRED_V2), { errors: [] })
        )
      ).toBeUndefined();
    });

    it('rejects a date phrase inside a longer message', () => {
      expect(
        classifyDateRejection(new Error(`Proof failed: ${EXPIRED_V2}`))
      ).toBeUndefined();
      expect(
        classifyDateRejection(new Error('Credential has expired. Also bad.'))
      ).toBeUndefined();
    });
  });

  describe('dateRejectionProblem', () => {
    it('names the v2 date, its property and the verification instant', () => {
      expect(
        dateRejectionProblem(
          'expired',
          { validUntil: '2011-01-01T00:00:00Z' },
          NOW
        )
      ).toEqual({
        type: ProblemTypes.CREDENTIAL_EXPIRED,
        title: 'Credential Expired',
        detail:
          'Validity ended at 2011-01-01T00:00:00Z (validUntil). Verified at 2026-01-01T00:00:00.000Z.'
      });
    });

    it('falls back to the v1 property', () => {
      const problem = dateRejectionProblem(
        'not-yet-valid',
        { issuanceDate: '2099-01-01T00:00:00Z' },
        NOW
      );

      expect(problem.type).toBe(ProblemTypes.CREDENTIAL_NOT_YET_VALID);
      expect(problem.detail).toBe(
        'Validity starts at 2099-01-01T00:00:00Z (issuanceDate). Verified at 2026-01-01T00:00:00.000Z.'
      );
    });

    it('quotes the property it is given', () => {
      expect(
        dateRejectionProblem(
          'expired',
          {
            validUntil: '2011-01-01T00:00:00Z',
            expirationDate: '2012-01-01T00:00:00Z'
          },
          NOW,
          'expirationDate'
        ).detail
      ).toBe(
        'Validity ended at 2012-01-01T00:00:00Z (expirationDate). Verified at 2026-01-01T00:00:00.000Z.'
      );
    });

    it('describes a credential without the date property', () => {
      expect(dateRejectionProblem('expired', {}, NOW).detail).toBe(
        'Validity ended. Verified at 2026-01-01T00:00:00.000Z.'
      );
    });
  });
});
