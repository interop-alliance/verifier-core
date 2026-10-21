/**
 * Default {@link CryptoService} for Linked Data Proofs and Data Integrity
 * proofs via `@interop/vc`. For a presentation only the VP's own proof is
 * verified (`verifyCredentials: false`); embedded credentials get their own
 * `verifyCredential` run.
 */

import {
  verifyCredential as vcVerifyCredential,
  verify as vcVerifyPresentation
} from '@interop/vc';
import jsonLdSignatures from '@interop/jsonld-signatures';
import type {
  IProofDescription,
  IVerifiableCredential,
  IVerifiablePresentation
} from '@interop/data-integrity-core';
import type {
  CryptoResult,
  CryptoService,
  CryptoVerifyOptions
} from '../types/crypto-service.js';
import type { CryptoSuite, ProofPurpose } from '../types/crypto-suite.js';
import type { ProblemDetail } from '../types/problem-detail.js';
import type { VerificationSubject } from '../types/subject.js';
import { ProblemTypes } from '../problem-types.js';
import { errorMessage } from '../util/error-message.js';
import { credentialIssuerId } from '../util/issuer-id.js';
import { documentHasProof, proofEntries } from '../util/document-has-proof.js';
import { isJsigsNoMatch } from '../util/jsigs-no-match.js';
import { isVerificationMethodMessage } from '../util/verification-method-messages.js';
import {
  classifyDateRejection,
  dateRejectionProblem
} from '../util/vc-date-messages.js';

/**
 * No-op `checkStatus` passed to `@interop/vc` so its
 * `_verifyCredential` doesn't throw `TypeError` when a VC carries
 * `credentialStatus`. The library requires a callable `checkStatus`
 * for any VC with `credentialStatus`; this no-op satisfies that
 * required signature without performing any real status work.
 *
 * Real status verification is owned by `statusSuite`
 * (`src/suites/status/bitstring-status-check.ts`). See plan
 * `docs/plans/2026-04-19-route-via-http-and-dedupe-status-check/`
 * for the rationale (P-E: status is owned solely by the status
 * suite, no double-check from the proof path).
 */
const noopCheckStatus = async (): Promise<{ verified: true; results: [] }> => ({
  verified: true,
  results: []
});

const { purposes } = jsonLdSignatures;

const HTTP_ERROR = 'HTTPError';
const JSONLD_VALIDATION_ERROR = 'jsonld.ValidationError';

/**
 * The sub-errors of an aggregate `VerificationError`, or the error itself.
 * Only objects are kept: a `null` or primitive entry carries no name, code,
 * or message to classify by, and must not turn a verdict into a throw.
 */
function extractErrors(error: unknown): object[] {
  const err = error as { errors?: unknown[] } | undefined;
  const candidates =
    err?.errors && Array.isArray(err.errors) ? err.errors : [error];
  return candidates.filter(
    (e): e is object => typeof e === 'object' && e !== null
  );
}

/**
 * A jsonld-signatures sub-error is either an `Error` or a `{ error }`
 * wrapper around one; this returns the error itself.
 */
function unwrapSubError(e: object): object {
  return (e as { error?: object | null }).error ?? e;
}

function subErrorMessage(e: object): string | undefined {
  const { message } = unwrapSubError(e) as { message?: unknown };
  return typeof message === 'string' && message !== '' ? message : undefined;
}

/**
 * The `VerificationMethodError` (from `@interop/data-integrity-core`) that
 * `@interop/jsonld-signatures` and the DID drivers throw, or `undefined` for
 * any other sub-error. Matched by `name` only: every code it carries is the
 * same fault, so a code added upstream must not demote it to a bad signature.
 */
function verificationMethodError(
  e: object
): { verificationMethod?: unknown } | undefined {
  const inner = unwrapSubError(e) as {
    name?: string;
    verificationMethod?: unknown;
  };
  return inner.name === 'VerificationMethodError' ? inner : undefined;
}

/**
 * The distinct sub-error messages, in order, with the verification method
 * faults (the typed error, or a message matching the known library texts)
 * listed separately from the rest. A typed error with a blank message is
 * described by the method id it names.
 */
function partitionSubErrorMessages(errors: object[]): {
  messages: string[];
  faults: string[];
  others: string[];
} {
  const messages = new Set<string>();
  const faults = new Set<string>();
  for (const e of errors) {
    const typed = verificationMethodError(e);
    const message = subErrorMessage(e) ?? (typed && typedFaultDetail(typed));
    if (message === undefined) {
      continue;
    }
    messages.add(message);
    if (typed !== undefined || isVerificationMethodMessage(message)) {
      faults.add(message);
    }
  }
  return {
    messages: [...messages],
    faults: [...faults],
    others: [...messages].filter(m => !faults.has(m))
  };
}

function typedFaultDetail(typed: { verificationMethod?: unknown }): string {
  const id = typed.verificationMethod;
  const named = typeof id === 'string' && id !== '' ? ` "${id}"` : '';
  return `Verification method${named} cannot back the proof.`;
}

function isHttpError(errors: unknown[]): boolean {
  return errors.some(e => {
    const x = e as { name?: string; type?: string };
    return x.name === HTTP_ERROR || x.type === HTTP_ERROR;
  });
}

const ISSUER_CONTROLLER_MISMATCH =
  'issuer must match the verification method controller';
/** jsonld-signatures purpose-validation messages, with the proof field each names. */
const BINDING_MISMATCHES = [
  { text: 'The challenge is not as expected', field: 'challenge' },
  { text: 'The domain is not as expected', field: 'domain' }
] as const;

function hasMessage(messages: string[], text: string): boolean {
  return messages.some(m => m.includes(text));
}

function isJsonLdError(errors: unknown[]): boolean {
  return errors.some(e => {
    const x = e as { name?: string; type?: string };
    return (
      x.name === JSONLD_VALIDATION_ERROR || x.type === JSONLD_VALIDATION_ERROR
    );
  });
}

function getHttpError(errors: unknown[]): unknown | undefined {
  return errors.find(e => {
    const x = e as { name?: string; type?: string };
    return x.name === HTTP_ERROR || x.type === HTTP_ERROR;
  });
}

function isDidWeb(did: string): boolean {
  return did.toLowerCase().startsWith('did:web:');
}

// A DID driver throws a `DIDResolutionError` (from
// `@interop/data-integrity-core`) when the DID could not be resolved. For
// example, `@interop/did-method-webvh` codes a 404 on the DID log as
// `notFound`, and any other HTTP error status or transport failure as
// `internalError`. Matched by `name`, since a duplicate package copy would
// defeat `instanceof`.
function isDidUnresolved(errors: object[]): boolean {
  return errors.some(e => {
    const inner = unwrapSubError(e) as { name?: string; code?: string };
    return (
      inner.name === 'DIDResolutionError' &&
      (inner.code === 'notFound' || inner.code === 'internalError')
    );
  });
}

function didUnresolvedProblems(detail: string): ProblemDetail[] {
  return [
    {
      type: ProblemTypes.DID_WEB_UNRESOLVED,
      title: 'DID Web Unresolved',
      detail
    }
  ];
}

function didWebToUrlPattern(did: string): string {
  return did.slice(8).replaceAll(':', '/').toLowerCase();
}

// did-io's `CachedResolver` throws `Driver for DID method "<m>" not found.` /
// `Driver for DID <did> not found.` when the document loader has no driver for
// the proof's verification-method DID method. `jsonld-signatures` buries this in
// its aggregated `errors[]`, so it would otherwise surface as a misleading
// INVALID_SIGNATURE.
const DRIVER_NOT_FOUND = /driver for did(?: method)? .* not found/i;

function isVerificationMethodUnresolved(messages: string[]): boolean {
  return messages.some(m => DRIVER_NOT_FOUND.test(m));
}

function proofVerificationMethod(
  credential: Record<string, unknown> | undefined
): string | undefined {
  const proof = credential?.proof as
    Record<string, unknown> | Array<Record<string, unknown>> | undefined;
  const first = Array.isArray(proof) ? proof[0] : proof;
  const vm = first?.verificationMethod;
  return typeof vm === 'string' ? vm : undefined;
}

/**
 * The `CryptoResult` for an `@interop/vc` rejection. The library judges
 * validity dates only once the proof verified, so a date rejection is the
 * one case that sets `proofVerified`: the signature was good, and only
 * the dates failed.
 */
function rejection(
  error: unknown,
  credential: Record<string, unknown> | undefined,
  now: Date
): CryptoResult {
  const problems = classifySignatureError(error, credential, now);
  return classifyDateRejection(error) === undefined
    ? { verified: false, problems }
    : { verified: false, problems, proofVerified: true };
}

/**
 * Map an `@interop/vc` rejection onto problems. `now` is the instant the
 * library judged validity dates against. Exported for unit testing.
 */
export function classifySignatureError(
  error: unknown,
  credential: Record<string, unknown> | undefined,
  now: Date
): ProblemDetail[] {
  // The library checks validity dates only after the proof verified, and
  // reports a date failure as a plain Error rather than a
  // VerificationError. Say so with a typed problem (and, in `rejection`,
  // with `proofVerified`): it is how `status.bitstring` tells an expired
  // list from a bad one. INVALID_SIGNATURE would accuse an honest issuer
  // of forgery.
  const dateRejection = classifyDateRejection(error);
  if (dateRejection !== undefined) {
    return [dateRejectionProblem(dateRejection, credential, now)];
  }

  const errors = extractErrors(error);
  const { messages, faults, others } = partitionSubErrorMessages(errors);

  if (isJsonLdError(errors)) {
    return errors.map((e: unknown) => {
      const x = e as { message?: string };
      return {
        type: ProblemTypes.PARSING_ERROR,
        title: 'JSON-LD Validation Error',
        detail: x.message || 'Invalid JSON-LD document'
      };
    });
  }

  if (isHttpError(errors)) {
    const httpError = getHttpError(errors) as
      | {
          requestUrl?: string;
          url?: string;
          message?: string;
        }
      | undefined;
    const requestUrl = httpError?.requestUrl || httpError?.url || '';

    if (credential) {
      const issuerDid = credentialIssuerId(credential) ?? '';

      if (isDidWeb(issuerDid)) {
        const didUrlPattern = didWebToUrlPattern(issuerDid);
        if (requestUrl.toLowerCase().includes(didUrlPattern)) {
          return didUnresolvedProblems(
            `The signature could not be checked because the public signing key could not be retrieved from ${String(requestUrl)}`
          );
        }
      }
    }

    return [
      {
        type: ProblemTypes.HTTP_ERROR,
        title: 'HTTP Error',
        detail:
          httpError?.message || 'An HTTP error prevented the signature check.'
      }
    ];
  }

  // A verification method whose DID could not be resolved (e.g. an
  // unreachable did:webvh log): the same concern as an unreachable did:web
  // document.
  const vmId = proofVerificationMethod(credential);
  if (isDidUnresolved(errors)) {
    const vmDid = vmId?.split('#')[0] ?? 'the verification method DID';
    return didUnresolvedProblems(
      `The signature could not be checked because ${vmDid} could not be resolved.`
    );
  }

  // An issuer / controller mismatch is not a bad signature: the proof verifies
  // cryptographically but its purpose validation fails because the credential's
  // `issuer` differs from the controller of the proof's verification method.
  // Surface it as a distinct, explicit problem rather than INVALID_SIGNATURE.
  if (hasMessage(messages, ISSUER_CONTROLLER_MISMATCH)) {
    const issuerId = credential ? credentialIssuerId(credential) : undefined;
    return [
      {
        type: ProblemTypes.ISSUER_PROOF_MISMATCH,
        title: 'Issuer / Proof Mismatch',
        detail: `The credential's issuer${issuerId ? ` (${issuerId})` : ''} does not match the controller of the proof's verification method.`
      }
    ];
  }

  // The verification method's DID method has no driver in the document loader,
  // so its public key could never be fetched -- the signature was never actually
  // checked. Distinguish this from a genuine INVALID_SIGNATURE.
  if (isVerificationMethodUnresolved(messages)) {
    return [
      {
        type: ProblemTypes.VERIFICATION_METHOD_UNRESOLVED,
        title: 'Verification Method Unresolved',
        detail:
          "The signature could not be checked because the proof's verification " +
          'method uses a DID method the verifier cannot resolve' +
          `${vmId ? ` (${vmId})` : ''}. Register a resolver/driver for it in ` +
          'the document loader.'
      }
    ];
  }

  // The verification method resolved but the controller document does not
  // list it, or does not authorize it for the proof purpose. The issuer's key
  // setup is wrong; the content was not shown to be altered. In a proof set,
  // the other proofs' failures are kept beside the fault rather than hidden
  // by it.
  if (faults.length > 0) {
    const problems: ProblemDetail[] = faults.map(detail => ({
      type: ProblemTypes.VERIFICATION_METHOD_ERROR,
      title: 'Verification Method Error',
      detail
    }));
    if (others.length > 0) {
      problems.push(invalidSignature(others));
    }
    return problems;
  }

  // A challenge or domain mismatch is a purpose validation failure, not a bad
  // signature: the proof may verify cryptographically but does not bind to
  // this request.
  const mismatch = BINDING_MISMATCHES.find(m => hasMessage(messages, m.text));
  if (mismatch) {
    const { field } = mismatch;
    return [
      {
        type: ProblemTypes.PROOF_PURPOSE_MISMATCH,
        title: field === 'challenge' ? 'Challenge Mismatch' : 'Domain Mismatch',
        detail: `The presentation proof's ${field} does not match the expected ${field}.`
      }
    ];
  }

  return [invalidSignature(messages)];
}

/**
 * The generic verdict, with the unpacked sub-error messages as detail: an
 * aggregate jsonld-signatures error carries only "Verification error(s)." on
 * itself, with the real causes in its `errors[]`.
 */
function invalidSignature(messages: string[]): ProblemDetail {
  return {
    type: ProblemTypes.INVALID_SIGNATURE,
    title: 'Invalid Signature',
    detail: messages.join('; ') || 'The signature is not valid.'
  };
}

function isAuthenticationPurpose(proofPurpose: unknown): boolean {
  return (
    proofPurpose === 'authentication' || proofPurpose === 'authenticationMethod'
  );
}

/** Whether any proof in the presentation's proof set is an authentication proof. */
function hasAuthenticationProof(
  presentation: Record<string, unknown>
): boolean {
  return proofEntries(presentation).some(entry =>
    isAuthenticationPurpose(entry.proofPurpose)
  );
}

/**
 * The proof purpose the library checks a credential's proof against: its
 * default `CredentialIssuancePurpose` is an assertion purpose.
 */
const CREDENTIAL_PROOF_PURPOSE = 'assertionMethod';

/**
 * Whether any configured suite would check `proof`, asked the way
 * jsonld-signatures asks: with the document's `@context` on the proof.
 * `undefined` when no suite matched but one threw while looking: a
 * `matchProof` may load the proof's context through `documentLoader`, so
 * a network fault there says nothing about the cryptosuite.
 */
async function anySuiteMatches(
  proof: Record<string, unknown>,
  document: Record<string, unknown>,
  suites: CryptoSuite[],
  documentLoader: CryptoVerifyOptions['documentLoader']
): Promise<boolean | undefined> {
  const proofWithContext = { '@context': document['@context'], ...proof };
  let threw = false;
  for (const suite of suites) {
    try {
      if (
        await suite.matchProof({
          proof: proofWithContext as IProofDescription,
          document,
          documentLoader
        })
      ) {
        return true;
      }
    } catch {
      threw = true;
    }
  }
  return threw ? undefined : false;
}

/**
 * Say why jsonld-signatures checked no proof, so that a warning about an
 * extra proof in a proof set names the real reason. jsonld-signatures
 * skips a proof for a purpose mismatch or for having no matching suite,
 * and reports both the same way; asking the suites tells them apart. A
 * document with several proofs gets a general wording, since each proof
 * may have been skipped for a different reason. So does a proof the
 * suites could not look at (see {@link anySuiteMatches}).
 */
async function unsupportedProofProblem(
  document: Record<string, unknown> | undefined,
  suites: CryptoSuite[],
  expectedPurpose: string,
  documentLoader: CryptoVerifyOptions['documentLoader']
): Promise<ProblemDetail> {
  let detail =
    'No proof in this document could be checked: none uses a cryptosuite this verifier supports with the expected proof purpose.';
  const [proof, ...otherProofs] = proofEntries(document);
  if (document && proof && otherProofs.length === 0) {
    const matched = await anySuiteMatches(
      proof,
      document,
      suites,
      documentLoader
    );
    if (matched === false) {
      detail = "This verifier does not support this proof's cryptosuite.";
    } else if (matched && proof.proofPurpose !== expectedPurpose) {
      detail = `This proof's purpose (${String(proof.proofPurpose ?? 'none')}) is not the one being checked (${expectedPurpose}).`;
    }
  }
  return {
    type: ProblemTypes.PROOF_UNSUPPORTED,
    title: 'Unsupported Proof',
    detail
  };
}

/**
 * Selects the proof purpose used to verify a presentation's proof set.
 *
 * A supplied `challenge` is the caller asking for replay protection, so it
 * decides the purpose. The proof must then use `authentication` and carry that
 * challenge (and `domain`, if given). The presentation's own `proofPurpose`
 * cannot opt out.
 *
 * With no challenge supplied, only the signature is checked. The scan covers
 * EVERY proof in a proof array, not just the first. Under
 * `AssertionProofPurpose`, jsonld-signatures skips non-matching proofs and
 * aggregates with `verified = results.some(...)`. Picking the purpose from
 * `proof[0]` alone would let a presentation whose first proof is an
 * `assertionMethod` proof verify while its `authentication` proof is never
 * signature-checked. So if any proof declares an authentication purpose, the
 * set is verified under a `ControllerProofPurpose` with the `authentication`
 * term. That checks the signature and the key's authorization for
 * `authentication`, but no `challenge` or `domain`, so a proof without a
 * challenge, or a set of proofs with different challenges, verifies on its
 * signatures alone.
 *
 * Exported for unit testing.
 */
export function getPresentationPurpose(
  presentation: Record<string, unknown>,
  challenge: string | null | undefined,
  domain?: string
): ProofPurpose {
  if (typeof challenge === 'string') {
    return new purposes.AuthenticationProofPurpose({
      // `term` defaults to `'authentication'` at runtime; the published types
      // mark it required, so pass the same default explicitly.
      term: 'authentication',
      challenge,
      domain
    });
  }

  if (hasAuthenticationProof(presentation)) {
    return new purposes.ControllerProofPurpose({ term: 'authentication' });
  }

  return new purposes.AssertionProofPurpose();
}

export interface DataIntegrityCryptoConfig {
  suites: CryptoSuite[];
}

/**
 * Builds a {@link CryptoService} that verifies with the given proof suites
 * (e.g. Ed25519Signature2020 + DataIntegrityProof).
 *
 * Signature verification only — credential status is the responsibility
 * of `statusSuite` (see `src/suites/status/`). This adapter does not
 * read or verify `credentialStatus`.
 */
export function DataIntegrityCryptoService(
  config: DataIntegrityCryptoConfig
): CryptoService {
  const { suites } = config;

  return {
    canVerify: (subject: VerificationSubject): boolean =>
      documentHasProof(
        subject.verifiablePresentation ?? subject.verifiableCredential
      ),

    verifyCredential: async (
      credential: unknown,
      options: CryptoVerifyOptions
    ): Promise<CryptoResult> => {
      const now = options.now ?? new Date();
      try {
        const result = await vcVerifyCredential({
          // Untrusted input crossing into the typed `@interop/vc` API; `canVerify`
          // has already confirmed a proof is present.
          credential: credential as IVerifiableCredential,
          suite: suites,
          documentLoader: options.documentLoader,
          checkStatus: noopCheckStatus,
          // Validity dates are checked after the proof verifies, exactly
          // against `now`. The library's default 300 seconds of clock skew
          // would let a credential that expired moments ago pass here and
          // fail `proof.validity-period`; a consumer wanting tolerance
          // moves the verifier's `timeService` instead.
          now,
          maxClockSkew: 0
        });

        const verified = result.verified ?? false;
        if (verified) {
          return {
            verified: true,
            message: 'Signature verified successfully.'
          };
        }

        if (isJsigsNoMatch(result.error)) {
          return {
            verified: false,
            problems: [
              await unsupportedProofProblem(
                credential as Record<string, unknown> | undefined,
                suites,
                CREDENTIAL_PROOF_PURPOSE,
                options.documentLoader
              )
            ]
          };
        }

        return rejection(
          result.error,
          credential as Record<string, unknown> | undefined,
          now
        );
      } catch (e) {
        return {
          verified: false,
          problems: [
            {
              type: ProblemTypes.PROOF_VERIFICATION_ERROR,
              title: 'Verification Error',
              detail: errorMessage(
                e,
                'An unexpected error occurred during signature verification.'
              )
            }
          ]
        };
      }
    },

    verifyPresentation: async (
      presentation: unknown,
      options: CryptoVerifyOptions
    ): Promise<CryptoResult> => {
      try {
        const doc = presentation as Record<string, unknown>;
        // With a challenge, `AuthenticationProofPurpose` skips every
        // non-authentication proof, and jsonld-signatures reports that as
        // "no proof matched": PROOF_UNSUPPORTED, naming the purpose.
        const purpose = getPresentationPurpose(
          doc,
          options.challenge,
          options.domain
        );

        // Only the VP's own proof is verified here. Embedded credentials get
        // their own `verifyCredential` run and result, so one bad credential
        // does not read as a bad presentation signature. `@interop/vc` still
        // checks the VP shape (VC context, `VerifiablePresentation` type).
        const result = await vcVerifyPresentation({
          // Untrusted input crossing into the typed `@interop/vc` API;
          // `canVerify` has already confirmed a proof is present.
          presentation: presentation as IVerifiablePresentation,
          presentationPurpose: purpose,
          suite: suites,
          documentLoader: options.documentLoader,
          verifyCredentials: false
        });

        if (result.verified) {
          return {
            verified: true,
            message: 'Signature verified successfully.'
          };
        }

        if (isJsigsNoMatch(result.error)) {
          return {
            verified: false,
            problems: [
              await unsupportedProofProblem(
                doc,
                suites,
                purpose.term,
                options.documentLoader
              )
            ]
          };
        }

        return rejection(result.error, undefined, options.now ?? new Date());
      } catch (e) {
        return {
          verified: false,
          problems: [
            {
              type: ProblemTypes.PROOF_VERIFICATION_ERROR,
              title: 'Verification Error',
              detail: errorMessage(
                e,
                'An unexpected error occurred during signature verification.'
              )
            }
          ]
        };
      }
    }
  };
}
