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
import { documentHasProof, proofEntries } from '../util/document-has-proof.js';

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

function extractErrors(error: unknown): unknown[] {
  const err = error as { errors?: unknown[] } | undefined;
  if (err?.errors && Array.isArray(err.errors)) {
    return err.errors;
  }
  return error ? [error] : [];
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

function hasMessage(errors: unknown[], text: string): boolean {
  return errors.some(e => {
    const x = e as { message?: string; error?: { message?: string } };
    return (x.error?.message ?? x.message)?.includes(text) ?? false;
  });
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
function isDidUnresolved(errors: unknown[]): boolean {
  return errors.some(e => {
    const x = e as {
      name?: string;
      code?: string;
      error?: { name?: string; code?: string };
    };
    const inner = x.error ?? x;
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

function isVerificationMethodUnresolved(errors: unknown[]): boolean {
  return errors.some(e => {
    const x = e as { message?: string; error?: { message?: string } };
    return (
      DRIVER_NOT_FOUND.test(x.message ?? '') ||
      DRIVER_NOT_FOUND.test(x.error?.message ?? '')
    );
  });
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

/** Exported for unit testing. */
export function classifySignatureError(
  error: unknown,
  credential: Record<string, unknown> | undefined
): ProblemDetail[] {
  const errors = extractErrors(error);

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
      const issuer = credential.issuer as string | { id: string } | undefined;
      const issuerDid = typeof issuer === 'string' ? issuer : issuer?.id || '';

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
  if (hasMessage(errors, ISSUER_CONTROLLER_MISMATCH)) {
    const issuer = credential?.issuer as string | { id?: string } | undefined;
    const issuerId = typeof issuer === 'string' ? issuer : issuer?.id;
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
  if (isVerificationMethodUnresolved(errors)) {
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

  // A challenge or domain mismatch is a purpose validation failure, not a bad
  // signature: the proof may verify cryptographically but does not bind to
  // this request.
  const mismatch = BINDING_MISMATCHES.find(m => hasMessage(errors, m.text));
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

  // Prefer the unpacked sub-error messages: an aggregate jsonld-signatures
  // error carries only "Verification error(s)." on itself, with the real
  // causes in its `errors[]`.
  const messages = [
    ...new Set(
      errors
        .map(e => {
          const x = e as { message?: string; error?: { message?: string } };
          return x.error?.message || x.message;
        })
        .filter((m): m is string => !!m)
    )
  ];
  return [
    {
      type: ProblemTypes.INVALID_SIGNATURE,
      title: 'Invalid Signature',
      detail: messages.join('; ') || 'The signature is not valid.'
    }
  ];
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

const PROOF_PURPOSE_MISMATCH: ProblemDetail = {
  type: ProblemTypes.PROOF_PURPOSE_MISMATCH,
  title: 'Proof Purpose Mismatch',
  detail:
    'A challenge was supplied, but no proof on the presentation uses the authentication purpose.'
};

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
      try {
        const result = await vcVerifyCredential({
          // Untrusted input crossing into the typed `@interop/vc` API; `canVerify`
          // has already confirmed a proof is present.
          credential: credential as IVerifiableCredential,
          suite: suites,
          documentLoader: options.documentLoader,
          checkStatus: noopCheckStatus
        });

        const verified = result.verified ?? false;
        if (verified) {
          return {
            verified: true,
            message: 'Signature verified successfully.'
          };
        }

        return {
          verified: false,
          problems: classifySignatureError(
            result.error,
            credential as Record<string, unknown> | undefined
          )
        };
      } catch (e) {
        return {
          verified: false,
          problems: [
            {
              type: ProblemTypes.PROOF_VERIFICATION_ERROR,
              title: 'Verification Error',
              detail:
                e instanceof Error
                  ? e.message
                  : 'An unexpected error occurred during signature verification.'
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
        // With a challenge, `AuthenticationProofPurpose` would skip every
        // non-authentication proof and jsonld-signatures would report only
        // "insufficient proofs matched". Name the cause instead.
        if (
          typeof options.challenge === 'string' &&
          !hasAuthenticationProof(doc)
        ) {
          return { verified: false, problems: [PROOF_PURPOSE_MISMATCH] };
        }

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

        return {
          verified: false,
          problems: classifySignatureError(result.error, undefined)
        };
      } catch (e) {
        return {
          verified: false,
          problems: [
            {
              type: ProblemTypes.PROOF_VERIFICATION_ERROR,
              title: 'Verification Error',
              detail:
                e instanceof Error
                  ? e.message
                  : 'An unexpected error occurred during signature verification.'
            }
          ]
        };
      }
    }
  };
}
