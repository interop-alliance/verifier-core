import {
  registerDefaultDidKeyHeaders,
  securityLoader
} from '@interop/security-document-loader';
import { CachedResolver } from '@interop/did-io';
import * as didKey from '@interop/did-method-key';
import { Ed25519VerificationKey } from '@interop/ed25519-verification-key';
import { DidWebResolver } from '@interop/did-web-resolver';
import { DIDResolutionError } from '@interop/data-integrity-core/did';
import type { DocumentLoader } from '../types/context.js';
import type { HttpGetService } from '../services/http-get-service/http-get-service.js';
import { didWebvhDriverWithHttpGet } from './did-webvh-driver-with-http-get.js';
import { parseJsonBody } from './json-body.js';
import { errorMessage } from './error-message.js';

/**
 * Fetch a did:web DID document through `httpGetService`. Every failure is a
 * `DIDResolutionError`: `notFound` for a 404, `internalError` for any other
 * non-2xx status, for a body that is not JSON (a landing page or captive
 * portal in place of the document), or for anything the service throws
 * (kept as `cause`). The messages are fixed text, so a network error's own
 * text never reaches them.
 *
 * @param httpGetService {HttpGetService}
 * @param url {string}
 * @returns {Promise<unknown>}
 */
async function fetchDidWebDocument(
  httpGetService: HttpGetService,
  url: string
): Promise<unknown> {
  let result;
  try {
    result = await httpGetService.get(url);
  } catch (cause) {
    throw new DIDResolutionError(`Could not fetch DID document at "${url}".`, {
      code: 'internalError',
      cause
    });
  }
  if (result.status < 200 || result.status >= 300) {
    throw new DIDResolutionError(
      `Fetching DID document at "${url}" returned HTTP ${result.status}.`,
      { code: result.status === 404 ? 'notFound' : 'internalError' }
    );
  }
  try {
    return parseJsonBody(result.body);
  } catch (cause) {
    throw new DIDResolutionError(`The DID document at "${url}" is not JSON.`, {
      code: 'internalError',
      cause
    });
  }
}

/**
 * Build a JSON-LD document loader that uses {@link securityLoader} for static
 * contexts and DID resolution, delegating http(s) remote documents to `httpGetService`.
 *
 * did:web resolution also uses `httpGetService` (the stock `securityLoader`
 * wires `DidWebResolver` to `http-client`, which bypasses caller caching), and
 * so does did:webvh resolution (the `did.jsonl` log and `did-witness.json`).
 */
export function documentLoaderFromHttpGet(
  httpGetService: HttpGetService
): DocumentLoader {
  const loader = securityLoader({ fetchRemoteContexts: true });

  const resolver = new CachedResolver();
  const didKeyDriver = didKey.driver();
  const didWebDriver = new DidWebResolver({
    fetchDocument: async ({ url }) => fetchDidWebDocument(httpGetService, url)
  });
  resolver.use(didKeyDriver);
  resolver.use(didWebDriver);
  resolver.use(didWebvhDriverWithHttpGet(httpGetService));
  didWebDriver.use({
    multibaseMultikeyHeader: 'z6Mk',
    fromMultibase: Ed25519VerificationKey.from
  });
  // Register the standard did:key suites (Ed25519 + ECDSA P-256/P-384/P-521) via
  // the shared helper so this driver stays in sync with `securityLoader`'s own.
  // Without the ECDSA headers, resolving an ecdsa did:key verification method
  // (e.g. an `ecdsa-rdfc-2019` proof) throws `Unsupported multibaseMultikeyHeader`.
  registerDefaultDidKeyHeaders(didKeyDriver);
  loader.setDidResolver(resolver);

  const handler = {
    async get(params: Record<string, string>) {
      const url = params.url;
      if (!url.startsWith('http')) {
        throw new Error('NotFoundError');
      }
      try {
        const { body, status } = await httpGetService.get(url);
        if (status < 200 || status >= 300) {
          throw new Error(`HTTP ${status}`);
        }
        // `@interop/security-document-loader` (jsonld-document-loader >= 2)
        // expects a protocol handler to return the bare document and wraps it
        // in `{ contextUrl, document, documentUrl }` itself. Returning the
        // wrapper here would double-nest it (`document.document`).
        //
        // A string body that is not JSON throws inside this try and surfaces
        // as a url-bearing NotFoundError.
        return parseJsonBody(body);
      } catch (e) {
        const msg = errorMessage(e, 'non-Error value thrown');
        throw new Error(`NotFoundError loading "${url}": ${msg}`, { cause: e });
      }
    }
  };
  loader.setProtocolHandler({ protocol: 'http', handler });
  loader.setProtocolHandler({ protocol: 'https', handler });
  return loader.build();
}
