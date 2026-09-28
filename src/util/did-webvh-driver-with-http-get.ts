/**
 * did:webvh resolution using caller-provided {@link HttpGetService}, so the
 * `did.jsonl` log and `did-witness.json` fetches share the verifier's cache
 * and any fetch wrapping the caller installed (e.g. a CORS-proxy fallback).
 *
 * Resolution, log verification (SCID, hash chain, entry proofs, witnesses)
 * and `did#fragment` dereferencing all come from
 * `@interop/did-method-webvh`'s driver. This module only adapts
 * `HttpGetService` to the fetch shape that driver accepts.
 */
import type { DidMethodDriver } from '@interop/did-io';
import { createDidWebvhDriver } from '@interop/did-method-webvh/driver';
import type { FetchLike } from '@interop/did-method-webvh';
import type { HttpGetService } from '../services/http-get-service/http-get-service.js';

/**
 * Adapts an {@link HttpGetService} to the fetch shape the did:webvh resolver
 * reads: `ok`, `status`, `text()` and `json()`.
 *
 * `did.jsonl` is JSON Lines, so an `HttpGetService` hands back either the raw
 * text (a multi-entry log is not valid JSON) or, for a single-entry log that
 * happens to parse as JSON, the parsed entry. `text()` serializes a parsed
 * body back to one JSON line. The resolver re-canonicalizes each entry before
 * hashing, so this round trip does not affect verification.
 *
 * @param httpGetService {HttpGetService}
 * @returns {FetchLike}
 */
function fetchFromHttpGet(httpGetService: HttpGetService): FetchLike {
  return async (url: string) => {
    const { body, status } = await httpGetService.get(url);
    const response = {
      ok: status >= 200 && status < 300,
      status,
      text: async () =>
        typeof body === 'string' ? body : (JSON.stringify(body) ?? ''),
      json: async () =>
        typeof body === 'string' ? (JSON.parse(body) as unknown) : body
    };
    // The resolver reads only the members above; the full `Response` class is
    // not needed (and its constructor refuses some statuses).
    return response as unknown as Response;
  };
}

/**
 * did-io driver for did:webvh that loads the DID log via `httpGetService`.
 *
 * A bare DID resolves to its verified DID document; a `did#fragment` URL
 * resolves to that node (e.g. a verification method) with an `@context`.
 * Resolution failures throw a `DIDResolutionError` carrying the resolution
 * error `code`.
 *
 * The underlying driver implements only the resolution half of did-io's
 * `DidMethodDriver` (`method`, `get`, `resolveDID`), which is all
 * `CachedResolver` calls. It has none of the key-generation members, which a
 * verifier never uses, hence the cast.
 *
 * @param httpGetService {HttpGetService}
 * @returns {DidMethodDriver}
 */
export function didWebvhDriverWithHttpGet(
  httpGetService: HttpGetService
): DidMethodDriver {
  return createDidWebvhDriver({
    fetch: fetchFromHttpGet(httpGetService)
  }) as unknown as DidMethodDriver;
}
