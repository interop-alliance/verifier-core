import type { CacheService } from '../../services/cache-service/cache-service.js';
import type { FetchJson } from '../../types/context.js';
import { isPlainObject } from '../../util/json-shape.js';

/**
 * TTL for a cached schema document (24 hours). {@link FetchJson} drops
 * response headers, so a fixed TTL stands in for `Cache-Control`.
 */
export const SCHEMA_TTL_MS = 24 * 60 * 60 * 1000;

/** `cacheService` key for a schema document; the cache is shared with registry data. */
export const schemaCacheKey = (url: string): string => `schema:${url}`;

async function fetchSchema(
  fetchJson: FetchJson,
  url: string
): Promise<Record<string, unknown>> {
  const doc = await fetchJson(url);
  if (!isPlainObject(doc)) {
    throw new Error(`Expected JSON object schema at ${url}`);
  }
  return doc;
}

/**
 * Build an AJV `loadSchema` that caches schema JSON in `cacheService`.
 *
 * AJV calls the loader for the root schema and for every `$ref` it follows.
 * Only URLs accepted by `isCacheable` are cached, so an issuer-chosen
 * `credentialSchema` URL cannot grow the cache. A document is stored, or
 * trusted from the cache, only when its `$id` is the requested URL; a hit
 * that fails that test is a miss and is overwritten by the next good fetch.
 */
export function createCachedSchemaLoader(
  fetchJson: FetchJson,
  cacheService: CacheService | undefined,
  isCacheable: (url: string) => boolean
): (url: string) => Promise<object> {
  return async (url: string): Promise<object> => {
    if (!cacheService || !isCacheable(url)) {
      return fetchSchema(fetchJson, url);
    }

    const hit = await cacheService.get(schemaCacheKey(url));
    if (isPlainObject(hit) && hit.$id === url) {
      return hit;
    }

    const doc = await fetchSchema(fetchJson, url);
    if (doc.$id === url) {
      await cacheService.set(schemaCacheKey(url), doc, SCHEMA_TTL_MS);
    }
    return doc;
  };
}
