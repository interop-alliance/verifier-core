import { describe, it, expect } from 'vitest';
import {
  createCachedSchemaLoader,
  schemaCacheKey,
  SCHEMA_TTL_MS
} from '../../src/suites/schema/schema-loader.js';
import { fetchJsonFromHttpGet } from '../../src/util/fetch-json-from-http-get.js';
import type { CacheService } from '../../src/services/cache-service/cache-service.js';
import type { HttpGetResult } from '../../src/types/http.js';
import { FakeCacheServiceWithSetLog } from '../factories/services/fake-cache-service.js';
import {
  FakeHttpGetService,
  httpGetResult,
  okJsonBody
} from '../factories/services/fake-http-get-service.js';

const SCHEMA_URL = 'https://schemas.test/known.json';
const OTHER_URL = 'https://schemas.test/other.json';
const SCHEMA = { $id: SCHEMA_URL, type: 'object' };

const onlyKnown = (url: string): boolean => url === SCHEMA_URL;

function loaderOver(
  urlMap: Record<string, HttpGetResult>,
  cacheService: CacheService | undefined
) {
  const http = FakeHttpGetService(urlMap);
  const load = createCachedSchemaLoader(
    fetchJsonFromHttpGet(http),
    cacheService,
    onlyKnown
  );
  return { http, load };
}

describe('createCachedSchemaLoader', () => {
  it('fetches a cacheable schema once and caches it under schema:<url> for SCHEMA_TTL_MS', async () => {
    const { cache, sets } = FakeCacheServiceWithSetLog();
    const { http, load } = loaderOver(
      { [SCHEMA_URL]: okJsonBody(SCHEMA) },
      cache
    );

    expect(await load(SCHEMA_URL)).toEqual(SCHEMA);
    expect(await load(SCHEMA_URL)).toEqual(SCHEMA);

    expect(http.callsTo(SCHEMA_URL)).toBe(1);
    expect(sets).toEqual([
      { key: `schema:${SCHEMA_URL}`, value: SCHEMA, ttl: SCHEMA_TTL_MS }
    ]);
  });

  it('fetches a URL the predicate rejects every time without caching it', async () => {
    const { cache, sets } = FakeCacheServiceWithSetLog();
    const { http, load } = loaderOver(
      { [OTHER_URL]: okJsonBody({ type: 'object' }) },
      cache
    );

    await load(OTHER_URL);
    await load(OTHER_URL);

    expect(http.callsTo(OTHER_URL)).toBe(2);
    expect(sets).toEqual([]);
  });

  it('fetches every time when there is no cacheService', async () => {
    const { http, load } = loaderOver(
      { [SCHEMA_URL]: okJsonBody(SCHEMA) },
      undefined
    );

    expect(await load(SCHEMA_URL)).toEqual(SCHEMA);
    expect(await load(SCHEMA_URL)).toEqual(SCHEMA);

    expect(http.callsTo(SCHEMA_URL)).toBe(2);
  });

  it('does not cache a non-2xx response, and caches the next successful fetch', async () => {
    const { cache, sets } = FakeCacheServiceWithSetLog();
    const urlMap: Record<string, HttpGetResult> = {
      [SCHEMA_URL]: httpGetResult(404, { error: 'not found' })
    };
    const { http, load } = loaderOver(urlMap, cache);

    await expect(load(SCHEMA_URL)).rejects.toThrow('HTTP 404');
    expect(sets).toEqual([]);

    urlMap[SCHEMA_URL] = okJsonBody(SCHEMA);
    expect(await load(SCHEMA_URL)).toEqual(SCHEMA);
    expect(await load(SCHEMA_URL)).toEqual(SCHEMA);

    expect(http.callsTo(SCHEMA_URL)).toBe(2);
    expect(sets).toHaveLength(1);
  });

  it.each([
    ['null', null],
    ['an array', [SCHEMA]],
    ['a string', '{"type":"object"}']
  ])('does not cache a body that is %s', async (_label, body) => {
    const { cache, sets } = FakeCacheServiceWithSetLog();
    const { load } = loaderOver({ [SCHEMA_URL]: okJsonBody(body) }, cache);

    await expect(load(SCHEMA_URL)).rejects.toThrow(
      `Expected JSON object schema at ${SCHEMA_URL}`
    );
    expect(sets).toEqual([]);
  });

  it.each([
    ['a string', 'not a schema'],
    ['an empty object', {}],
    ['a schema with another $id', { $id: OTHER_URL, type: 'object' }]
  ])(
    'treats a cached value that is %s as a miss and replaces it',
    async (_label, stale) => {
      const { cache, sets } = FakeCacheServiceWithSetLog();
      await cache.set(schemaCacheKey(SCHEMA_URL), stale);
      sets.length = 0;
      const { http, load } = loaderOver(
        { [SCHEMA_URL]: okJsonBody(SCHEMA) },
        cache
      );

      expect(await load(SCHEMA_URL)).toEqual(SCHEMA);

      expect(http.callsTo(SCHEMA_URL)).toBe(1);
      expect(sets).toEqual([
        { key: schemaCacheKey(SCHEMA_URL), value: SCHEMA, ttl: SCHEMA_TTL_MS }
      ]);
    }
  );

  it('uses a fetched schema whose $id is not the URL, but does not cache it', async () => {
    const { cache, sets } = FakeCacheServiceWithSetLog();
    const anonymous = { type: 'object' };
    const { http, load } = loaderOver(
      { [SCHEMA_URL]: okJsonBody(anonymous) },
      cache
    );

    expect(await load(SCHEMA_URL)).toEqual(anonymous);
    expect(await load(SCHEMA_URL)).toEqual(anonymous);

    expect(http.callsTo(SCHEMA_URL)).toBe(2);
    expect(sets).toEqual([]);
  });
});
