import { beforeAll, beforeEach, describe, it, expect } from 'vitest';
import type { EntityIdentityRegistry } from '../../../src/types/registry.js';
import type { HttpGetResult } from '../../../src/types/http.js';
import type { TimeService } from '../../../src/services/time-service/time-service.js';
import { DEFAULT_TTL_MS } from '../../../src/services/registry-handlers/cache-ttl.js';
import { lookupOidf } from '../../../src/services/registry-handlers/oidf-handler.js';
import type { RegistryHandlerContext } from '../../../src/services/registry-handlers/types.js';
import {
  FakeCacheService,
  FakeCacheServiceWithSetLog
} from '../../factories/services/fake-cache-service.js';
import { buildHandlerContext } from '../../factories/services/build-handler-context.js';
import {
  FakeHttpGetService,
  httpGetResult,
  okJsonBody
} from '../../factories/services/fake-http-get-service.js';
import {
  ONE_DAY_SECONDS,
  encodeJson,
  entityConfigurationPayload,
  epochSeconds,
  generateSigningKey,
  jwkSet,
  signJws,
  subordinateStatementPayload,
  type TestSigningKey
} from '../../factories/oidf/sign-entity-statement.js';

/**
 * A settable clock. The handler reads "now" from the context's
 * `TimeService`, so `exp` handling is tested by moving this clock, not by
 * faking `Date`.
 */
function clock(startMs = new Date('2026-06-01T12:00:00.250Z').getTime()) {
  let nowMs = startMs;
  const timeService: TimeService = {
    dateNowMs: () => nowMs,
    performanceNowMs: () => 0
  };
  return {
    timeService,
    now: () => nowMs,
    advance: (ms: number) => {
      nowMs += ms;
    },
    /** Seconds since the epoch at the clock's "now", offset by `delta`. */
    seconds: (delta = 0) => epochSeconds(delta, nowMs)
  };
}

const ecUrl = 'https://ta.example/.well-known/openid-federation';
const entityId = 'https://ta.example';
const fetchEndpoint = 'https://op.example/federation-fetch';
const did = 'did:key:abc';

function lookupUrlFor(sub: string, endpoint = fetchEndpoint): string {
  const url = new URL(endpoint);
  url.searchParams.set('sub', sub);
  return url.href;
}

const lookupUrl = lookupUrlFor(did);

const oidfRegistry: EntityIdentityRegistry = {
  name: 'OIDF Test',
  type: 'oidf',
  trustAnchorEC: ecUrl
};

const found = { status: 'found' };
const unchecked = { status: 'unchecked' };

/** A 200 serving a JWT, as `BuiltinHttpGetService` returns entity statements. */
const jwtResult = (jwt: string, headers = new Headers()): HttpGetResult =>
  httpGetResult(200, jwt, headers);

describe('lookupOidf', () => {
  let anchorKey: TestSigningKey;
  let otherKey: TestSigningKey;
  let time: ReturnType<typeof clock>;

  beforeAll(async () => {
    anchorKey = await generateSigningKey('ES256', 'anchor-key');
    otherKey = await generateSigningKey('ES256', 'other-key');
  });

  function buildCtx(
    overrides: Partial<RegistryHandlerContext> = {}
  ): RegistryHandlerContext {
    return buildHandlerContext({ timeService: time.timeService, ...overrides });
  }

  /** Look up `did` in the OIDF registry with the given services. */
  function lookup(overrides: Partial<RegistryHandlerContext> = {}) {
    return lookupOidf(did, oidfRegistry, buildCtx(overrides));
  }

  /** Tweaks to a statement: payload members to merge, signing key, header. */
  type StatementOptions = {
    payload?: Record<string, unknown>;
    key?: TestSigningKey;
    header?: Record<string, unknown>;
  };

  /** Sign `base` merged with `payload`, by `key` (the anchor's by default). */
  function signStatement(
    base: Record<string, unknown>,
    { payload = {}, key = anchorKey, header }: StatementOptions
  ): Promise<string> {
    return signJws({ key, header, payload: { ...base, ...payload } });
  }

  /** The trust anchor's entity configuration, signed by its own key. */
  function entityConfigurationJwt(options: StatementOptions = {}) {
    return signStatement(
      entityConfigurationPayload({
        entityId,
        jwks: jwkSet(anchorKey),
        fetchEndpoint,
        exp: time.seconds(ONE_DAY_SECONDS)
      }),
      options
    );
  }

  /** A subordinate statement about `did`, signed by the anchor's key. */
  function subordinateJwt(options: StatementOptions = {}) {
    return signStatement(
      subordinateStatementPayload({
        entityId,
        did,
        exp: time.seconds(ONE_DAY_SECONDS)
      }),
      options
    );
  }

  async function registryServing(
    subordinate: HttpGetResult,
    entityConfiguration?: HttpGetResult
  ) {
    return FakeHttpGetService({
      [ecUrl]: entityConfiguration ?? jwtResult(await entityConfigurationJwt()),
      [lookupUrl]: subordinate
    });
  }

  // A fresh clock per test; `beforeAll` keys are reused across clocks.
  beforeEach(() => {
    time = clock();
  });

  it('caches entity config JWT (single EC fetch across two lookups)', async () => {
    const httpGetService = await registryServing(
      jwtResult(
        await subordinateJwt(),
        new Headers({ 'cache-control': 'max-age=30' })
      )
    );
    const cache = FakeCacheService();
    await lookup({ httpGetService, cacheService: cache });
    await lookup({ httpGetService, cacheService: cache });
    expect(httpGetService.callsTo(ecUrl)).toBe(1);
  });

  it('returns found when federation fetch returns a verified statement', async () => {
    const httpGetService = await registryServing(
      jwtResult(await subordinateJwt())
    );
    expect(await lookup({ httpGetService })).toEqual(found);
  });

  it('returns not-found on 404 and does not cache lookup', async () => {
    const httpGetService = await registryServing(
      httpGetResult(404, '', new Headers())
    );
    const cache = FakeCacheService();
    expect(await lookup({ httpGetService, cacheService: cache })).toEqual({
      status: 'not-found'
    });
    expect(await cache.get(`oidf:lookup:${lookupUrl}`)).toBeUndefined();
  });

  it('returns unchecked on federation non-404 error', async () => {
    const httpGetService = await registryServing(httpGetResult(503, ''));
    expect(await lookup({ httpGetService })).toEqual(unchecked);
  });

  it('returns unchecked when EC fetch throws', async () => {
    expect(await lookup()).toEqual(unchecked);
  });

  it('respects Cache-Control max-age on DID lookup cache set', async () => {
    const httpGetService = await registryServing(
      jwtResult(
        await subordinateJwt(),
        new Headers({ 'cache-control': 'max-age=45' })
      )
    );
    const { cache, sets } = FakeCacheServiceWithSetLog();
    await lookup({ httpGetService, cacheService: cache });
    const lookupSet = sets.find(s => s.key.startsWith('oidf:lookup:'));
    expect(lookupSet?.ttl).toBe(45_000);
  });

  it('caches DID lookup result and skips second federation fetch', async () => {
    const httpGetService = await registryServing(
      jwtResult(await subordinateJwt())
    );
    const cache = FakeCacheService();
    await lookup({ httpGetService, cacheService: cache });
    const second = await lookup({ httpGetService, cacheService: cache });
    expect(second).toEqual(found);
    expect(httpGetService.callsTo(lookupUrl)).toBe(1);
  });

  it('caches only the raw JWTs, never a verdict', async () => {
    const subordinate = await subordinateJwt();
    const ec = await entityConfigurationJwt();
    const httpGetService = await registryServing(
      jwtResult(subordinate),
      jwtResult(ec)
    );
    const { cache, sets } = FakeCacheServiceWithSetLog();
    await lookup({ httpGetService, cacheService: cache });
    expect(sets.map(s => [s.key, s.value])).toEqual([
      [`oidf:ec:${ecUrl}`, ec],
      [`oidf:lookup:${lookupUrl}`, subordinate]
    ]);
  });

  it('uses default TTL for entity config when no Cache-Control', async () => {
    const httpGetService = await registryServing(
      jwtResult(await subordinateJwt())
    );
    const { cache, sets } = FakeCacheServiceWithSetLog();
    await lookup({ httpGetService, cacheService: cache });
    // The statement expires in a day, so the one-hour default is the minimum.
    const ecSet = sets.find(s => s.key.startsWith('oidf:ec:'));
    expect(ecSet?.ttl).toBe(DEFAULT_TTL_MS);
  });

  it('returns unchecked when registry type is not oidf', async () => {
    const dcc: EntityIdentityRegistry = {
      name: 'Legacy',
      type: 'dcc-legacy',
      url: 'https://example.com/r.json'
    };
    const httpGetService = FakeHttpGetService(
      {},
      { fallback: { get: async () => okJsonBody({}) } }
    );
    const result = await lookupOidf(
      'did:key:x',
      dcc,
      buildCtx({ httpGetService })
    );
    expect(result).toEqual({
      status: 'unchecked'
    });
    expect(httpGetService.allCalls()).toEqual([]);
  });

  it('accepts a signed subordinate statement without metadata', async () => {
    // OIDF subordinate statements need only speak about `sub`.
    const httpGetService = await registryServing(
      jwtResult(await subordinateJwt({ payload: { metadata: undefined } }))
    );
    expect(await lookup({ httpGetService })).toEqual(found);
  });

  it('accepts statements served with a trailing newline', async () => {
    const httpGetService = await registryServing(
      jwtResult(`${await subordinateJwt()}\n`),
      jwtResult(`${await entityConfigurationJwt()}\r\n`)
    );
    expect(await lookup({ httpGetService })).toEqual(found);
  });

  describe('header typ and crit', () => {
    it.each<[string, StatementOptions]>([
      ['whose typ is not entity-statement+jwt', { header: { typ: 'JWT' } }],
      ['without a typ', { header: { typ: undefined } }],
      ['with a crit header', { header: { crit: ['exp'], exp: 1 } }]
    ])('rejects a subordinate statement %s', async (_label, options) => {
      const httpGetService = await registryServing(
        jwtResult(await subordinateJwt(options))
      );
      expect(await lookup({ httpGetService })).toEqual(unchecked);
    });

    it('rejects an entity configuration whose typ is not entity-statement+jwt', async () => {
      const httpGetService = await registryServing(
        jwtResult(await subordinateJwt()),
        jwtResult(await entityConfigurationJwt({ header: { typ: 'JWT' } }))
      );
      expect(await lookup({ httpGetService })).toEqual(unchecked);
    });
  });

  describe('forged or invalid statements', () => {
    it('rejects an unsigned subordinate statement', async () => {
      // The pre-fix handler accepted exactly this: any JWT with metadata.
      const forged = `${encodeJson({ alg: 'ES256', kid: 'anchor-key' })}.${encodeJson(
        subordinateStatementPayload({
          entityId,
          did,
          exp: time.seconds(ONE_DAY_SECONDS)
        })
      )}.c2ln`;
      const cache = FakeCacheService();
      const httpGetService = await registryServing(jwtResult(forged));
      expect(await lookup({ httpGetService, cacheService: cache })).toEqual(
        unchecked
      );
      expect(await cache.get(`oidf:lookup:${lookupUrl}`)).toBeUndefined();
    });

    it('rejects a subordinate statement signed by another key', async () => {
      const httpGetService = await registryServing(
        jwtResult(await subordinateJwt({ key: otherKey }))
      );
      expect(await lookup({ httpGetService })).toEqual(unchecked);
    });

    it.each<[string, () => StatementOptions]>([
      ['does not verify against its own jwks', () => ({ key: otherKey })],
      ['has an unsupported alg', () => ({ header: { alg: 'RS256' } })],
      ['has iss !== sub', () => ({ payload: { iss: 'https://evil.example' } })],
      ['has no jwks', () => ({ payload: { jwks: undefined } })],
      ['has expired', () => ({ payload: { exp: time.seconds(-60) } })],
      [
        'has no fetch endpoint',
        () => ({ payload: { metadata: { federation_entity: {} } } })
      ]
    ])(
      'rejects an entity configuration that %s, without calling the fetch endpoint',
      async (_label, options) => {
        const httpGetService = await registryServing(
          jwtResult(await subordinateJwt()),
          jwtResult(await entityConfigurationJwt(options()))
        );
        expect(await lookup({ httpGetService })).toEqual(unchecked);
        expect(httpGetService.callsTo(lookupUrl)).toBe(0);
      }
    );

    it.each([
      ['the wrong iss', () => ({ iss: 'https://other-anchor.example' })],
      ['the wrong sub', () => ({ sub: 'did:key:someone-else' })],
      ['an expired exp', () => ({ exp: time.seconds(-60) })],
      [
        'an expired digit-string exp',
        () => ({ exp: String(time.seconds(-60)) })
      ],
      ['a non-numeric string exp', () => ({ exp: 'tomorrow' })],
      ['no exp', () => ({ exp: undefined })]
    ])('rejects a subordinate statement with %s', async (_label, payload) => {
      const httpGetService = await registryServing(
        jwtResult(await subordinateJwt({ payload: payload() }))
      );
      expect(await lookup({ httpGetService })).toEqual(unchecked);
    });

    it('accepts exp as a digit string, as OpenSALT signs it', async () => {
      const exp = String(time.seconds(ONE_DAY_SECONDS));
      const httpGetService = await registryServing(
        jwtResult(await subordinateJwt({ payload: { exp } })),
        jwtResult(await entityConfigurationJwt({ payload: { exp } }))
      );
      expect(await lookup({ httpGetService })).toEqual(found);
    });

    it('does not trust a forged statement already in the cache', async () => {
      const cache = FakeCacheService();
      await cache.set(
        `oidf:lookup:${lookupUrl}`,
        await subordinateJwt({ key: otherKey })
      );
      const httpGetService = await registryServing(
        httpGetResult(404, '', new Headers())
      );
      expect(await lookup({ httpGetService, cacheService: cache })).toEqual({
        status: 'not-found'
      });
      expect(httpGetService.callsTo(lookupUrl)).toBe(1);
    });
  });

  it('verifies the Credential Engine shape: EdDSA, did:web entity id, header kid matching no key', async () => {
    const edKey = await generateSigningKey(
      'EdDSA',
      'did:web:apps.example.org#z6Mk-test'
    );
    const edEntityId = 'did:web:apps.example.org';
    const header = { kid: 'sandbox-ta-1' };
    const exp = time.seconds(ONE_DAY_SECONDS);
    const ec = await signJws({
      key: edKey,
      header,
      payload: entityConfigurationPayload({
        entityId: edEntityId,
        jwks: jwkSet(edKey),
        fetchEndpoint,
        exp
      })
    });
    const subordinate = await signJws({
      key: edKey,
      header,
      payload: subordinateStatementPayload({ entityId: edEntityId, did, exp })
    });
    const httpGetService = await registryServing(
      jwtResult(subordinate),
      jwtResult(ec)
    );
    expect(await lookup({ httpGetService })).toEqual(found);
  });

  describe('expiry on the injected clock', () => {
    it('re-verifies a cached subordinate statement and refetches it once expired', async () => {
      const urlMap: Record<string, HttpGetResult> = {
        [ecUrl]: jwtResult(await entityConfigurationJwt()),
        [lookupUrl]: jwtResult(
          await subordinateJwt({ payload: { exp: time.seconds(120) } })
        )
      };
      const httpGetService = FakeHttpGetService(urlMap);
      const cache = FakeCacheService(); // Ignores TTL, so only `exp` can expire it.
      const ctx = buildCtx({ httpGetService, cacheService: cache });

      expect(await lookupOidf(did, oidfRegistry, ctx)).toEqual(found);
      expect(await lookupOidf(did, oidfRegistry, ctx)).toEqual(found);
      expect(httpGetService.callsTo(lookupUrl)).toBe(1);

      time.advance(121_000);
      urlMap[lookupUrl] = jwtResult(
        await subordinateJwt({ payload: { exp: time.seconds(120) } })
      );
      expect(await lookupOidf(did, oidfRegistry, ctx)).toEqual(found);
      expect(httpGetService.callsTo(lookupUrl)).toBe(2);
    });

    it('never serves a cached statement past its exp', async () => {
      const httpGetService = await registryServing(
        jwtResult(await subordinateJwt({ payload: { exp: time.seconds(120) } }))
      );
      const ctx = buildCtx({
        httpGetService,
        cacheService: FakeCacheService()
      });

      expect(await lookupOidf(did, oidfRegistry, ctx)).toEqual(found);
      time.advance(121_000);
      // The registry still serves the now-expired statement.
      expect(await lookupOidf(did, oidfRegistry, ctx)).toEqual(unchecked);
    });

    it('refetches a cached entity configuration once expired', async () => {
      const urlMap: Record<string, HttpGetResult> = {
        [ecUrl]: jwtResult(
          await entityConfigurationJwt({
            payload: { exp: time.seconds(120) }
          })
        ),
        [lookupUrl]: jwtResult(await subordinateJwt())
      };
      const httpGetService = FakeHttpGetService(urlMap);
      const ctx = buildCtx({
        httpGetService,
        cacheService: FakeCacheService()
      });

      expect(await lookupOidf(did, oidfRegistry, ctx)).toEqual(found);
      time.advance(121_000);
      urlMap[ecUrl] = jwtResult(await entityConfigurationJwt());
      expect(await lookupOidf(did, oidfRegistry, ctx)).toEqual(found);
      expect(httpGetService.callsTo(ecUrl)).toBe(2);
    });

    it('caps cache TTLs at the statement exp when Cache-Control is longer', async () => {
      const longCache = new Headers({ 'cache-control': 'max-age=86400' });
      const httpGetService = await registryServing(
        jwtResult(
          await subordinateJwt({ payload: { exp: time.seconds(60) } }),
          longCache
        ),
        jwtResult(
          await entityConfigurationJwt({
            payload: { exp: time.seconds(300) }
          }),
          longCache
        )
      );
      const { cache, sets } = FakeCacheServiceWithSetLog();
      await lookup({ httpGetService, cacheService: cache });
      const ttlFor = (prefix: string) =>
        sets.find(s => s.key.startsWith(prefix))?.ttl;
      // The clock is frozen, so the remaining lifetime is exact (less the
      // rounding of exp down to whole seconds: the clock sits at .250 s).
      expect(ttlFor('oidf:lookup:')).toBe(60_000 - 250);
      expect(ttlFor('oidf:ec:')).toBe(300_000 - 250);
    });
  });

  it('keeps an existing query on the fetch endpoint and sets sub', async () => {
    const endpointWithQuery = 'https://op.example/fetch?x=1';
    const expectedUrl = lookupUrlFor(did, endpointWithQuery);
    expect(expectedUrl).toBe(
      'https://op.example/fetch?x=1&sub=did%3Akey%3Aabc'
    );
    const httpGetService = FakeHttpGetService({
      [ecUrl]: jwtResult(
        await entityConfigurationJwt({
          payload: {
            metadata: {
              federation_entity: {
                federation_fetch_endpoint: endpointWithQuery
              }
            }
          }
        })
      ),
      [expectedUrl]: jwtResult(await subordinateJwt())
    });
    expect(await lookup({ httpGetService })).toEqual(found);
    expect(httpGetService.allCalls()).toEqual([ecUrl, expectedUrl]);
  });

  it('returns unchecked when the fetch endpoint is not a URL', async () => {
    const httpGetService = FakeHttpGetService({
      [ecUrl]: jwtResult(
        await entityConfigurationJwt({
          payload: {
            metadata: {
              federation_entity: { federation_fetch_endpoint: 'not a url' }
            }
          }
        })
      )
    });
    expect(await lookup({ httpGetService })).toEqual(unchecked);
    expect(httpGetService.allCalls()).toEqual([ecUrl]);
  });
});
