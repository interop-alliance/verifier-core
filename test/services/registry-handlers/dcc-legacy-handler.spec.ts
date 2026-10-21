import { describe, it, expect } from 'vitest';
import type { EntityIdentityRegistry } from '../../../src/types/registry.js';
import { DEFAULT_TTL_MS } from '../../../src/services/registry-handlers/cache-ttl.js';
import { lookupDccLegacy } from '../../../src/services/registry-handlers/dcc-legacy-handler.js';
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

const registryUrl = 'https://example.com/registry.json';

const dccRegistry: EntityIdentityRegistry = {
  name: 'Sandbox',
  type: 'dcc-legacy',
  url: registryUrl
};

const sampleBody = {
  meta: { updated: '2026-01-01T00:00:00+00:00' },
  registry: {
    'did:key:found': { name: 'Found Issuer', url: 'https://issuer.example' }
  }
};

describe('lookupDccLegacy', () => {
  it('returns found when DID is in registry', async () => {
    const httpGetService = FakeHttpGetService({
      [registryUrl]: okJsonBody(sampleBody)
    });
    const result = await lookupDccLegacy(
      'did:key:found',
      dccRegistry,
      buildHandlerContext({ httpGetService })
    );
    expect(result).toEqual({
      status: 'found',
      entity: {
        name: 'Found Issuer',
        url: 'https://issuer.example',
        raw: sampleBody.registry['did:key:found']
      }
    });
  });

  it('hands out a copy of the entry, so the cached registry stays intact', async () => {
    const ctx = buildHandlerContext({
      httpGetService: FakeHttpGetService({
        [registryUrl]: okJsonBody(sampleBody)
      })
    });
    const first = await lookupDccLegacy('did:key:found', dccRegistry, ctx);
    if (first.status !== 'found' || first.entity === undefined) {
      throw new Error('expected a found result with an entity');
    }
    (first.entity.raw as Record<string, unknown>).name = 'Tampered';

    const second = await lookupDccLegacy('did:key:found', dccRegistry, ctx);
    expect(second).toEqual({
      status: 'found',
      entity: {
        name: 'Found Issuer',
        url: 'https://issuer.example',
        raw: { name: 'Found Issuer', url: 'https://issuer.example' }
      }
    });
  });

  it('returns a found result with no entity fields for a bare entry', async () => {
    const httpGetService = FakeHttpGetService({
      [registryUrl]: okJsonBody({ registry: { 'did:key:bare': {} } })
    });
    const result = await lookupDccLegacy(
      'did:key:bare',
      dccRegistry,
      buildHandlerContext({ httpGetService })
    );
    expect(result).toEqual({
      status: 'found',
      entity: { raw: {} }
    });
  });

  it.each(['__proto__', 'constructor', 'toString'])(
    'returns not-found for the inherited key %s',
    async did => {
      const httpGetService = FakeHttpGetService({
        [registryUrl]: okJsonBody(sampleBody)
      });
      const result = await lookupDccLegacy(
        did,
        dccRegistry,
        buildHandlerContext({ httpGetService })
      );
      expect(result).toEqual({ status: 'not-found' });
    }
  );

  it('returns not-found when DID is absent', async () => {
    const httpGetService = FakeHttpGetService({
      [registryUrl]: okJsonBody(sampleBody)
    });
    const result = await lookupDccLegacy(
      'did:key:missing',
      dccRegistry,
      buildHandlerContext({ httpGetService })
    );
    expect(result).toEqual({ status: 'not-found' });
  });

  it('returns unchecked when httpGetService.get throws', async () => {
    const httpGetService = {
      async get() {
        throw new Error('network');
      }
    };
    const result = await lookupDccLegacy(
      'did:key:found',
      dccRegistry,
      buildHandlerContext({ httpGetService })
    );
    expect(result).toEqual({
      status: 'unchecked'
    });
  });

  it('returns unchecked on non-OK response', async () => {
    const httpGetService = FakeHttpGetService({
      [registryUrl]: httpGetResult(503, '')
    });
    const result = await lookupDccLegacy(
      'did:key:found',
      dccRegistry,
      buildHandlerContext({ httpGetService })
    );
    expect(result).toEqual({
      status: 'unchecked'
    });
  });

  it('returns unchecked on invalid JSON shape', async () => {
    const httpGetService = FakeHttpGetService({
      [registryUrl]: okJsonBody({ notRegistry: true })
    });
    const result = await lookupDccLegacy(
      'did:key:found',
      dccRegistry,
      buildHandlerContext({ httpGetService })
    );
    expect(result).toEqual({
      status: 'unchecked'
    });
  });

  it('uses cache on second lookup (single httpGet)', async () => {
    let calls = 0;
    const httpGetService = {
      async get(url: string) {
        calls++;
        if (url !== registryUrl) {
          throw new Error(`unexpected ${url}`);
        }
        return okJsonBody(sampleBody);
      }
    };
    const cache = FakeCacheService();
    await lookupDccLegacy(
      'did:key:found',
      dccRegistry,
      buildHandlerContext({ httpGetService, cacheService: cache })
    );
    await lookupDccLegacy(
      'did:key:found',
      dccRegistry,
      buildHandlerContext({ httpGetService, cacheService: cache })
    );
    expect(calls).toBe(1);
  });

  it('passes Cache-Control max-age to cache TTL', async () => {
    const httpGetService = FakeHttpGetService({
      [registryUrl]: {
        body: sampleBody,
        headers: new Headers({ 'cache-control': 'max-age=120' }),
        status: 200
      }
    });
    const { cache, sets } = FakeCacheServiceWithSetLog();
    await lookupDccLegacy(
      'did:key:found',
      dccRegistry,
      buildHandlerContext({ httpGetService, cacheService: cache })
    );
    expect(sets).toHaveLength(1);
    expect(sets[0].key).toBe(`dcc-legacy:${registryUrl}`);
    expect(sets[0].value).toEqual(sampleBody);
    expect(sets[0].ttl).toBe(120_000);
  });

  it('uses default TTL when Cache-Control has no max-age', async () => {
    const httpGetService = FakeHttpGetService({
      [registryUrl]: okJsonBody(sampleBody)
    });
    const { cache, sets } = FakeCacheServiceWithSetLog();
    await lookupDccLegacy(
      'did:key:found',
      dccRegistry,
      buildHandlerContext({ httpGetService, cacheService: cache })
    );
    expect(sets[0].ttl).toBe(DEFAULT_TTL_MS);
  });

  it('returns unchecked when registry type is not dcc-legacy', async () => {
    const oidf: EntityIdentityRegistry = {
      name: 'OIDF',
      type: 'oidf',
      trustAnchorEC: 'https://ta.example/.well-known/openid-federation'
    };
    let calls = 0;
    const httpGetService = {
      async get() {
        calls++;
        return okJsonBody({});
      }
    };
    const result = await lookupDccLegacy(
      'did:key:x',
      oidf,
      buildHandlerContext({ httpGetService })
    );
    expect(result).toEqual({ status: 'unchecked' });
    expect(calls).toBe(0);
  });
});
