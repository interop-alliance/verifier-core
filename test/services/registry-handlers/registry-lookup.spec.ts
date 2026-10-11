import { describe, it, expect } from 'vitest';
import type { EntityIdentityRegistry } from '../../../src/types/registry.js';
import { createRegistryLookup } from '../../../src/services/registry-lookup.js';
import type {
  RegistryHandler,
  RegistryHandlerMap
} from '../../../src/services/registry-handlers/types.js';
import {
  FakeCacheService,
  FakeCacheServiceWithSetLog
} from '../../factories/services/fake-cache-service.js';
import {
  FakeHttpGetService,
  okJsonBody
} from '../../factories/services/fake-http-get-service.js';
import { FakeVerifier } from '../../factories/services/fake-verifier.js';
import { DEFAULT_TTL_MS } from '../../../src/services/registry-handlers/cache-ttl.js';

const dccRegistry: EntityIdentityRegistry = {
  name: 'Test Legacy',
  type: 'dcc-legacy',
  url: 'https://example.com/registry.json'
};

/**
 * A handler map with the given handlers and a not-found stub for every
 * other registry type.
 */
function handlersWith(
  overrides: Partial<RegistryHandlerMap>
): RegistryHandlerMap {
  const notFound: RegistryHandler = async () => ({ status: 'not-found' });
  return {
    'dcc-legacy': notFound,
    oidf: notFound,
    'vc-recognition': notFound,
    ...overrides
  };
}

describe('createRegistryLookup', () => {
  it('aggregates found and not-found across registries', async () => {
    const handlers = handlersWith({
      'dcc-legacy': async () => ({
        status: 'found'
      })
    });
    const lookup = createRegistryLookup(
      FakeHttpGetService({ 'https://x.test/': okJsonBody({}) }),
      FakeCacheService(),
      handlers
    );
    const result = await lookup('did:key:test', [dccRegistry]);
    expect(result.found).toBe(true);
    expect(result.matches).toEqual([
      {
        registry: {
          name: 'Test Legacy',
          type: 'dcc-legacy',
          url: 'https://example.com/registry.json'
        }
      }
    ]);
    expect(result.uncheckedRegistries).toEqual([]);
  });

  it('passes a handler entity through to the match', async () => {
    const handlers = handlersWith({
      'dcc-legacy': async () => ({
        status: 'found',
        entity: { name: 'Example University', url: 'https://example.edu' }
      })
    });
    const lookup = createRegistryLookup(
      FakeHttpGetService({}),
      FakeCacheService(),
      handlers
    );
    const result = await lookup('did:key:test', [dccRegistry]);
    expect(result.matches[0].entity).toEqual({
      name: 'Example University',
      url: 'https://example.edu'
    });
  });

  it('names an oidf registry by its trust anchor entity configuration', async () => {
    const oidf: EntityIdentityRegistry = {
      name: 'Test OIDF',
      type: 'oidf',
      trustAnchorEC: 'https://ta.example/.well-known/openid-federation'
    };
    const handlers = handlersWith({
      oidf: async () => ({
        status: 'found'
      })
    });
    const lookup = createRegistryLookup(
      FakeHttpGetService({}),
      FakeCacheService(),
      handlers
    );
    const result = await lookup('did:key:test', [oidf]);
    expect(result.matches[0].registry).toEqual({
      name: 'Test OIDF',
      type: 'oidf',
      url: 'https://ta.example/.well-known/openid-federation'
    });
  });

  it('collects unchecked registry names', async () => {
    const handlers = handlersWith({
      'dcc-legacy': async () => ({
        status: 'unchecked'
      })
    });
    const lookup = createRegistryLookup(
      FakeHttpGetService({ 'https://x.test/': okJsonBody({}) }),
      FakeCacheService(),
      handlers
    );
    const result = await lookup('did:key:x', [dccRegistry]);
    expect(result.found).toBe(false);
    expect(result.matches).toEqual([]);
    expect(result.uncheckedRegistries).toEqual([
      {
        name: 'Test Legacy',
        type: 'dcc-legacy',
        url: 'https://example.com/registry.json'
      }
    ]);
  });

  it('iterates multiple registries with exhaustive mode', async () => {
    const second: EntityIdentityRegistry = {
      name: 'Other',
      type: 'dcc-legacy',
      url: 'https://example.com/other.json'
    };
    const handlers = handlersWith({
      'dcc-legacy': async did =>
        did === 'did:key:a' ? { status: 'found' } : { status: 'not-found' }
    });
    const lookup = createRegistryLookup(
      FakeHttpGetService({ 'https://x.test/': okJsonBody({}) }),
      FakeCacheService(),
      handlers
    );
    const result = await lookup('did:key:a', [dccRegistry, second], {
      exhaustive: true
    });
    expect(result.found).toBe(true);
    expect(result.matches.map(match => match.registry.name)).toEqual([
      'Test Legacy',
      'Other'
    ]);
  });

  describe('caching', () => {
    const oidfRegistry: EntityIdentityRegistry = {
      name: 'Test OIDF',
      type: 'oidf',
      trustAnchorEC: 'https://ta.example/.well-known/openid-federation'
    };

    it('caches a result with an unchecked registry for 60 s', async () => {
      const handlers = handlersWith({
        oidf: async () => ({
          status: 'unchecked'
        })
      });
      const { cache, sets } = FakeCacheServiceWithSetLog();
      const lookup = createRegistryLookup(
        FakeHttpGetService({}),
        cache,
        handlers
      );
      const result = await lookup('did:key:a', [dccRegistry, oidfRegistry]);
      expect(result.uncheckedRegistries).toEqual([
        {
          name: 'Test OIDF',
          type: 'oidf',
          url: 'https://ta.example/.well-known/openid-federation'
        }
      ]);
      expect(sets).toMatchObject([
        { key: expect.stringMatching(/^reg-result:2:/), ttl: 60_000 }
      ]);
    });

    it('caches a complete result for the default TTL', async () => {
      const handlers = handlersWith({});
      const { cache, sets } = FakeCacheServiceWithSetLog();
      const lookup = createRegistryLookup(
        FakeHttpGetService({}),
        cache,
        handlers
      );
      await lookup('did:key:a', [dccRegistry, oidfRegistry]);
      expect(sets).toMatchObject([
        { key: expect.stringMatching(/^reg-result:2:/), ttl: DEFAULT_TTL_MS }
      ]);
    });

    it('returns a copy, so mutating a result does not alter the cache', async () => {
      const handlers = handlersWith({
        'dcc-legacy': async () => ({
          status: 'found',
          entity: { name: 'Org', raw: { name: 'Org' } }
        })
      });
      const lookup = createRegistryLookup(
        FakeHttpGetService({}),
        FakeCacheService(),
        handlers
      );
      const first = await lookup('did:key:a', [dccRegistry]);
      first.matches[0].entity!.name = 'Tampered';
      first.uncheckedRegistries.push({
        name: 'Bogus',
        type: 'oidf',
        url: 'https://bogus.test/ec'
      });

      const second = await lookup('did:key:a', [dccRegistry]);
      expect(second.matches[0].entity).toEqual({
        name: 'Org',
        raw: { name: 'Org' }
      });
      expect(second.uncheckedRegistries).toEqual([]);
      expect(second).not.toBe(first);
    });

    it('threads the given timeService to handlers', async () => {
      let seen: number | undefined;
      const handlers = handlersWith({
        'dcc-legacy': async (_did, _registry, ctx) => {
          seen = ctx.timeService.dateNowMs();
          return { status: 'not-found' };
        }
      });
      const lookup = createRegistryLookup(
        FakeHttpGetService({}),
        FakeCacheService(),
        handlers,
        undefined,
        { dateNowMs: () => 1234, performanceNowMs: () => 0 }
      );
      await lookup('did:key:a', [dccRegistry]);
      expect(seen).toBe(1234);
    });

    it('caches result for same DID and registries', async () => {
      let handlerCallCount = 0;
      const handlers = handlersWith({
        'dcc-legacy': async () => {
          handlerCallCount++;
          return { status: 'found' };
        }
      });
      const cache = FakeCacheService();
      const lookup = createRegistryLookup(
        FakeHttpGetService({}),
        cache,
        handlers
      );

      // First lookup
      await lookup('did:key:test', [dccRegistry]);
      expect(handlerCallCount).toBe(1);

      // Second lookup should hit cache
      await lookup('did:key:test', [dccRegistry]);
      expect(handlerCallCount).toBe(1); // Not called again
    });

    it('different DID triggers new lookup', async () => {
      let handlerCallCount = 0;
      const handlers = handlersWith({
        'dcc-legacy': async () => {
          handlerCallCount++;
          return { status: 'found' };
        }
      });
      const lookup = createRegistryLookup(
        FakeHttpGetService({}),
        FakeCacheService(),
        handlers
      );

      await lookup('did:key:first', [dccRegistry]);
      await lookup('did:key:second', [dccRegistry]);
      expect(handlerCallCount).toBe(2);
    });

    it('different registries trigger new lookup', async () => {
      let handlerCallCount = 0;
      const handlers = handlersWith({
        'dcc-legacy': async () => {
          handlerCallCount++;
          return { status: 'found' };
        }
      });
      const lookup = createRegistryLookup(
        FakeHttpGetService({}),
        FakeCacheService(),
        handlers
      );

      const registry1: EntityIdentityRegistry = {
        ...dccRegistry,
        url: 'https://a.com'
      };
      const registry2: EntityIdentityRegistry = {
        ...dccRegistry,
        url: 'https://b.com'
      };

      await lookup('did:key:same', [registry1]);
      await lookup('did:key:same', [registry2]);
      expect(handlerCallCount).toBe(2);
    });

    it('same registries in different order share cache key', async () => {
      let handlerCallCount = 0;
      const handlers = handlersWith({
        'dcc-legacy': async () => {
          handlerCallCount++;
          return { status: 'found' };
        }
      });
      const cache = FakeCacheService();
      const lookup = createRegistryLookup(
        FakeHttpGetService({}),
        cache,
        handlers
      );

      const reg1: EntityIdentityRegistry = {
        ...dccRegistry,
        name: 'Reg1',
        url: 'https://a.com'
      };
      const reg2: EntityIdentityRegistry = {
        ...dccRegistry,
        name: 'Reg2',
        url: 'https://b.com'
      };

      await lookup('did:key:same', [reg1, reg2]);
      await lookup('did:key:same', [reg2, reg1]); // Different order
      expect(handlerCallCount).toBe(1); // Cache hit
    });
  });

  describe('short-circuit', () => {
    it('stops after first found by default', async () => {
      let handlerCallCount = 0;
      const handlers = handlersWith({
        'dcc-legacy': async () => {
          handlerCallCount++;
          return { status: 'found' };
        },
        oidf: async () => {
          handlerCallCount++;
          return { status: 'found' };
        },
        'vc-recognition': async () => {
          handlerCallCount++;
          return { status: 'found' };
        }
      });

      const registries: EntityIdentityRegistry[] = [
        { name: 'First', type: 'dcc-legacy', url: 'https://first.com' },
        { name: 'Second', type: 'oidf', trustAnchorEC: 'https://second.com' },
        {
          name: 'Third',
          type: 'vc-recognition',
          url: 'https://third.com',
          acceptedIssuers: []
        }
      ];

      const lookup = createRegistryLookup(
        FakeHttpGetService({}),
        FakeCacheService(),
        handlers
      );

      await lookup('did:key:test', registries);
      expect(handlerCallCount).toBe(1); // Only first called
    });

    it('checks all registries when exhaustive: true', async () => {
      let handlerCallCount = 0;
      const handlers = handlersWith({
        'dcc-legacy': async () => {
          handlerCallCount++;
          return { status: 'found' };
        },
        oidf: async () => {
          handlerCallCount++;
          return { status: 'found' };
        },
        'vc-recognition': async () => {
          handlerCallCount++;
          return { status: 'found' };
        }
      });

      const registries: EntityIdentityRegistry[] = [
        { name: 'First', type: 'dcc-legacy', url: 'https://first.com' },
        { name: 'Second', type: 'oidf', trustAnchorEC: 'https://second.com' },
        {
          name: 'Third',
          type: 'vc-recognition',
          url: 'https://third.com',
          acceptedIssuers: []
        }
      ];

      const lookup = createRegistryLookup(
        FakeHttpGetService({}),
        FakeCacheService(),
        handlers
      );

      const result = await lookup('did:key:test', registries, {
        exhaustive: true
      });
      expect(handlerCallCount).toBe(3); // All called
      expect(result.matches.map(match => match.registry.name)).toEqual([
        'First',
        'Second',
        'Third'
      ]);
    });
  });

  describe('fresh lookup', () => {
    it('bypasses cache when fresh: true', async () => {
      let handlerCallCount = 0;
      const handlers = handlersWith({
        'dcc-legacy': async () => {
          handlerCallCount++;
          return { status: 'found' };
        }
      });
      const cache = FakeCacheService();
      const lookup = createRegistryLookup(
        FakeHttpGetService({}),
        cache,
        handlers
      );

      // First lookup (cache miss)
      await lookup('did:key:test', [dccRegistry]);
      expect(handlerCallCount).toBe(1);

      // Second lookup without fresh (cache hit)
      await lookup('did:key:test', [dccRegistry]);
      expect(handlerCallCount).toBe(1);

      // Third lookup with fresh (cache bypass)
      await lookup('did:key:test', [dccRegistry], { fresh: true });
      expect(handlerCallCount).toBe(2);
    });

    it('caches result after fresh lookup', async () => {
      let handlerCallCount = 0;
      const handlers = handlersWith({
        'dcc-legacy': async () => {
          handlerCallCount++;
          return { status: 'found' };
        }
      });
      const cache = FakeCacheService();
      const lookup = createRegistryLookup(
        FakeHttpGetService({}),
        cache,
        handlers
      );

      // Fresh lookup
      await lookup('did:key:test', [dccRegistry], { fresh: true });
      expect(handlerCallCount).toBe(1);

      // Non-fresh should use cached result
      await lookup('did:key:test', [dccRegistry]);
      expect(handlerCallCount).toBe(1);
    });
  });

  describe('verifier threading', () => {
    it('passes the provided verifier through to handler context', async () => {
      const fakeVerifier = FakeVerifier();
      let receivedVerifier: unknown;
      const captureHandler: RegistryHandler = async (_did, registry, ctx) => {
        receivedVerifier = ctx.verifier;
        return { status: 'found' };
      };
      const handlers = handlersWith({
        'dcc-legacy': captureHandler
      });
      const lookup = createRegistryLookup(
        FakeHttpGetService({}),
        FakeCacheService(),
        handlers,
        () => fakeVerifier
      );
      await lookup('did:key:test', [dccRegistry]);
      expect(receivedVerifier).toBe(fakeVerifier);
    });

    it('lets dcc-legacy / oidf handlers run when no verifier is provided', async () => {
      // The handlers themselves don't touch ctx.verifier — only
      // accessing it lazily should throw.
      const handlers = handlersWith({
        'dcc-legacy': async () => ({
          status: 'found'
        })
      });
      const lookup = createRegistryLookup(
        FakeHttpGetService({}),
        FakeCacheService(),
        handlers
        // no verifier
      );
      const result = await lookup('did:key:test', [dccRegistry]);
      expect(result.found).toBe(true);
    });

    it('throws a clear error when a handler accesses ctx.verifier without one bound', async () => {
      const handlers = handlersWith({
        'dcc-legacy': async (_did, _registry, ctx) => {
          // Force access — vc-recognition does this in production.
          void ctx.verifier;
          return { status: 'not-found' };
        }
      });
      const lookup = createRegistryLookup(
        FakeHttpGetService({}),
        FakeCacheService(),
        handlers
      );
      let caught: unknown;
      try {
        await lookup('did:key:test', [dccRegistry]);
      } catch (err) {
        caught = err;
      }
      expect(caught).toBeInstanceOf(Error);
      expect((caught as Error).message).toMatch(/verifier/i);
    });
  });
});
