import type { CacheService } from '../../../src/services/cache-service/cache-service.js';

/**
 * Fake {@link CacheService} for tests.
 *
 * TTL is ignored — entries never expire in-process.
 * Useful for testing caching behavior without time manipulation.
 */
export function FakeCacheService(): CacheService {
  const map = new Map<string, unknown>();

  return {
    async get(key: string) {
      return map.get(key);
    },

    async set(key: string, value: unknown) {
      map.set(key, value);
    }
  };
}

export type FakeCacheService = ReturnType<typeof FakeCacheService>;

/**
 * A {@link FakeCacheService} that also records every `set` call, for
 * asserting on cache keys, values and TTLs.
 */
export function FakeCacheServiceWithSetLog(): {
  cache: CacheService;
  sets: Array<{ key: string; value: unknown; ttl?: number }>;
} {
  const base = FakeCacheService();
  const sets: Array<{ key: string; value: unknown; ttl?: number }> = [];
  return {
    cache: {
      get: base.get.bind(base),
      set: async (key: string, value: unknown, ttl?: number) => {
        sets.push({ key, value, ttl });
        return base.set(key, value, ttl);
      }
    },
    sets
  };
}
