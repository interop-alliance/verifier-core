import type { EntityIdentityRegistry } from '../types/registry.js';

/**
 * Stable cache key for a list of registries: the sorted registry ids
 * themselves rather than a hash of them, so two different registry lists
 * can never share a key, even across tenants sharing a cache.
 *
 * The key is deterministic regardless of registry order. Each id is a
 * JSON-encoded `[type, name, url]` triple (a `vc-recognition` id also
 * carries its sorted `acceptedIssuers`, since two registries differing only
 * in accepted issuers answer differently) and the list is JSON-encoded
 * again, so no registry name or URL can contain a separator that makes one
 * list's key read as another's.
 */
export function registryCacheKey(registries: EntityIdentityRegistry[]): string {
  const ids = registries.map(registry => {
    switch (registry.type) {
      case 'dcc-legacy':
        return JSON.stringify(['dcc-legacy', registry.name, registry.url]);
      case 'oidf':
        return JSON.stringify(['oidf', registry.name, registry.trustAnchorEC]);
      case 'vc-recognition':
        return JSON.stringify([
          'vc-recognition',
          registry.name,
          registry.url,
          [...registry.acceptedIssuers].sort()
        ]);
      default:
        // Handles any future registry type; the switch is exhaustive for
        // the current union.
        return JSON.stringify([
          'unknown',
          (registry as { name?: string }).name ?? 'unnamed'
        ]);
    }
  });

  ids.sort();
  return JSON.stringify(ids);
}
