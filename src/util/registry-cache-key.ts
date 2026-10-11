import type { EntityIdentityRegistry } from '../types/registry.js';
import { registryUrl } from './registry-reference.js';

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
    const id: unknown[] = [registry.type, registry.name, registryUrl(registry)];
    if (registry.type === 'vc-recognition') {
      id.push([...registry.acceptedIssuers].sort());
    }
    return JSON.stringify(id);
  });

  ids.sort();
  return JSON.stringify(ids);
}
