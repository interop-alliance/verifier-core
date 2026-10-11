import type {
  EntityIdentityRegistry,
  RegistryReference
} from '../types/registry.js';

/**
 * Where a configured registry is read from: the list URL for `dcc-legacy`
 * and `vc-recognition`, and the trust anchor's entity configuration for
 * `oidf`. The one place that knows which field each type keeps it in.
 */
export function registryUrl(registry: EntityIdentityRegistry): string {
  return registry.type === 'oidf' ? registry.trustAnchorEC : registry.url;
}

/** The configured registry, as it is named in a lookup result. */
export function registryReference(
  registry: EntityIdentityRegistry
): RegistryReference {
  return {
    name: registry.name,
    type: registry.type,
    url: registryUrl(registry)
  };
}
