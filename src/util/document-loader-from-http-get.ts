import { securityLoader } from '@digitalcredentials/security-document-loader';
import { CachedResolver } from '@digitalcredentials/did-io';
import * as didKey from '@digitalcredentials/did-method-key';
import * as Ed25519Multikey from '@digitalcredentials/ed25519-multikey';
import type { DocumentLoader } from '../types/context.js';
import type { HttpGetService } from '../services/http-get-service/http-get-service.js';
import { didWebDriverWithHttpGet } from './did-web-driver-with-http-get.js';

/**
 * Build a JSON-LD document loader that uses {@link securityLoader} for static
 * contexts and DID resolution, delegating http(s) remote documents to `httpGetService`.
 *
 * did:web resolution also uses `httpGetService` (stock `securityLoader` wires
 * `DidWebDriver` to `http-client`, which bypasses caller caching).
 */
export function documentLoaderFromHttpGet(
  httpGetService: HttpGetService
): DocumentLoader {
  const loader = securityLoader({ fetchRemoteContexts: true });

  const resolver = new CachedResolver();
  const didKeyDriver = didKey.driver();
  const didWebDriver = didWebDriverWithHttpGet(httpGetService);
  resolver.use(didKeyDriver);
  resolver.use(didWebDriver);
  didWebDriver.use({
    multibaseMultikeyHeader: 'z6Mk',
    fromMultibase: Ed25519Multikey.from
  });
  didKeyDriver.use({
    multibaseMultikeyHeader: 'z6Mk',
    fromMultibase: Ed25519Multikey.from
  });
  loader.setDidResolver(resolver);

  const handler = {
    async get(params: Record<string, string>) {
      const url = params.url;
      if (!url.startsWith('http')) {
        throw new Error('NotFoundError');
      }
      try {
        const { body, status } = await httpGetService.get(url);
        if (status < 200 || status >= 300) {
          throw new Error(`HTTP ${status}`);
        }
        return {
          contextUrl: null,
          document: body,
          documentUrl: url
        };
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        throw new Error(`NotFoundError loading "${url}": ${msg}`, { cause: e });
      }
    }
  };
  loader.setProtocolHandler({ protocol: 'http', handler });
  loader.setProtocolHandler({ protocol: 'https', handler });
  return loader.build() as DocumentLoader;
}
