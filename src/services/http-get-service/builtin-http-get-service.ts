import type { HttpGetResult } from '../../types/http.js';
import type { HttpGetService } from './http-get-service.js';

/**
 * `fetch`-based {@link HttpGetService}.
 *
 * Returns the parsed JSON document as `body`. Most consumers (the JSON-LD
 * document loader, the did:web driver, registry fetches) treat `body` as an
 * already-parsed object, so this adapter normalizes accordingly: it parses on a
 * JSON Content-Type and also attempts to parse a string body when a host serves
 * JSON-LD as `text/plain` (e.g. raw.githubusercontent.com status lists),
 * falling back to the raw text only if parsing fails. Status and headers are
 * returned for the caller to handle non-2xx responses.
 */
export function BuiltinHttpGetService(): HttpGetService {
  return {
    async get(url: string): Promise<HttpGetResult> {
      const response = await fetch(url);
      const contentType = response.headers.get('content-type') ?? '';

      let body: unknown;
      if (/json/i.test(contentType)) {
        try {
          body = await response.json();
        } catch {
          body = await response.text();
        }
      } else {
        const text = await response.text();
        try {
          body = JSON.parse(text);
        } catch {
          body = text;
        }
      }

      return { body, headers: response.headers, status: response.status };
    }
  };
}

export type BuiltinHttpGetServiceType = ReturnType<
  typeof BuiltinHttpGetService
>;
