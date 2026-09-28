import type { HttpGetResult } from '../../types/http.js';
import type { HttpGetService } from './http-get-service.js';

/**
 * `fetch`-based {@link HttpGetService}.
 *
 * Returns the parsed JSON document as `body`. Most consumers (the JSON-LD
 * document loader, the did:web driver, registry fetches) treat `body` as an
 * already-parsed object, so this adapter normalizes accordingly: it parses the
 * body as JSON whatever the Content-Type (a host may serve JSON-LD as
 * `text/plain`, e.g. raw.githubusercontent.com status lists), falling back to
 * the raw text when parsing fails (e.g. a JSON Lines did:webvh log). Status
 * and headers are returned for the caller to handle non-2xx responses.
 */
export function BuiltinHttpGetService(): HttpGetService {
  return {
    async get(url: string): Promise<HttpGetResult> {
      const response = await fetch(url);
      // Read the body once: a stream cannot be consumed twice, so a
      // `json()` call cannot fall back to `text()`.
      const text = await response.text();
      let body: unknown;
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }

      return { body, headers: response.headers, status: response.status };
    }
  };
}

export type BuiltinHttpGetServiceType = ReturnType<
  typeof BuiltinHttpGetService
>;
