import type { HttpGetResult } from '../../types/http.js';
import type { HttpGetService } from './http-get-service.js';
import { checkUrl } from './url-policy.js';

/** Options for {@link BuiltinHttpGetService}. */
export interface BuiltinHttpGetServiceOptions {
  /** Deadline for the whole request, redirects and body included. Default 10 000. */
  timeoutMs?: number;
  /** Largest body accepted, in bytes. Default 5 MiB (5 * 1024 * 1024). */
  maxBytes?: number;
  /**
   * Allow `http:` URLs and `localhost`, loopback, private, link-local and
   * unspecified hosts. Applies to the first URL, every redirect hop and the
   * final URL. The URL must still parse. The deadline, byte cap and redirect
   * limit still apply. Default `false`.
   *
   * For local development only. Do not set it on a server that verifies
   * untrusted credentials: a credential could then make the server fetch
   * from its own network.
   */
  allowInsecure?: boolean;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_BYTES = 5 * 1024 * 1024;
export const MAX_REDIRECTS = 5;

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * `fetch`-based {@link HttpGetService} that is safe to point at URLs a
 * credential chooses.
 *
 * - Only `https:` is fetched. `localhost` and loopback, private, link-local,
 *   multicast, reserved and unspecified IP literals are refused. See
 *   `allowInsecure` for local development. On Node, every redirect hop is
 *   checked before it is requested, and at most {@link MAX_REDIRECTS} are
 *   followed. Browsers and React Native follow redirects themselves and
 *   hide the hops. There only the first URL and the final URL are checked.
 * - One deadline (`timeoutMs`) covers the whole request, body included.
 *   The body is capped at `maxBytes`.
 * - The body is read once and parsed as JSON whatever the content type. If
 *   it is not JSON, the text is returned.
 * - Errors carry fixed text naming the URL and the reason. They never carry
 *   response bytes, parser output or the underlying network error, because
 *   callers put error messages into problem details. The original error is
 *   kept as `cause`.
 *
 * An injected {@link HttpGetService} gets none of this hardening. Hosts are
 * judged as names or literals only. There is no portable DNS lookup, so a
 * public name resolving to a private address is not caught.
 */
export function BuiltinHttpGetService(
  options: BuiltinHttpGetServiceOptions = {}
): HttpGetService {
  const timeoutMs = positiveOption(
    'timeoutMs',
    options.timeoutMs,
    DEFAULT_TIMEOUT_MS
  );
  const maxBytes = positiveOption(
    'maxBytes',
    options.maxBytes,
    DEFAULT_MAX_BYTES
  );
  const allowInsecure = options.allowInsecure === true;
  // Set once the runtime is seen to hide redirects (see `fetchWithinPolicy`),
  // so later requests skip the manual probe instead of fetching twice.
  let followsRedirects = false;

  function assertAllowed(url: string): void {
    const check = checkUrl(url, { allowInsecure });
    if (!check.allowed) {
      throw new Error(`Request to ${url} refused: ${check.reason}`);
    }
  }

  /**
   * Fetch `url` under the URL policy.
   *
   * On Node, `redirect: 'manual'` returns each 3xx with its `Location`, so
   * every hop is checked before it is requested. Browsers return an opaque
   * response with no `Location` instead, and React Native ignores `manual`
   * and follows on its own. On those runtimes the hops cannot be seen. The
   * request is then made with `redirect: 'follow'`, the runtime's own
   * redirect limit applies, and only the first URL and the URL actually
   * reached are checked. An intermediate hop to a private address is not
   * caught there. The policy therefore protects a server, where the fetch
   * runs on Node, and not a client.
   */
  async function fetchWithinPolicy(
    url: string,
    signal: AbortSignal
  ): Promise<HttpGetResult> {
    let current = url;
    let response: Response;
    for (let redirects = 0; ; redirects++) {
      assertAllowed(current);
      const redirect = followsRedirects ? 'follow' : 'manual';
      response = await fetchOrFail(current, { redirect, signal });
      if (response.type === 'opaqueredirect') {
        followsRedirects = true;
        response = await fetchOrFail(current, { redirect: 'follow', signal });
      }
      const location = response.headers.get('location');
      if (
        followsRedirects ||
        !REDIRECT_STATUSES.has(response.status) ||
        location === null
      ) {
        break;
      }
      await discard(response);
      if (redirects === MAX_REDIRECTS) {
        throw new Error(`Request to ${current} refused: too many redirects`);
      }
      try {
        current = new URL(location, current).href;
      } catch {
        throw new Error(`Request to ${current} refused: not a valid URL`);
      }
    }

    // Where the runtime followed redirects itself, `response.url` is the URL
    // actually reached. It is judged before the body is read.
    const reached = response.url || current;
    if (reached !== current) {
      try {
        assertAllowed(reached);
      } catch (e) {
        await discard(response);
        throw e;
      }
    }

    const text = await readCapped(response, reached, maxBytes);
    return {
      body: parseOnce(text),
      headers: response.headers,
      status: response.status
    };
  }

  return {
    async get(url: string): Promise<HttpGetResult> {
      const controller = new AbortController();
      let timer: ReturnType<typeof setTimeout> | undefined;
      // The race keeps the deadline even on a runtime where aborting does
      // not interrupt a body read already in progress.
      const deadline = new Promise<never>((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(
            new Error(`Request to ${url} timed out after ${timeoutMs} ms`)
          );
        }, timeoutMs);
      });
      try {
        return await Promise.race([
          fetchWithinPolicy(url, controller.signal),
          deadline
        ]);
      } finally {
        clearTimeout(timer);
      }
    }
  };
}

export type BuiltinHttpGetServiceType = ReturnType<
  typeof BuiltinHttpGetService
>;

function positiveOption(
  name: string,
  value: number | undefined,
  fallback: number
): number {
  if (value === undefined) {
    return fallback;
  }
  if (!Number.isFinite(value) || value <= 0) {
    throw new RangeError(`${name} must be a positive number`);
  }
  return value;
}

async function fetchOrFail(url: string, init: RequestInit): Promise<Response> {
  try {
    return await fetch(url, init);
  } catch (cause) {
    // The network error's own text (ECONNREFUSED and the like) would let a
    // caller probe which hosts and ports answer, so it stays on `cause`.
    throw new Error(`Request to ${url} failed`, { cause });
  }
}

/**
 * Read the body as text, refusing more than `maxBytes`. Streams where the
 * runtime offers `response.body` (Node, browsers), and checks the size after
 * the fact where it does not (React Native).
 */
async function readCapped(
  response: Response,
  url: string,
  maxBytes: number
): Promise<string> {
  const tooLarge = () =>
    new Error(`Request to ${url} exceeded ${maxBytes} bytes`);

  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > maxBytes) {
    await discard(response);
    throw tooLarge();
  }

  const reader = response.body?.getReader?.();
  if (reader === undefined) {
    const text = await response.text();
    // UTF-8 takes between one and three bytes per UTF-16 unit, so the
    // exact count is only needed when those bounds straddle the cap.
    if (text.length > maxBytes) {
      throw tooLarge();
    }
    if (text.length * 3 > maxBytes && byteLength(text) > maxBytes) {
      throw tooLarge();
    }
    return text;
  }

  const decoder = new TextDecoder();
  let total = 0;
  let text = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      return text + decoder.decode();
    }
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw tooLarge();
    }
    text += decoder.decode(value, { stream: true });
  }
}

/** UTF-8 length of `text`, counted by hand where `TextEncoder` is absent. */
function byteLength(text: string): number {
  if (typeof TextEncoder === 'function') {
    return new TextEncoder().encode(text).byteLength;
  }
  let bytes = 0;
  for (const char of text) {
    const codePoint = char.codePointAt(0) ?? 0;
    if (codePoint < 0x80) {
      bytes += 1;
    } else if (codePoint < 0x800) {
      bytes += 2;
    } else if (codePoint < 0x10000) {
      bytes += 3;
    } else {
      bytes += 4;
    }
  }
  return bytes;
}

/** Parsed JSON when the body is JSON, whatever the content type; else the text. */
function parseOnce(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

async function discard(response: Response): Promise<void> {
  await response.body?.cancel().catch(() => undefined);
}
