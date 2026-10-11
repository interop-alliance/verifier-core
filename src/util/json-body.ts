/**
 * Return an `HttpGetService` body as JSON.
 *
 * `BuiltinHttpGetService` already parses JSON bodies, but the service is
 * injectable and a custom adapter may hand back raw text. A string body is
 * parsed here. A string that is not JSON throws fixed text: the parser's own
 * message quotes the body, and these messages reach problem details.
 */
export function parseJsonBody(body: unknown): unknown {
  if (typeof body !== 'string') {
    return body;
  }
  try {
    return JSON.parse(body) as unknown;
  } catch {
    throw new Error('response is not JSON');
  }
}
