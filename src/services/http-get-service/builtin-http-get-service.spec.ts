import { describe, it, expect, vi, afterEach } from 'vitest';
import { BuiltinHttpGetService } from './builtin-http-get-service.js';

describe('BuiltinHttpGetService', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function stubFetch(body: string, contentType: string) {
    vi.stubGlobal(
      'fetch',
      vi.fn(
        async () =>
          new Response(body, {
            status: 200,
            headers: { 'content-type': contentType }
          })
      )
    );
  }

  it('returns an HttpGetService interface', () => {
    const service = BuiltinHttpGetService();
    expect(service).toHaveProperty('get');
    expect(typeof service.get).toBe('function');
  });

  it('returns a non-JSON body as text', async () => {
    // A multi-entry did:webvh `did.jsonl` is not valid JSON. The body must be
    // read once, so the text fallback still works after the parse fails.
    const jsonl = '{"a":1}\n{"b":2}\n';
    stubFetch(jsonl, 'application/jsonl');

    const { body, status } = await BuiltinHttpGetService().get(
      'https://example.com/.well-known/did.jsonl'
    );

    expect(status).toBe(200);
    expect(body).toBe(jsonl);
  });

  it('parses a JSON body', async () => {
    stubFetch('{"a":1}', 'application/json');

    const { body } = await BuiltinHttpGetService().get('https://example.com/');

    expect(body).toEqual({ a: 1 });
  });

  // Note: Full fetch integration tests are covered by smoke tests
  // and registry handler tests using FakeHttpGetService.
});
