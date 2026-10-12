import http from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi
} from 'vitest';
import {
  BuiltinHttpGetService,
  MAX_REDIRECTS
} from './builtin-http-get-service.js';
import { documentLoaderFromHttpGet } from '../../util/document-loader-from-http-get.js';

const SECRET_BODY = 'SECRET-TOK-1234 not json';

type FetchStub = ReturnType<typeof vi.fn<typeof fetch>>;

function stubFetch(impl: typeof fetch): FetchStub {
  const stub = vi.fn<typeof fetch>(impl);
  vi.stubGlobal('fetch', stub);
  return stub;
}

function redirectTo(location: string, status = 302): Response {
  return new Response(null, { status, headers: { location } });
}

/** A response shape `new Response` cannot produce (opaque, a set `url`, no stream). */
function fakeResponse(fields: Partial<Response>): Response {
  return {
    type: 'basic',
    status: 200,
    url: '',
    headers: new Headers(),
    body: null,
    text: async () => '',
    ...fields
  } as Response;
}

function streamOf(bytes: number, onCancel: () => void): ReadableStream {
  let sent = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      const size = Math.min(1024, bytes - sent);
      if (size <= 0) {
        controller.close();
        return;
      }
      sent += size;
      controller.enqueue(new Uint8Array(size).fill(0x61));
    },
    cancel: onCancel
  });
}

/** Start a loopback HTTP server on a free port; stop it when the suite ends. */
function useLoopbackServer(handler: http.RequestListener): {
  port: () => number;
} {
  let server: http.Server;
  let port = 0;
  beforeAll(async () => {
    server = http.createServer(handler);
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as AddressInfo).port;
  });
  afterAll(async () => {
    await new Promise<void>(resolve => server.close(() => resolve()));
  });
  return { port: () => port };
}

async function rejectionOf(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (e) {
    return e as Error;
  }
  throw new Error('expected a rejection');
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('BuiltinHttpGetService -- URL policy', () => {
  it.each([
    ['http://example.com/', 'scheme is not https'],
    ['https://169.254.169.254/latest/meta-data', 'host is a link-local address']
  ])('refuses %s without calling fetch', async (url, reason) => {
    const fetchStub = stubFetch(async () => new Response('{}'));
    await expect(BuiltinHttpGetService().get(url)).rejects.toThrow(
      `Request to ${url} refused: ${reason}`
    );
    expect(fetchStub).not.toHaveBeenCalled();
  });

  describe('against a real loopback server', () => {
    let requests = 0;
    const loopback = useLoopbackServer((_req, res) => {
      requests++;
      res.end('{}');
    });

    it('never sends a request to a refused address', async () => {
      const service = BuiltinHttpGetService();
      const port = loopback.port();
      await expect(service.get(`http://127.0.0.1:${port}/`)).rejects.toThrow(
        'refused'
      );
      await expect(service.get(`https://127.0.0.1:${port}/`)).rejects.toThrow(
        'refused'
      );
      expect(requests).toBe(0);
    });
  });
});

describe('BuiltinHttpGetService -- redirects', () => {
  it('follows a redirect to an allowed URL', async () => {
    const fetchStub = stubFetch(async input =>
      String(input) === 'https://a.example/x'
        ? redirectTo('https://b.example/y')
        : new Response('{"ok":true}')
    );
    const result = await BuiltinHttpGetService().get('https://a.example/x');
    expect(result.body).toEqual({ ok: true });
    expect(fetchStub.mock.calls.map(c => c[0])).toEqual([
      'https://a.example/x',
      'https://b.example/y'
    ]);
    expect(fetchStub.mock.calls[0][1]?.redirect).toBe('manual');
  });

  it('never requests a redirect target the policy refuses', async () => {
    const fetchStub = stubFetch(async () =>
      redirectTo('http://127.0.0.1/latest/meta-data')
    );
    await expect(
      BuiltinHttpGetService().get('https://a.example/x')
    ).rejects.toThrow(
      'Request to http://127.0.0.1/latest/meta-data refused: scheme is not https'
    );
    expect(fetchStub).toHaveBeenCalledTimes(1);
  });

  it('resolves a relative Location against the current URL', async () => {
    const fetchStub = stubFetch(async input =>
      String(input) === 'https://a.example/dir/x'
        ? redirectTo('../y')
        : new Response('{}')
    );
    await BuiltinHttpGetService().get('https://a.example/dir/x');
    expect(fetchStub.mock.calls[1][0]).toBe('https://a.example/y');
  });

  it(`follows at most ${MAX_REDIRECTS} redirects`, async () => {
    let n = 0;
    const fetchStub = stubFetch(async () =>
      redirectTo(`https://a.example/${++n}`)
    );
    await expect(
      BuiltinHttpGetService().get('https://a.example/0')
    ).rejects.toThrow(
      `Request to https://a.example/${MAX_REDIRECTS} refused: too many redirects`
    );
    expect(fetchStub).toHaveBeenCalledTimes(MAX_REDIRECTS + 1);
  });

  it('retries an opaque redirect once with redirect: follow', async () => {
    const fetchStub = stubFetch(async (_input, init) =>
      init?.redirect === 'manual'
        ? fakeResponse({ type: 'opaqueredirect', status: 0 })
        : new Response('{"a":1}')
    );
    const service = BuiltinHttpGetService();
    const result = await service.get('https://a.example/x');
    expect(result.body).toEqual({ a: 1 });
    expect(fetchStub.mock.calls.map(c => c[1]?.redirect)).toEqual([
      'manual',
      'follow'
    ]);

    // The runtime is now known to hide redirects, so the probe is skipped.
    await service.get('https://a.example/y');
    expect(fetchStub.mock.calls.map(c => c[1]?.redirect)).toEqual([
      'manual',
      'follow',
      'follow'
    ]);
  });

  it('still checks the first URL after the runtime is known to follow', async () => {
    const fetchStub = stubFetch(async (_input, init) =>
      init?.redirect === 'manual'
        ? fakeResponse({ type: 'opaqueredirect', status: 0 })
        : new Response('{}')
    );
    const service = BuiltinHttpGetService();
    await service.get('https://a.example/x');
    await expect(service.get('https://10.0.0.1/')).rejects.toThrow(
      'Request to https://10.0.0.1/ refused: host is a private address'
    );
    expect(fetchStub).toHaveBeenCalledTimes(2);
  });

  it('refuses a response whose final URL the policy refuses', async () => {
    const textSpy = vi.fn(async () => SECRET_BODY);
    stubFetch(async () =>
      fakeResponse({ url: 'https://10.0.0.1/', text: textSpy })
    );
    await expect(
      BuiltinHttpGetService().get('https://a.example/x')
    ).rejects.toThrow(
      'Request to https://10.0.0.1/ refused: host is a private address'
    );
    expect(textSpy).not.toHaveBeenCalled();
  });

  it('returns a 3xx without Location as a result', async () => {
    stubFetch(async () => new Response(null, { status: 304 }));
    const result = await BuiltinHttpGetService().get('https://a.example/x');
    expect(result.status).toBe(304);
  });
});

describe('BuiltinHttpGetService -- deadline', () => {
  it('fails after timeoutMs and aborts the request', async () => {
    let signal: AbortSignal | undefined;
    stubFetch((_input, init) => {
      signal = init?.signal ?? undefined;
      return new Promise<Response>(() => undefined);
    });
    await expect(
      BuiltinHttpGetService({ timeoutMs: 50 }).get('https://a.example/x')
    ).rejects.toThrow('Request to https://a.example/x timed out after 50 ms');
    expect(signal?.aborted).toBe(true);
  });
});

describe('BuiltinHttpGetService -- byte cap', () => {
  const maxBytes = 4096;

  it('refuses a declared Content-Length over the cap without reading', async () => {
    const textSpy = vi.fn(async () => '{}');
    stubFetch(async () =>
      fakeResponse({
        headers: new Headers({ 'content-length': String(maxBytes + 1) }),
        text: textSpy
      })
    );
    await expect(
      BuiltinHttpGetService({ maxBytes }).get('https://a.example/x')
    ).rejects.toThrow(
      `Request to https://a.example/x exceeded ${maxBytes} bytes`
    );
    expect(textSpy).not.toHaveBeenCalled();
  });

  it('stops reading a stream once past the cap', async () => {
    const onCancel = vi.fn();
    stubFetch(async () => new Response(streamOf(maxBytes * 4, onCancel)));
    await expect(
      BuiltinHttpGetService({ maxBytes }).get('https://a.example/x')
    ).rejects.toThrow(`exceeded ${maxBytes} bytes`);
    expect(onCancel).toHaveBeenCalled();
  });

  it('accepts a stream of exactly maxBytes', async () => {
    stubFetch(async () => new Response(streamOf(maxBytes, () => undefined)));
    const result = await BuiltinHttpGetService({ maxBytes }).get(
      'https://a.example/x'
    );
    expect(result.body).toBe('a'.repeat(maxBytes));
  });

  it('checks the size after reading when there is no stream (React Native)', async () => {
    stubFetch(async () =>
      fakeResponse({ text: async () => 'a'.repeat(maxBytes + 1) })
    );
    await expect(
      BuiltinHttpGetService({ maxBytes }).get('https://a.example/x')
    ).rejects.toThrow(`exceeded ${maxBytes} bytes`);
  });

  it('counts UTF-8 bytes without TextEncoder (no stream)', async () => {
    // Three-byte characters: well under the cap in UTF-16 units, over in bytes.
    const body = '\u20ac'.repeat(Math.ceil(maxBytes / 3) + 1);
    expect(body.length).toBeLessThan(maxBytes);
    stubFetch(async () => fakeResponse({ text: async () => body }));
    vi.stubGlobal('TextEncoder', undefined);
    await expect(
      BuiltinHttpGetService({ maxBytes }).get('https://a.example/x')
    ).rejects.toThrow(`exceeded ${maxBytes} bytes`);
  });
});

describe('BuiltinHttpGetService -- parse once', () => {
  it.each([
    ['text/plain JSON', '{"a":1}', 'text/plain', { a: 1 }],
    [
      'JSON-typed non-JSON (no double read)',
      SECRET_BODY,
      'application/json',
      SECRET_BODY
    ],
    ['JSON-typed JSON', '{"a":1}', 'application/json', { a: 1 }],
    // A multi-entry did:webvh `did.jsonl` is not valid JSON. The body must be
    // read once, so the text fallback still works after the parse fails.
    [
      'JSON Lines as text',
      '{"a":1}\n{"b":2}\n',
      'application/jsonl',
      '{"a":1}\n{"b":2}\n'
    ],
    ['a JWT', 'aaa.bbb.ccc', 'application/entity-statement+jwt', 'aaa.bbb.ccc'],
    ['an empty body', '', 'text/plain', '']
  ])('returns %s as expected', async (_label, body, contentType, expected) => {
    stubFetch(
      async () =>
        new Response(body, { headers: { 'content-type': contentType } })
    );
    const result = await BuiltinHttpGetService().get('https://a.example/x');
    expect(result.body).toEqual(expected);
  });

  it('returns a 404 as a result, not an error', async () => {
    stubFetch(async () => new Response('{"error":"missing"}', { status: 404 }));
    const result = await BuiltinHttpGetService().get('https://a.example/x');
    expect(result).toMatchObject({ status: 404, body: { error: 'missing' } });
  });
});

describe('BuiltinHttpGetService -- error text', () => {
  it('never puts body text into an error', async () => {
    const service = BuiltinHttpGetService({ maxBytes: 8 });
    stubFetch(async () => new Response(SECRET_BODY));
    const error = await rejectionOf(service.get('https://a.example/x'));
    expect(error.message).not.toContain('SECRET');
  });

  it('reports a network failure with fixed text and keeps the cause', async () => {
    const cause = new Error('connect ECONNREFUSED 10.0.0.1:22');
    stubFetch(async () => {
      throw cause;
    });
    const error = await rejectionOf(
      BuiltinHttpGetService().get('https://a.example/x')
    );
    expect(error.message).toBe('Request to https://a.example/x failed');
    expect(error.cause).toBe(cause);
  });
});

describe('BuiltinHttpGetService -- options', () => {
  it.each([{ timeoutMs: 0 }, { timeoutMs: Number.NaN }, { maxBytes: -1 }])(
    'rejects %o at construction',
    options => {
      expect(() => BuiltinHttpGetService(options)).toThrow(RangeError);
    }
  );
});

describe('BuiltinHttpGetService -- allowInsecure', () => {
  describe('against a real loopback server', () => {
    const loopback = useLoopbackServer((_req, res) => {
      res.setHeader('content-type', 'application/json');
      res.end('{"local":true}');
    });

    it('fetches an http loopback URL and returns the body', async () => {
      const service = BuiltinHttpGetService({ allowInsecure: true });
      const result = await service.get(`http://127.0.0.1:${loopback.port()}/`);
      expect(result.status).toBe(200);
      expect(result.body).toEqual({ local: true });
    });
  });

  it('allows http://localhost/', async () => {
    const fetchStub = stubFetch(async () => new Response('{"ok":true}'));
    const result = await BuiltinHttpGetService({ allowInsecure: true }).get(
      'http://localhost/'
    );
    expect(result.body).toEqual({ ok: true });
    expect(fetchStub).toHaveBeenCalledTimes(1);
  });

  it('follows a redirect to a private address', async () => {
    const fetchStub = stubFetch(async input =>
      String(input) === 'https://a.example/x'
        ? redirectTo('http://10.0.0.1/y')
        : new Response('{"private":true}')
    );
    const result = await BuiltinHttpGetService({ allowInsecure: true }).get(
      'https://a.example/x'
    );
    expect(result.body).toEqual({ private: true });
    expect(fetchStub.mock.calls.map(c => c[0])).toEqual([
      'https://a.example/x',
      'http://10.0.0.1/y'
    ]);
  });

  it('accepts a final URL at a private address', async () => {
    stubFetch(async () =>
      fakeResponse({ url: 'http://192.168.1.1/', text: async () => '{}' })
    );
    const result = await BuiltinHttpGetService({ allowInsecure: true }).get(
      'https://a.example/x'
    );
    expect(result.body).toEqual({});
  });

  it('still refuses a URL that does not parse', async () => {
    const fetchStub = stubFetch(async () => new Response('{}'));
    await expect(
      BuiltinHttpGetService({ allowInsecure: true }).get('not a url')
    ).rejects.toThrow('Request to not a url refused: not a valid URL');
    expect(fetchStub).not.toHaveBeenCalled();
  });

  it('still enforces maxBytes', async () => {
    stubFetch(async () => new Response('a'.repeat(64)));
    await expect(
      BuiltinHttpGetService({ allowInsecure: true, maxBytes: 8 }).get(
        'http://localhost/'
      )
    ).rejects.toThrow('Request to http://localhost/ exceeded 8 bytes');
  });

  it('still enforces timeoutMs', async () => {
    stubFetch(() => new Promise<Response>(() => undefined));
    await expect(
      BuiltinHttpGetService({ allowInsecure: true, timeoutMs: 50 }).get(
        'http://localhost/'
      )
    ).rejects.toThrow('Request to http://localhost/ timed out after 50 ms');
  });

  it(`still follows at most ${MAX_REDIRECTS} redirects`, async () => {
    let n = 0;
    stubFetch(async () => redirectTo(`http://localhost/${++n}`));
    await expect(
      BuiltinHttpGetService({ allowInsecure: true }).get('http://localhost/0')
    ).rejects.toThrow('refused: too many redirects');
  });
});

describe('BuiltinHttpGetService -- consumers agree', () => {
  it('lets did:web resolve a DID document served as text/plain', async () => {
    stubFetch(
      async () =>
        new Response(
          JSON.stringify({
            '@context': 'https://www.w3.org/ns/did/v1',
            id: 'did:web:example.com'
          }),
          { headers: { 'content-type': 'text/plain' } }
        )
    );
    const loader = documentLoaderFromHttpGet(BuiltinHttpGetService());
    const { document } = await loader('did:web:example.com');
    expect((document as { id: string }).id).toBe('did:web:example.com');
  });
});
