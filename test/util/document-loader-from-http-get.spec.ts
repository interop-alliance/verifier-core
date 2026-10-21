import { describe, it, expect } from 'vitest';
import type { DIDResolutionError } from '@interop/data-integrity-core/did';
import type { HttpGetService } from '../../src/services/http-get-service/http-get-service.js';
import { documentLoaderFromHttpGet } from '../../src/util/document-loader-from-http-get.js';
import {
  FakeHttpGetService,
  httpGetResult,
  okJsonBody
} from '../factories/services/fake-http-get-service.js';

/**
 * A status list credential is the realistic case. Static contexts cover most
 * URLs a verification resolves, so an arbitrary remote document like this one
 * is close to the only thing that reaches the http protocol handler, which is
 * why a bug here shows up as "revocation is broken" and nothing else.
 */
const STATUS_LIST_URL = 'https://example.edu/status/1';
const STATUS_LIST = {
  '@context': ['https://www.w3.org/ns/credentials/v2'],
  id: STATUS_LIST_URL,
  type: ['VerifiableCredential', 'BitstringStatusListCredential'],
  credentialSubject: {
    id: `${STATUS_LIST_URL}#list`,
    type: 'BitstringStatusList',
    statusPurpose: 'revocation',
    encodedList:
      'uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA'
  }
};

/**
 * `BuiltinHttpGetService` returns any JSON body parsed, whatever the content
 * type. A custom `HttpGetService` may skip parsing and return the raw text.
 * Both shapes are reproduced here because they fail for different reasons.
 */
const jsonService = FakeHttpGetService({
  [STATUS_LIST_URL]: okJsonBody(STATUS_LIST)
});

/** How a status list arrives from raw.githubusercontent.com (text/plain). */
const textService = FakeHttpGetService({
  [STATUS_LIST_URL]: httpGetResult(
    200,
    JSON.stringify(STATUS_LIST),
    new Headers({ 'content-type': 'text/plain; charset=utf-8' })
  )
});

describe('documentLoaderFromHttpGet', () => {
  it('resolves a JSON-typed body to the document, not a nested envelope', async () => {
    const loader = documentLoaderFromHttpGet(jsonService);

    const result = await loader(STATUS_LIST_URL);

    // `jsonld-document-loader` builds the `{ contextUrl, document,
    // documentUrl }` envelope around whatever the protocol handler returns.
    // A handler that returns an envelope of its own gets it nested, and every
    // caller that unwraps `.document` (`checkStatus` among them) receives
    // the inner envelope rather than the credential.
    expect(result.documentUrl).toBe(STATUS_LIST_URL);
    expect(result.document).toEqual(STATUS_LIST);
    expect(result.document).not.toHaveProperty('document');
  });

  it('parses a string body rather than passing it through', async () => {
    const loader = documentLoaderFromHttpGet(textService);

    const result = await loader(STATUS_LIST_URL);

    // `ContextResolver` parses strings itself, so remote JSON-LD contexts
    // survive a string body and only document loads fail, which is why this
    // hid behind "status lists are broken" rather than "the loader is broken".
    expect(typeof result.document).toBe('object');
    expect(result.document).toEqual(STATUS_LIST);
  });

  it('exposes the fields a status list consumer destructures', async () => {
    for (const service of [jsonService, textService]) {
      const loader = documentLoaderFromHttpGet(service);

      const { document } = (await loader(STATUS_LIST_URL)) as {
        document: typeof STATUS_LIST;
      };

      // The shape `vc-bitstring-status-list` reaches for. Reading it off a
      // nested envelope, or off a string, throws "Cannot destructure property
      // 'statusPurpose' of 'slCredential.credentialSubject' as it is
      // undefined".
      expect(document.credentialSubject.statusPurpose).toBe('revocation');
    }
  });

  it('reports an unparseable body as a NotFoundError naming the url', async () => {
    const brokenService = FakeHttpGetService({
      [STATUS_LIST_URL]: httpGetResult(
        200,
        '<!DOCTYPE html><title>404</title>',
        new Headers({ 'content-type': 'text/html' })
      )
    });
    const loader = documentLoaderFromHttpGet(brokenService);

    // A 200 carrying an error page is common enough to be worth pinning: it
    // has to surface as this loader failing to find the document, with the
    // url in the message, rather than as a destructuring error further down.
    await expect(loader(STATUS_LIST_URL)).rejects.toThrow(
      `NotFoundError loading "${STATUS_LIST_URL}"`
    );

    // The parser's message quotes the body, and loader messages reach
    // problem details, so the body must not appear in the error.
    const error = await loader(STATUS_LIST_URL).catch((e: unknown) => e);
    const message = (error as Error).message;
    expect(message).toContain('response is not JSON');
    expect(message).not.toContain('DOCTYPE');
    expect(message).not.toContain('<title>');
  });

  it('reports a non-2xx status as a NotFoundError naming the url', async () => {
    const notFoundService = FakeHttpGetService({
      [STATUS_LIST_URL]: httpGetResult(404, 'Not Found')
    });
    const loader = documentLoaderFromHttpGet(notFoundService);

    await expect(loader(STATUS_LIST_URL)).rejects.toThrow(
      `NotFoundError loading "${STATUS_LIST_URL}": HTTP 404`
    );
  });
});

describe('documentLoaderFromHttpGet did:web resolution failures', () => {
  const DID = 'did:web:example.com';
  const DID_URL = 'https://example.com/.well-known/did.json';

  async function failure(service: HttpGetService): Promise<unknown> {
    try {
      await documentLoaderFromHttpGet(service)(DID);
    } catch (e) {
      return e;
    }
    return undefined;
  }

  it('throws a notFound DIDResolutionError for a 404', async () => {
    const error = (await failure(
      FakeHttpGetService({ [DID_URL]: httpGetResult(404, 'Not Found') })
    )) as DIDResolutionError;

    expect(error.name).toBe('DIDResolutionError');
    expect(error.code).toBe('notFound');
    expect(error.message).toBe(
      `Fetching DID document at "${DID_URL}" returned HTTP 404.`
    );
  });

  it('throws an internalError DIDResolutionError for another non-2xx status', async () => {
    const error = (await failure(
      FakeHttpGetService({ [DID_URL]: httpGetResult(503, '') })
    )) as DIDResolutionError;

    expect(error.name).toBe('DIDResolutionError');
    expect(error.code).toBe('internalError');
    expect(error.message).toContain('HTTP 503');
  });

  it('throws an internalError DIDResolutionError for a 2xx body that is not JSON', async () => {
    const error = (await failure(
      FakeHttpGetService({
        [DID_URL]: httpGetResult(200, '<!DOCTYPE html><title>Welcome</title>')
      })
    )) as DIDResolutionError;

    expect(error.name).toBe('DIDResolutionError');
    expect(error.code).toBe('internalError');
    expect(error.message).toBe(`The DID document at "${DID_URL}" is not JSON.`);
    expect(error.message).not.toContain('DOCTYPE');
  });

  it('wraps a thrown transport error, keeping it as the cause', async () => {
    const transport = new Error('getaddrinfo ENOTFOUND secret-host');
    const error = (await failure({
      async get() {
        throw transport;
      }
    })) as DIDResolutionError;

    expect(error.name).toBe('DIDResolutionError');
    expect(error.code).toBe('internalError');
    expect(error.cause).toBe(transport);
    expect(error.message).toBe(`Could not fetch DID document at "${DID_URL}".`);
    expect(error.message).not.toContain('ENOTFOUND');
  });
});
