/**
 * did:web resolution using caller-provided {@link HttpGetService} so DID document
 * fetches share the same cache as JSON-LD context loads (e.g. Keyv in
 * transaction-service). The stock {@link DidWebResolver} uses
 * `@interop/http-client` and bypasses that cache.
 *
 * Fragment dereference logic matches `@interop/did-web-resolver`
 * `getNode` (suite context map aligned with that package).
 */
import { DidWebResolver, urlFromDid } from '@interop/did-web-resolver';
import type {
  IDID,
  IDidDocument,
  IPublicKey
} from '@interop/data-integrity-core';
import { klona } from 'klona';
import type { HttpGetService } from '../services/http-get-service/http-get-service.js';

const contextsBySuite = new Map<string, string>([
  [
    'Ed25519VerificationKey2020',
    'https://w3id.org/security/suites/ed25519-2020/v1'
  ],
  [
    'Ed25519VerificationKey2018',
    'https://w3id.org/security/suites/ed25519-2018/v1'
  ],
  ['Multikey', 'https://w3id.org/security/multikey/v1'],
  [
    'X25519KeyAgreementKey2020',
    'https://w3id.org/security/suites/x25519-2020/v1'
  ],
  [
    'X25519KeyAgreementKey2019',
    'https://w3id.org/security/suites/x25519-2019/v1'
  ]
]);

function assertDomainAllowList(
  allowList: string[] | undefined,
  url: string
): void {
  if (!allowList || allowList.length <= 0) {
    return;
  }
  const { host } = new URL(url);
  if (allowList.includes(host)) {
    return;
  }
  throw new Error(`Domain "${host}" is not allowed.`);
}

function getNodeFromDidDocument(
  didDocument: Record<string, unknown>,
  id: string
): Record<string, unknown> {
  const vms = didDocument.verificationMethod;
  let match: Record<string, unknown> | undefined;
  if (Array.isArray(vms)) {
    match = vms.find(
      (vm: unknown) =>
        typeof vm === 'object' &&
        vm !== null &&
        (vm as { id?: string }).id === id
    ) as Record<string, unknown> | undefined;
  }
  if (!match) {
    for (const [key, value] of Object.entries(didDocument)) {
      if (key === '@context' || key === 'verificationMethod') {
        continue;
      }
      if (Array.isArray(value)) {
        match = value.find(
          (e: unknown) =>
            typeof e === 'object' &&
            e !== null &&
            (e as { id?: string }).id === id
        ) as Record<string, unknown> | undefined;
      } else if (
        value &&
        typeof value === 'object' &&
        (value as { id?: string }).id === id
      ) {
        match = value as Record<string, unknown>;
      }
      if (match) {
        break;
      }
    }
  }
  if (!match) {
    throw new Error(`DID document entity with id "${id}" not found.`);
  }
  const suiteType = match.type;
  const ctxFromSuite =
    typeof suiteType === 'string' ? contextsBySuite.get(suiteType) : undefined;
  const ctxSource = ctxFromSuite ?? didDocument['@context'];
  return {
    '@context': klona(ctxSource),
    ...klona(match)
  };
}

/**
 * did-io driver for did:web that loads documents via `httpGetService`.
 *
 * Returns a {@link DidWebResolver} instance (which implements `did-io`'s
 * `DidMethodDriver`, so it can be registered via `CachedResolver.use(...)`, and
 * exposes `use(...)` for registering key suites) with only `get` overridden to
 * route fetches through the caller's `httpGetService`. The generation/key
 * methods (`generate`, `fromKeyPair`, etc.) are inherited unchanged; a verifier
 * never calls them.
 */
export function didWebDriverWithHttpGet(
  httpGetService: HttpGetService,
  options?: ConstructorParameters<typeof DidWebResolver>[0]
): DidWebResolver {
  const driver = new DidWebResolver(options);
  driver.get = async ({
    did,
    url
  }: {
    did?: IDID | string;
    url?: string;
    [key: string]: unknown;
  } = {}): Promise<IDidDocument | IPublicKey> => {
    const didOrUrl = did || url;
    if (!didOrUrl) {
      throw new TypeError('A DID or URL is required.');
    }
    const resolvedUrl = new URL(
      didOrUrl.startsWith('did:') ? urlFromDid({ did: didOrUrl }) : didOrUrl
    );
    const fragment = resolvedUrl.hash;
    resolvedUrl.hash = '';
    const baseUrl = resolvedUrl.toString();
    assertDomainAllowList(driver.allowList, baseUrl);
    const { body, status } = await httpGetService.get(baseUrl);
    if (status < 200 || status >= 300) {
      throw new Error(`Failed to fetch DID document: HTTP ${status}`);
    }
    const data = body as Record<string, unknown> | null;
    const [didAuth] = didOrUrl.split(/(?=[?#])/);
    if (data?.id !== didAuth) {
      throw new Error(`DID document for DID "${didOrUrl}" not found.`);
    }
    // The fetched body is untrusted JSON; assert it into the typed DID-document /
    // verification-method node shapes at this boundary.
    if (fragment) {
      const id = `${String(data.id)}${fragment}`;
      return getNodeFromDidDocument(data, id) as unknown as IPublicKey;
    }
    return data as unknown as IDidDocument;
  };
  return driver;
}
