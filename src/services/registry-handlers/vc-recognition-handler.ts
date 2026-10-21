import type {
  RegistryEntity,
  VcRecognitionEntityIdentityRegistry
} from '../../types/registry.js';
import type { HttpGetService } from '../http-get-service/http-get-service.js';
import { klona } from 'klona';
import { credentialIssuerId } from '../../util/issuer-id.js';
import { DEFAULT_TTL_MS, resolveTtl, ttlFromValidUntil } from './cache-ttl.js';
import type {
  HandlerResult,
  RegistryHandler,
  RegistryHandlerContext
} from './types.js';

/**
 * VerifiableRecognitionCredential registry: fetch the recognition VC,
 * verify its issuer + proof using the parent {@link Verifier}
 * (sharing the same cache + crypto stack), cache it for at most an hour,
 * or until `validUntil` if sooner, so revocation of the recognition
 * credential is re-checked, then check `credentialSubject` for `did`.
 *
 * The recursive call passes `registries: []` to skip the registry suite
 * for the recognition credential itself — that prevents infinite
 * recursion when the recognition VC's own issuer is also looked up
 * through a recognition registry.
 *
 * @see https://w3c.github.io/vc-recognition/
 */
export const lookupVcRecognition: RegistryHandler = async (
  did,
  registry,
  ctx
) => {
  if (registry.type !== 'vc-recognition') {
    return { status: 'unchecked' };
  }
  return lookupVcRecognitionForRegistry(did, registry, ctx);
};

async function lookupVcRecognitionForRegistry(
  did: string,
  registry: VcRecognitionEntityIdentityRegistry,
  ctx: RegistryHandlerContext
): Promise<HandlerResult> {
  const { httpGetService, cacheService, verifier, timeService } = ctx;
  const key = cacheKeyForVcRecognitionUrl(registry.url);
  let credential = (await cacheService.get(key)) as
    Record<string, unknown> | undefined;

  if (!credential) {
    const loaded = await fetchRecognitionCredentialJson(
      registry.url,
      httpGetService
    );
    if (!loaded) {
      return { status: 'unchecked' };
    }

    const issuerId = credentialIssuerId(loaded);
    if (!issuerId || !registry.acceptedIssuers.includes(issuerId)) {
      return { status: 'unchecked' };
    }

    const verification = await verifier.verifyCredential({
      credential: loaded,
      registries: []
    });

    if (!verification.verified) {
      return { status: 'unchecked' };
    }

    // At most an hour, or until `validUntil` if sooner, on the verifier's
    // clock. A missing or past `validUntil` gets the hour: the verifier
    // above already rejected an expired credential.
    const ttlMs = Math.min(
      resolveTtl(ttlFromValidUntil(loaded.validUntil, timeService.dateNowMs())),
      DEFAULT_TTL_MS
    );
    await cacheService.set(key, loaded, ttlMs);
    credential = loaded;
  }

  const entry = findSubjectEntry(credential, did);
  if (entry === undefined) {
    return { status: 'not-found' };
  }
  return { status: 'found', entity: entityFromEntry(entry) };
}

function cacheKeyForVcRecognitionUrl(url: string): string {
  return `vc-recognition:${url}`;
}

async function fetchRecognitionCredentialJson(
  url: string,
  httpGetService: HttpGetService
): Promise<Record<string, unknown> | null> {
  let result;
  try {
    result = await httpGetService.get(url);
  } catch {
    return null;
  }
  if (result.status < 200 || result.status >= 300) {
    return null;
  }
  const json = result.body;
  if (!json || typeof json !== 'object' || Array.isArray(json)) {
    return null;
  }
  return json as Record<string, unknown>;
}

/**
 * The `credentialSubject` entry whose `id` is `did`, or `undefined`. The
 * subject is one object or an array of them.
 */
function findSubjectEntry(
  credential: Record<string, unknown>,
  did: string
): Record<string, unknown> | undefined {
  const subject = credential.credentialSubject;
  const entries = Array.isArray(subject) ? subject : [subject];
  return entries.find(
    (entry): entry is Record<string, unknown> =>
      entry !== null &&
      typeof entry === 'object' &&
      !Array.isArray(entry) &&
      (entry as { id?: unknown }).id === did
  );
}

/**
 * The recognition credential's record of the issuer: its name and homepage
 * when they are plain strings, plus the whole entry, so a consumer can read
 * fields this shape does not name. A `name` that is a language map stays in
 * `raw` only. `raw` is a copy: the entry belongs to the cached recognition
 * credential, which every later lookup sharing the cache reads.
 */
function entityFromEntry(entry: Record<string, unknown>): RegistryEntity {
  const entity: RegistryEntity = { raw: klona(entry) };
  if (typeof entry.name === 'string') {
    entity.name = entry.name;
  }
  if (typeof entry.url === 'string') {
    entity.url = entry.url;
  }
  return entity;
}
