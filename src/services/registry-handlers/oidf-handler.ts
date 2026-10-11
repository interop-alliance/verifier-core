import type { OidfEntityIdentityRegistry } from '../../types/registry.js';
import type { CacheService } from '../cache-service/cache-service.js';
import type { HttpGetService } from '../http-get-service/http-get-service.js';
import { parseCacheControlMaxAge, resolveTtl } from './cache-ttl.js';
import { verifyJws } from './jws-verify.js';
import { jwtDecodePayload } from './jwt-payload-decode.js';
import type {
  HandlerResult,
  RegistryHandler,
  RegistryHandlerContext
} from './types.js';

/** The `typ` every OIDF entity statement header must carry. */
const ENTITY_STATEMENT_TYP = 'entity-statement+jwt';

/**
 * OpenID Federation (OIDF) trust-anchor lookup.
 *
 * 1. Fetch the trust anchor's entity configuration from `trustAnchorEC` and
 *    verify it against its own `jwks`, with `iss === sub` and an unexpired
 *    `exp`. The federation fetch endpoint is read only from that verified
 *    payload. Both statements must carry the `entity-statement+jwt` header
 *    `typ`, and response bodies are trimmed before decoding so a trailing
 *    newline does not fail the lookup.
 * 2. Fetch the issuer's subordinate statement from that endpoint and verify
 *    it against the anchor's keys, with `iss` equal to the anchor's entity
 *    identifier, `sub` equal to the issuer DID, and an unexpired `exp`.
 *
 * Trust is rooted in the HTTPS fetch of the configured `trustAnchorEC`: there
 * are no pinned anchor keys, so the entity configuration is trusted because
 * of where it was fetched from, and everything else follows from its keys.
 *
 * Only the raw JWTs are cached, never a verdict. Each is re-verified on
 * every cache hit and never cached past its `exp`. A 404 from the fetch
 * endpoint is `not-found`; every other failure, including any failed check,
 * is `unchecked`, because it says nothing about whether the issuer is a
 * member. "Now" is read once per lookup from the context's `TimeService`.
 */
export const lookupOidf: RegistryHandler = async (did, registry, ctx) => {
  if (registry.type !== 'oidf') {
    return { status: 'unchecked' };
  }
  return lookupOidfForRegistry(did, registry, ctx);
};

/** The parts of a verified entity configuration the lookup needs. */
type VerifiedEntityConfiguration = {
  /** The anchor's entity identifier (its `sub`), which may be a DID, not the URL. */
  entityId: string;
  jwks: unknown;
  fetchEndpoint: string;
  /** Expiry, in seconds since the epoch. */
  exp: number;
};

async function lookupOidfForRegistry(
  did: string,
  registry: OidfEntityIdentityRegistry,
  { httpGetService, cacheService, timeService }: RegistryHandlerContext
): Promise<HandlerResult> {
  const unchecked: HandlerResult = {
    status: 'unchecked'
  };
  // One clock reading per lookup, so every expiry check and TTL in this
  // lookup agrees on "now".
  const nowMs = timeService.dateNowMs();

  const ec = await getVerifiedEntityConfiguration(
    registry.trustAnchorEC,
    httpGetService,
    cacheService,
    nowMs
  );
  if (!ec) {
    return unchecked;
  }

  // Built with URL so an endpoint that already carries a query keeps it.
  let lookupUrl: string;
  try {
    const url = new URL(ec.fetchEndpoint);
    url.searchParams.set('sub', did);
    lookupUrl = url.href;
  } catch {
    return unchecked;
  }
  const lookupKey = cacheKeyForOidfLookup(lookupUrl);

  const cached = await cacheService.get(lookupKey);
  if (typeof cached === 'string' && cached) {
    const exp = await verifySubordinateStatement(cached, ec, did, nowMs);
    if (exp !== undefined) {
      return { status: 'found' };
    }
    // A cached statement that no longer verifies (typically one past its
    // `exp`) is refetched rather than trusted.
  }

  let result;
  try {
    result = await httpGetService.get(lookupUrl);
  } catch {
    return unchecked;
  }

  if (result.status === 404) {
    return { status: 'not-found' };
  }
  if (result.status < 200 || result.status >= 300) {
    return unchecked;
  }

  const issuerJwt = bodyToJwt(result.body);
  const exp = await verifySubordinateStatement(issuerJwt, ec, did, nowMs);
  if (exp === undefined) {
    return unchecked;
  }

  await cacheService.set(
    lookupKey,
    issuerJwt,
    ttlBoundedByExp(result.headers, exp, nowMs)
  );
  return { status: 'found' };
}

/**
 * The trust anchor's verified entity configuration, from the cache or a
 * fresh fetch, or `null` when it cannot be fetched or does not verify.
 * Only a JWT that verifies is cached.
 */
async function getVerifiedEntityConfiguration(
  trustAnchorEcUrl: string,
  httpGetService: HttpGetService,
  cacheService: CacheService,
  nowMs: number
): Promise<VerifiedEntityConfiguration | null> {
  const key = cacheKeyForOidfEntityConfig(trustAnchorEcUrl);
  const cached = await cacheService.get(key);
  if (typeof cached === 'string' && cached) {
    const ec = await verifyEntityConfiguration(cached, nowMs);
    if (ec) {
      return ec;
    }
    // Fall through to a fresh fetch: the cached copy has expired or no
    // longer verifies.
  }

  let result;
  try {
    result = await httpGetService.get(trustAnchorEcUrl);
  } catch {
    return null;
  }
  if (result.status < 200 || result.status >= 300) {
    return null;
  }

  const jwt = bodyToJwt(result.body);
  const ec = await verifyEntityConfiguration(jwt, nowMs);
  if (!ec) {
    return null;
  }

  await cacheService.set(
    key,
    jwt,
    ttlBoundedByExp(result.headers, ec.exp, nowMs)
  );
  return ec;
}

/**
 * Verify a self-signed entity configuration: its signature against the
 * `jwks` it carries, `iss === sub`, an unexpired `exp`, and a federation
 * fetch endpoint. Returns `null` on any failure.
 */
async function verifyEntityConfiguration(
  jwt: string,
  nowMs: number
): Promise<VerifiedEntityConfiguration | null> {
  // The configuration is self-signed, so its keys come from the statement
  // itself. Reading them before verification is safe: if the payload was
  // altered, the signature over it fails.
  let unverified: unknown;
  try {
    unverified = jwtDecodePayload(jwt);
  } catch {
    return null;
  }
  const result = await verifyJws(
    jwt,
    (unverified as { jwks?: unknown } | null)?.jwks,
    { typ: ENTITY_STATEMENT_TYP }
  );
  if (!result.valid) {
    return null;
  }

  const { iss, sub, jwks } = result.payload;
  const exp = unexpiredNumericDate(result.payload.exp, nowMs);
  if (typeof iss !== 'string' || iss !== sub || exp === undefined) {
    return null;
  }
  const fetchEndpoint = getFederationFetchEndpoint(result.payload);
  if (!fetchEndpoint) {
    return null;
  }
  return { entityId: iss, jwks, fetchEndpoint, exp };
}

/**
 * Verify a subordinate statement for `did`: signed by one of the anchor's
 * keys, issued by the anchor's entity identifier, about `did`, and
 * unexpired. A `metadata` object is not required: OIDF subordinate
 * statements need only speak about `sub`. Returns its `exp` in seconds
 * since the epoch, or `undefined` on any failure.
 */
async function verifySubordinateStatement(
  jwt: string,
  ec: VerifiedEntityConfiguration,
  did: string,
  nowMs: number
): Promise<number | undefined> {
  const result = await verifyJws(jwt, ec.jwks, { typ: ENTITY_STATEMENT_TYP });
  if (!result.valid) {
    return undefined;
  }
  const { iss, sub } = result.payload;
  const exp = unexpiredNumericDate(result.payload.exp, nowMs);
  if (iss !== ec.entityId || sub !== did || exp === undefined) {
    return undefined;
  }
  return exp;
}

/**
 * A fetched statement body as a compact JWS. Bodies are trimmed because the
 * trailing newline some registries send belongs to the transport, and a
 * compact JWS is whitespace-sensitive.
 */
function bodyToJwt(body: unknown): string {
  return String(body ?? '').trim();
}

/**
 * `exp` as seconds since the epoch, when it is in the future; otherwise
 * `undefined`. A string of decimal digits is accepted as well as a number:
 * the spec requires a number, but a live registry (OpenSALT) signs `exp` as
 * a digit string, and the value is covered by the signature either way.
 */
function unexpiredNumericDate(exp: unknown, nowMs: number): number | undefined {
  const seconds =
    typeof exp === 'string' && /^\d+$/.test(exp) ? Number(exp) : exp;
  return typeof seconds === 'number' && seconds * 1000 > nowMs
    ? seconds
    : undefined;
}

/**
 * Cache TTL from `Cache-Control` (or the default), but never past the
 * statement's own `exp`.
 */
function ttlBoundedByExp(headers: Headers, exp: number, nowMs: number): number {
  return Math.min(
    resolveTtl(parseCacheControlMaxAge(headers)),
    exp * 1000 - nowMs
  );
}

function getFederationFetchEndpoint(decoded: unknown): string | undefined {
  const endpoint = (
    decoded as {
      metadata?: { federation_entity?: { federation_fetch_endpoint?: string } };
    }
  )?.metadata?.federation_entity?.federation_fetch_endpoint;
  return typeof endpoint === 'string' && endpoint.length > 0
    ? endpoint
    : undefined;
}

function cacheKeyForOidfEntityConfig(trustAnchorEcUrl: string): string {
  return `oidf:ec:${trustAnchorEcUrl}`;
}

function cacheKeyForOidfLookup(lookupUrl: string): string {
  return `oidf:lookup:${lookupUrl}`;
}
