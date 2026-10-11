/**
 * Address policy for the built-in HTTP service.
 *
 * Internal module -- not exported from `index.ts`.
 */

/** Outcome of {@link checkUrl}. `reason` is fixed text, safe to put in an error. */
export type UrlCheck = { allowed: true } | { allowed: false; reason: string };

/**
 * Decide whether the built-in HTTP service may fetch `url`.
 *
 * The verifier fetches URLs the credential chooses (contexts, did:web
 * documents, status lists, schemas). On a server, an unchecked fetch lets a
 * credential reach the server's own network. Only `https:` is allowed. The
 * host may not be `localhost` or a loopback, private, link-local, multicast,
 * reserved or unspecified IP literal. The check runs on the first URL and on
 * every redirect hop the runtime lets the service see.
 *
 * With `allowInsecure`, `http:` is allowed too and the host is not judged.
 * The URL must still parse, and other schemes are still refused. This is for
 * local development only.
 *
 * The host is judged as a name or a literal only. Browsers and React Native
 * offer no DNS lookup, so a public name that resolves to a private address
 * is not caught here.
 */
export function checkUrl(
  url: string,
  { allowInsecure = false }: { allowInsecure?: boolean } = {}
): UrlCheck {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return refused('not a valid URL');
  }

  if (allowInsecure) {
    return parsed.protocol === 'https:' || parsed.protocol === 'http:'
      ? ALLOWED
      : refused('scheme is not http or https');
  }

  if (parsed.protocol !== 'https:') {
    return refused('scheme is not https');
  }

  // Judge the parsed hostname rather than the raw string. The URL parser has
  // already turned `0x7f.1`, `2130706433` and `127.1` into `127.0.0.1`, and
  // compressed IPv6 literals.
  const host = parsed.hostname.toLowerCase().replace(/\.$/, '');

  if (host === 'localhost' || host.endsWith('.localhost')) {
    return refused('host is localhost');
  }

  if (IPV4_LITERAL.test(host)) {
    return checkIpv4(ipv4ToInt(host));
  }

  if (host.startsWith('[')) {
    return checkIpv6(host.slice(1, -1));
  }

  return ALLOWED;
}

const ALLOWED: UrlCheck = { allowed: true };

const IPV4_LITERAL = /^\d{1,3}(\.\d{1,3}){3}$/;

function refused(reason: string): UrlCheck {
  return { allowed: false, reason };
}

/**
 * IPv4 ranges the policy refuses, as `[network, mask, reason]` integers,
 * built from CIDR notation once at load.
 */
const IPV4_BLOCKED: ReadonlyArray<readonly [number, number, string]> = (
  [
    ['0.0.0.0', 8, 'host is an unspecified address'],
    ['127.0.0.0', 8, 'host is a loopback address'],
    ['10.0.0.0', 8, 'host is a private address'],
    ['172.16.0.0', 12, 'host is a private address'],
    ['192.168.0.0', 16, 'host is a private address'],
    // Carrier-grade NAT space. Treated as private because some cloud
    // providers serve instance metadata from it (e.g. 100.100.100.200).
    ['100.64.0.0', 10, 'host is a private address'],
    // Azure's wire server, which serves instance metadata from public space.
    ['168.63.129.16', 32, 'host is a private address'],
    // IETF protocol assignments (RFC 6890), not routable.
    ['192.0.0.0', 24, 'host is a reserved address'],
    ['169.254.0.0', 16, 'host is a link-local address'],
    ['224.0.0.0', 4, 'host is a multicast address'],
    // Reserved (RFC 1112), including the broadcast address.
    ['240.0.0.0', 4, 'host is a reserved address']
  ] as const
).map(([network, prefix, reason]) => {
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  return [(ipv4ToInt(network) & mask) >>> 0, mask, reason] as const;
});

function checkIpv4(address: number): UrlCheck {
  for (const [network, mask, reason] of IPV4_BLOCKED) {
    if ((address & mask) >>> 0 === network) {
      return refused(reason);
    }
  }
  return ALLOWED;
}

function ipv4ToInt(dotted: string): number {
  return (
    dotted
      .split('.')
      .reduce((acc, octet) => acc * 256 + Number.parseInt(octet, 10), 0) >>> 0
  );
}

function checkIpv6(literal: string): UrlCheck {
  const groups = expandIpv6(literal);
  const zerosUpTo = (end: number) => groups.slice(0, end).every(g => g === 0);

  if (zerosUpTo(8)) {
    return refused('host is an unspecified address');
  }
  if (zerosUpTo(7) && groups[7] === 1) {
    return refused('host is a loopback address');
  }
  // Prefixes that embed an IPv4 address in the last 32 bits: IPv4-mapped
  // (::ffff:0:0/96), IPv4-compatible (::/96) and NAT64 (64:ff9b::/96).
  // Judge the embedded IPv4 address.
  const nat64 = groups[0] === 0x0064 && groups[1] === 0xff9b;
  const mapped = zerosUpTo(5) && (groups[5] === 0xffff || groups[5] === 0);
  if (mapped || (nat64 && groups.slice(2, 6).every(g => g === 0))) {
    return checkIpv4(((groups[6] << 16) | groups[7]) >>> 0);
  }
  // 6to4 (2002::/16) embeds the IPv4 address in the second and third groups.
  if (groups[0] === 0x2002) {
    return checkIpv4(((groups[1] << 16) | groups[2]) >>> 0);
  }
  // Local-use NAT64 (64:ff9b:1::/48), unique local (fc00::/7) and the
  // deprecated site-local range (fec0::/10), still routed on some networks.
  if (
    (nat64 && groups[2] === 1) ||
    (groups[0] & 0xfe00) === 0xfc00 ||
    (groups[0] & 0xffc0) === 0xfec0
  ) {
    return refused('host is a private address');
  }
  if ((groups[0] & 0xffc0) === 0xfe80) {
    return refused('host is a link-local address');
  }
  if ((groups[0] & 0xff00) === 0xff00) {
    return refused('host is a multicast address');
  }
  return ALLOWED;
}

/**
 * Expand an IPv6 address (without brackets) into its eight 16-bit groups.
 * The URL parser has already validated and normalised the literal, so it is
 * well formed and a trailing dotted IPv4 part never appears here.
 */
function expandIpv6(literal: string): number[] {
  const [head, tail = ''] = literal.split('::');
  const headGroups = head === '' ? [] : head.split(':');
  const tailGroups = tail === '' ? [] : tail.split(':');
  const fill = Array<string>(8 - headGroups.length - tailGroups.length).fill(
    '0'
  );
  return [...headGroups, ...fill, ...tailGroups].map(g =>
    Number.parseInt(g, 16)
  );
}
