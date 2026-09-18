// Egress guard for URLs this library did not choose.
//
// Mediator endpoints come out of a resolved DID document, and a VTA base
// URL usually arrives from a QR code or stored config. Neither is a URL
// the caller has vetted, so before dialing one the SDK checks it here:
//
//   - the scheme is one of the network schemes the call site expects
//     (https/wss by default; http/ws only with `allowInsecure`);
//   - there is no userinfo (`https://user:pass@host/`);
//   - the host is not a special-use name (`localhost`, `*.localhost`,
//     `*.local`, `*.internal`, `*.home.arpa`) and not an IP literal in a
//     non-public range (loopback, RFC 1918, link-local / cloud metadata,
//     CGNAT, IPv4-mapped / -compatible IPv6, NAT64, ULA, …), unless
//     `allowPrivate` is set;
//   - if `allowHosts` is given, the host matches one of its entries.
//     The allow-list only ever narrows: it never re-admits a blocked
//     address.
//
// The WHATWG `URL` parser has already canonicalised the host by the time
// it is checked, so `https://2130706433/`, `https://0x7f.1/` and
// `https://[::ffff:7f00:1]/` are all seen as loopback.
//
// What this cannot do: a hostname that *resolves* to a private address
// passes the literal check. Browsers and extension service workers expose
// no DNS API, so there `allowHosts` is the strong control. In Node, pair
// this with `guardedLookup` from `./net-guard/node`, which filters the
// resolved addresses at connect time.
//
// This module deliberately imports nothing from the rest of the package,
// so it can be lifted into a standalone package without an API change.

/** Stable `code` carried by every {@link BlockedEndpointError}. */
export const BLOCKED_ENDPOINT = "E_BLOCKED_ENDPOINT";

/**
 * Why an endpoint was refused.
 * @typedef {"invalid_url" | "scheme" | "userinfo" | "private_address" | "private_name" | "not_allowlisted" | "redirect"} BlockedReason
 */

/**
 * Network policy for endpoints the caller did not choose. Every field
 * defaults to the strict setting.
 *
 * @typedef {Object} NetPolicy
 * @property {boolean} [allowInsecure] - also permit the plaintext
 *   scheme (`http:` / `ws:`) next to each secure one. Scheme only: it
 *   does NOT admit private hosts.
 * @property {boolean} [allowPrivate] - permit special-use names
 *   (`localhost`, `*.local`, …) and non-public IP literals. Local
 *   development only.
 * @property {string[] | null} [allowHosts] - if set, the host must match
 *   an entry: an exact host (`"mediator.example"`) or a `*.` suffix
 *   (`"*.vta.example"`, which matches subdomains but not the apex). An
 *   empty array admits nothing.
 */

/**
 * {@link NetPolicy} plus the call-site settings for one endpoint.
 *
 * @typedef {Object} EndpointPolicy
 * @property {string} [label] - names the endpoint in error messages.
 * @property {string[]} [schemes] - secure schemes accepted, from
 *   `https:` and `wss:` (default both). `http:` / `ws:` may be listed
 *   explicitly, but `allowInsecure` is the usual way to admit them.
 * @property {boolean} [allowInsecure]
 * @property {boolean} [allowPrivate]
 * @property {string[] | null} [allowHosts]
 */

/** Thrown when an endpoint fails the egress policy. */
export class BlockedEndpointError extends Error {
  /**
   * @param {string} message
   * @param {Object} [details]
   * @param {BlockedReason} [details.reason]
   * @param {string} [details.url] - the endpoint, without userinfo,
   *   query or fragment.
   * @param {string} [details.host] - the canonical host that was checked.
   * @param {string} [details.label]
   */
  constructor(message, { reason, url, host, label } = {}) {
    super(message);
    this.name = "BlockedEndpointError";
    /** @type {"E_BLOCKED_ENDPOINT"} */
    this.code = BLOCKED_ENDPOINT;
    /** @type {BlockedReason | undefined} */
    this.reason = reason;
    /** @type {string | undefined} */
    this.url = url;
    /** @type {string | undefined} */
    this.host = host;
    /** @type {string | undefined} */
    this.label = label;
  }
}

// ─── IP classification ─────────────────────────────────────────────────

// [network, prefix length]. Mirrors the affinidi-did-web classifier, plus
// the documentation ranges from the SEC-4045 conformance vectors.
const V4_BLOCKED = [
  ["0.0.0.0", 8], //        "this network"
  ["10.0.0.0", 8], //       private (RFC 1918)
  ["100.64.0.0", 10], //    shared address space / CGNAT (Alibaba metadata 100.100.100.200)
  ["127.0.0.0", 8], //      loopback
  ["169.254.0.0", 16], //   link-local (cloud metadata 169.254.169.254)
  ["172.16.0.0", 12], //    private (RFC 1918)
  ["192.0.0.0", 24], //     IETF protocol assignments
  ["192.0.2.0", 24], //     documentation (TEST-NET-1)
  ["192.168.0.0", 16], //   private (RFC 1918)
  ["198.18.0.0", 15], //    benchmarking
  ["198.51.100.0", 24], //  documentation (TEST-NET-2)
  ["203.0.113.0", 24], //   documentation (TEST-NET-3)
  ["224.0.0.0", 4], //      multicast
  ["240.0.0.0", 4], //      reserved, incl. 255.255.255.255 broadcast
].map(([net, prefix]) => [v4ToUint(parseIpv4(net)), prefix]);

/**
 * True if `ip` is an address the SDK must not dial by default.
 *
 * Accepts a dotted-quad IPv4 address or an IPv6 address (brackets
 * optional). IPv6 forms that embed an IPv4 address (IPv4-mapped
 * `::ffff:0:0/96`, IPv4-compatible `::/96`, NAT64 `64:ff9b::/96`, 6to4
 * `2002::/16`) are judged by the embedded address.
 *
 * Fails closed: anything that is not a well-formed IP literal (including
 * a hostname, a zone-scoped address, or an octal-looking `0177.0.0.1`)
 * returns `true`.
 *
 * @param {string} ip
 * @returns {boolean}
 */
export function isBlockedIp(ip) {
  if (typeof ip !== "string") {
    throw new TypeError("net-guard: isBlockedIp expects a string");
  }
  const v4 = parseIpv4(ip);
  if (v4) return v4Blocked(v4ToUint(v4));
  const v6 = parseIpv6(ip);
  if (v6) return v6Blocked(v6);
  return true;
}

function v4Blocked(n) {
  for (const [net, prefix] of V4_BLOCKED) {
    const shift = 32 - prefix;
    if (n >>> shift === net >>> shift) return true;
  }
  return false;
}

function v6Blocked(g) {
  const zeros = (from, to) => g.slice(from, to).every((x) => x === 0);
  const embedded = (hi, lo) => v4Blocked(((hi << 16) >>> 0) + lo);

  // ::/96: unspecified (::), loopback (::1) and IPv4-compatible
  // (::a.b.c.d). `::` and `::1` land in 0.0.0.0/8 and are blocked.
  if (zeros(0, 6)) return embedded(g[6], g[7]);
  // ::ffff:0:0/96 IPv4-mapped.
  if (zeros(0, 5) && g[5] === 0xffff) return embedded(g[6], g[7]);
  // ::ffff:0:0:0/96 IPv4-translated (RFC 2765).
  if (zeros(0, 4) && g[4] === 0xffff && g[5] === 0) return embedded(g[6], g[7]);
  // 64:ff9b::/96 well-known NAT64 prefix.
  if (g[0] === 0x64 && g[1] === 0xff9b && zeros(2, 6)) return embedded(g[6], g[7]);
  // 64:ff9b:1::/48 local-use NAT64: can translate to anything.
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 1) return true;
  // 2002::/16 6to4: the IPv4 address sits in groups 1-2.
  if (g[0] === 0x2002) return embedded(g[1], g[2]);
  // 2001::/23 IETF protocol assignments (Teredo 2001::/32, benchmarking,
  // ORCHID).
  if (g[0] === 0x2001 && g[1] < 0x200) return true;
  // 2001:db8::/32 and 3fff::/20 documentation.
  if (g[0] === 0x2001 && g[1] === 0xdb8) return true;
  if (g[0] === 0x3fff && (g[1] & 0xf000) === 0) return true;
  // Everything else outside 2000::/3 global unicast is reserved or local
  // (100::/64 discard, fc00::/7 ULA incl. AWS IMDSv6 fd00:ec2::254,
  // fe80::/10 link-local, fec0::/10 site-local, ff00::/8 multicast).
  if ((g[0] & 0xe000) !== 0x2000) return true;
  return false;
}

// Strict dotted-quad: four decimal octets, no leading zeros.
function parseIpv4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const out = [];
  for (let i = 1; i <= 4; i++) {
    if (m[i].length > 1 && m[i][0] === "0") return null;
    const n = Number(m[i]);
    if (n > 255) return null;
    out.push(n);
  }
  return out;
}

function v4ToUint([a, b, c, d]) {
  return ((a << 24) >>> 0) + (b << 16) + (c << 8) + d;
}

// RFC 4291 text form → eight 16-bit groups, or null. Zone IDs are refused.
function parseIpv6(input) {
  let s = input;
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  if (!/^[0-9A-Fa-f:.]+$/.test(s)) return null;
  const lastColon = s.lastIndexOf(":");
  if (lastColon === -1) return null;

  let tail = [];
  if (s.includes(".")) {
    const v4 = parseIpv4(s.slice(lastColon + 1));
    if (!v4) return null;
    tail = [(v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]];
    s = s.slice(0, lastColon + 1);
    if (!s.endsWith("::")) s = s.slice(0, -1);
  }

  const want = 8 - tail.length;
  const groups = (part) => {
    if (part === "") return [];
    const out = [];
    for (const piece of part.split(":")) {
      if (!/^[0-9A-Fa-f]{1,4}$/.test(piece)) return null;
      out.push(parseInt(piece, 16));
    }
    return out;
  };

  const gap = s.indexOf("::");
  if (gap === -1) {
    const all = groups(s);
    if (!all || all.length !== want) return null;
    return [...all, ...tail];
  }
  if (gap !== s.lastIndexOf("::")) return null;
  const head = groups(s.slice(0, gap));
  const rest = groups(s.slice(gap + 2));
  if (!head || !rest) return null;
  const fill = want - head.length - rest.length;
  if (fill < 1) return null;
  return [...head, ...new Array(fill).fill(0), ...rest, ...tail];
}

// ─── URL policy ────────────────────────────────────────────────────────

const NETWORK_SCHEMES = new Set(["https:", "wss:", "http:", "ws:"]);
const PLAINTEXT_OF = { "https:": "http:", "wss:": "ws:" };
const BLOCKED_NAME_SUFFIXES = [".localhost", ".local", ".internal", ".home.arpa"];

/**
 * Check a URL against the egress policy before dialing it.
 *
 * @param {string | URL} url
 * @param {EndpointPolicy} [policy]
 * @returns {URL} the parsed URL, for the caller to dial.
 * @throws {BlockedEndpointError} if the URL is invalid or not allowed.
 * @throws {TypeError} if the policy itself is malformed.
 */
export function assertSafeEndpoint(url, policy = {}) {
  const { label = "endpoint", allowPrivate = false } = policy ?? {};
  const schemes = normalizeSchemes(policy?.schemes, policy?.allowInsecure);
  const allowList = normalizeAllowHosts(policy?.allowHosts);

  let parsed;
  try {
    if (typeof url !== "string" && !(url instanceof URL)) throw new Error("not a URL");
    parsed = new URL(String(url));
  } catch {
    throw new BlockedEndpointError(`net-guard: ${label} endpoint is not a valid absolute URL`, {
      reason: "invalid_url",
      label,
    });
  }

  const shown = displayUrl(parsed);
  const refuse = (reason, why, host) =>
    new BlockedEndpointError(`net-guard: ${label} endpoint ${shown} refused: ${why}`, {
      reason,
      url: shown,
      host,
      label,
    });

  if (!schemes.has(parsed.protocol)) {
    const hint = Object.values(PLAINTEXT_OF).includes(parsed.protocol)
      ? " (plaintext transport needs allowInsecure)"
      : "";
    throw refuse("scheme", `scheme ${parsed.protocol} is not allowed${hint}`);
  }
  if (parsed.username !== "" || parsed.password !== "") {
    throw refuse("userinfo", "credentials in the URL are not allowed");
  }

  const bracketed = parsed.hostname.startsWith("[");
  const host = canonicalHost(parsed.hostname);
  if (host === "") {
    throw new BlockedEndpointError(`net-guard: ${label} endpoint has no host`, {
      reason: "invalid_url",
      label,
    });
  }

  if (!allowPrivate) {
    if (bracketed || parseIpv4(host)) {
      if (isBlockedIp(host)) {
        throw refuse("private_address", `${host} is not a public address (set allowPrivate for local development)`, host);
      }
    } else if (isBlockedName(host)) {
      throw refuse("private_name", `${host} is a local-only name (set allowPrivate for local development)`, host);
    }
  }

  if (allowList && !hostAllowed(host, allowList)) {
    throw refuse("not_allowlisted", `${host} is not in allowHosts`, host);
  }

  return parsed;
}

/**
 * Wrap a `fetch` so every request is checked by {@link assertSafeEndpoint}
 * first and never follows a redirect.
 *
 * The wrapper forces `redirect: "manual"`. A 3xx response (Node) or an
 * `opaqueredirect` response (browsers) is rejected with a
 * {@link BlockedEndpointError} whose `reason` is `"redirect"`, so the
 * redirect target is never requested. A custom `fetchImpl` must honour
 * `redirect: "manual"` for that guarantee to hold.
 *
 * @param {Function | null | undefined} fetchImpl - defaults to `globalThis.fetch`.
 * @param {EndpointPolicy} [policy]
 * @returns {(input: string | URL | { url: string }, init?: Object) => Promise<Response>}
 */
export function guardedFetch(fetchImpl, policy = {}) {
  const impl = fetchImpl ?? globalThis.fetch;
  if (typeof impl !== "function") {
    throw new TypeError("net-guard: guardedFetch needs a fetch implementation");
  }
  // Validate the policy now, so a malformed allow-list fails at wiring time.
  normalizeSchemes(policy?.schemes, policy?.allowInsecure);
  normalizeAllowHosts(policy?.allowHosts);
  const label = policy?.label ?? "endpoint";

  return async function netGuardedFetch(input, init) {
    const target = typeof input === "string" || input instanceof URL ? input : input?.url;
    const parsed = assertSafeEndpoint(target, policy);
    const resp = await impl(input, { ...(init ?? {}), redirect: "manual" });
    if (resp?.type === "opaqueredirect" || (resp?.status >= 300 && resp?.status < 400)) {
      try {
        await resp.body?.cancel?.();
      } catch {
        // Nothing to release, or already consumed.
      }
      const shown = displayUrl(parsed);
      const err = new BlockedEndpointError(
        `net-guard: ${label} endpoint ${shown} answered with a redirect${resp.status ? ` (${resp.status})` : ""}; redirects are not followed`,
        { reason: "redirect", url: shown, host: canonicalHost(parsed.hostname), label },
      );
      err.status = resp.status;
      throw err;
    }
    return resp;
  };
}

// ─── Internals ─────────────────────────────────────────────────────────

function normalizeSchemes(schemes, allowInsecure) {
  const list = schemes ?? ["https:", "wss:"];
  if (!Array.isArray(list) || list.length === 0) {
    throw new TypeError("net-guard: schemes must be a non-empty array");
  }
  const out = new Set();
  for (const raw of list) {
    if (typeof raw !== "string") throw new TypeError("net-guard: schemes entries must be strings");
    const s = raw.toLowerCase().endsWith(":") ? raw.toLowerCase() : `${raw.toLowerCase()}:`;
    if (!NETWORK_SCHEMES.has(s)) {
      throw new TypeError(`net-guard: unsupported scheme ${JSON.stringify(raw)} (use https:, wss:, http: or ws:)`);
    }
    out.add(s);
    if (allowInsecure && PLAINTEXT_OF[s]) out.add(PLAINTEXT_OF[s]);
  }
  return out;
}

function normalizeAllowHosts(allowHosts) {
  if (allowHosts == null) return null;
  if (!Array.isArray(allowHosts)) {
    throw new TypeError("net-guard: allowHosts must be an array of host names, or null");
  }
  return allowHosts.map((entry) => {
    if (typeof entry !== "string") throw new TypeError("net-guard: allowHosts entries must be strings");
    const invalid = () =>
      new TypeError(
        `net-guard: invalid allowHosts entry ${JSON.stringify(entry)} (host names only, no scheme, port or path)`,
      );
    const trimmed = entry.trim().toLowerCase();
    const wildcard = trimmed.startsWith("*.");
    const name = wildcard ? trimmed.slice(2) : trimmed;
    if (name === "" || /[/@?#\s*]/.test(name)) throw invalid();
    // A colon is only legal inside an IPv6 literal; anything else is a port.
    let authority = name;
    if (!name.startsWith("[") && name.includes(":")) {
      if (!parseIpv6(name)) throw invalid();
      authority = `[${name}]`;
    }
    let host;
    try {
      const u = new URL(`https://${authority}/`);
      if (u.port !== "") throw invalid();
      host = canonicalHost(u.hostname);
    } catch {
      throw invalid();
    }
    return wildcard ? { suffix: `.${host}` } : { exact: host };
  });
}

function hostAllowed(host, allowList) {
  return allowList.some((rule) =>
    rule.exact !== undefined ? host === rule.exact : host.length > rule.suffix.length && host.endsWith(rule.suffix),
  );
}

function isBlockedName(host) {
  // A bare single-label host (no dot) is never a public FQDN: it can only be an
  // internal name (`localhost`, `intranet`, `metadata`, `router`) or a
  // decimal/hex IP spelling the dotted-quad `parseIpv4` check above didn't
  // catch. Reject it. The browser wallet's own did:webvh guard already blocks
  // single-label hosts; this brings the library's name check in line (SEC #15).
  // Only reached for non-IP-literal hosts (IPv4/IPv6 literals are handled by the
  // `isBlockedIp` branch before this is called).
  if (!host.includes(".")) return true;
  return BLOCKED_NAME_SUFFIXES.some((suffix) => host.endsWith(suffix));
}

function canonicalHost(hostname) {
  let h = hostname.toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) return h.slice(1, -1);
  return h.replace(/\.+$/, "");
}

// Scheme, host, port and path only: no userinfo, query or fragment.
function displayUrl(parsed) {
  return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
}
