// Node-only half of the egress guard: filter what a hostname resolves to.
//
// `assertSafeEndpoint` (./net-guard.js) can only judge the URL text, so a
// public-looking name whose DNS answer is 127.0.0.1 or 169.254.169.254
// still passes it. `guardedLookup` closes that gap at connect time: it is a
// drop-in `lookup` for `net.connect`, `http(s).request`, `https.Agent` and
// undici's `Agent({ connect: { lookup } })`. It resolves every address,
// refuses the whole name if ANY answer is non-public, and hands the socket
// only the vetted addresses — so there is no second lookup to rebind.
//
// Exported as `@openvtc/vti-didcomm-js/net-guard/node`, a separate subpath,
// so browser and extension bundles never pull in `node:dns`.

import { lookup as dnsLookup } from "node:dns";
import { BlockedEndpointError, isBlockedIp } from "./net-guard.js";

/**
 * Build a `dns.lookup`-compatible function that refuses hostnames
 * resolving to a non-public address.
 *
 * @param {Object} [policy]
 * @param {boolean} [policy.allowPrivate=false] - skip the address check
 *   (local development only).
 * @param {string} [policy.label="endpoint"] - names the endpoint in errors.
 * @param {Function} [policy.lookup] - the underlying resolver, with the
 *   `dns.lookup(hostname, options, callback)` signature. Defaults to
 *   `dns.lookup`; injectable for tests.
 * @returns {(hostname: string, options: Object | number | Function, callback?: Function) => void}
 */
export function guardedLookup(policy = {}) {
  const { allowPrivate = false, label = "endpoint", lookup = dnsLookup } = policy ?? {};
  if (typeof lookup !== "function") {
    throw new TypeError("net-guard: guardedLookup policy.lookup must be a function");
  }

  return function netGuardedLookup(hostname, options, callback) {
    let opts = options;
    let cb = callback;
    if (typeof opts === "function") {
      cb = opts;
      opts = {};
    } else if (typeof opts === "number") {
      opts = { family: opts };
    }
    opts = opts ?? {};

    lookup(hostname, { ...opts, all: true }, (err, addresses) => {
      if (err) return cb(err);
      const list = Array.isArray(addresses) ? addresses : [];
      if (list.length === 0) {
        const empty = new Error(`net-guard: ${hostname} resolved to no addresses`);
        empty.code = "ENOTFOUND";
        return cb(empty);
      }
      if (!allowPrivate) {
        const bad = list.find((a) => isBlockedIp(String(a?.address)));
        if (bad) {
          return cb(
            new BlockedEndpointError(
              `net-guard: ${label} host ${hostname} refused: it resolves to non-public address ${bad.address}`,
              { reason: "private_address", host: hostname, label },
            ),
          );
        }
      }
      if (opts.all) return cb(null, list);
      return cb(null, list[0].address, list[0].family);
    });
  };
}
