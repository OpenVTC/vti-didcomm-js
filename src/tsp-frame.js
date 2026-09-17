// Recognising a TSP frame — the one place in this library that knows how one
// is spelled.
//
// The mediator multiplexes TSP onto the same socket as DIDComm, so every
// inbound frame has to be classified before it can be parsed, and the classifier
// is key-blind: it sees the leading bytes and nothing else. Getting it wrong is
// silent in the worst direction — a TSP message handed to the DIDComm unpacker
// throws, is logged as a poison frame, and is never acked, so the mediator
// redelivers it forever while the consumer that wanted it never hears.
//
// ── Two framings, because Rev 3 widened the -E count ──
//
// A TSP message opens with the binary-CESR `-E` count code. Under spec Rev 2
// that count covered only the envelope header — a couple of dozen quadlets
// whatever the message size — so it was always the three-byte short form and
// always began `0xF8`. Rev 3 widened it to cover *all* signable content, the
// ciphertext included, so any message past 4095 quadlets (~12 KB) is framed with
// the six-byte long form instead and begins `0xFB`.
//
// In the qb64 text domain the mediator delivers, that is the difference between
// a frame starting `-E` and one starting `--E`:
//
//   short  f8 4X XX          ->  "-EAo…"    (DASH | E | count)
//   long   fb e6 XX XX XX XX ->  "--EAAB…"  (DASH | DASH | E | count)
//
// `"--EAAB…".startsWith("-E")` is false, which is why this needed fixing rather
// than merely extending: the check that was here routed every large Rev 3
// message to the DIDComm unpacker. Nothing could have caught it before Rev 3
// existed, because Rev 2 could not produce the frame.
//
// ── What is deliberately not matched ──
//
// Rev 2's long form spelled its second selector `0` (`-0E…`, from a superseded
// draft of the CESR v2 tables) rather than Rev 3's second dash. It is not
// matched here because nothing can emit it: reaching a long count under Rev 2's
// header-only semantics would need about 12 KB of VIDs in one envelope.
// Matching it would mean routing to a TSP consumer a frame no TSP
// implementation produces.
//
// Neither prefix is ambiguous against DIDComm, which is JSON (`{`) or compact
// JWS (`ey…`).

/** First byte of a TSP message framed with a short `-E` count code. */
export const TSP_MAGIC_BYTE = 0xf8;
/** First byte of a TSP message framed with a long `-E` count code (Rev 3 only,
 *  for messages past ~12 KB). */
export const TSP_MAGIC_BYTE_LONG = 0xfb;

/** qb64 text prefixes of the two framings, longest first so that matching is
 *  order-independent for a reader. */
const TSP_TEXT_PREFIXES = ["--E", "-E"];

/**
 * Does this qb64 text frame look like a TSP message?
 *
 * A pre-classifier for routing, not a validator: it inspects the count code and
 * nothing else, and the TSP consumer is what actually parses. Anything that is
 * not a TSP frame is left for the DIDComm path.
 *
 * @param {string} text - the frame as the mediator delivered it (base64url qb2).
 * @returns {boolean}
 */
export function isTspFrameText(text) {
  return typeof text === "string" && TSP_TEXT_PREFIXES.some((p) => text.startsWith(p));
}

/**
 * Does this byte sequence look like a TSP message?
 *
 * The binary-domain twin of {@link isTspFrameText}, for callers holding qb2
 * bytes rather than the text form — and the same predicate the mediator applies
 * at ingress (`affinidi_tsp::is_tsp`) and the wallet's TSP codec applies to
 * outbound bytes (`@openvtc/vti-tsp-js`'s `isTsp`). All three must accept both
 * framings or a large message is dropped at whichever one lags.
 *
 * @param {Uint8Array} bytes
 * @returns {boolean}
 */
export function isTspFrameBytes(bytes) {
  const first = bytes?.[0];
  return first === TSP_MAGIC_BYTE || first === TSP_MAGIC_BYTE_LONG;
}
