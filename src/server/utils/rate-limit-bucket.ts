import { isIPv6 } from 'node:net'

/** Groups in a full IPv6 address. */
const IPV6_GROUPS = 8

/** Groups kept when charging an IPv6 address to its /64 prefix. */
const IPV6_PREFIX_GROUPS = 4

/**
 * Collapses a client address to the unit a rate limit should actually be charged against.
 *
 * IPv4 is returned unchanged: one address is one host, and the smallest routine allocation is a
 * single address.
 *
 * IPv6 is truncated to its /64 prefix, because there the address is not the unit. A /64 is the
 * standard end-site subnet — the smallest thing a residential or cloud customer is handed — and
 * every one of its 2^64 addresses is free to mint and free to rotate. Keying on the full /128
 * therefore hands one attacker 2^64 independent budgets: the per-route counter is per key, so
 * "5 login attempts per minute" becomes 5 attempts per address per minute, which is no limit at
 * all. Charging the /64 makes the budget belong to the subnet that was actually allocated to
 * somebody.
 *
 * The cost is that hosts sharing a /64 share a budget. That is the same trade IPv4 NAT already
 * forces, and it is the correct side of it: the alternative is a limiter an attacker steps
 * around by incrementing a counter.
 *
 * IPv4-mapped addresses (`::ffff:1.2.3.4`) unwrap to their IPv4 form **before** any truncation.
 * This is not an edge case on Node: a dual-stack listener reports every IPv4 peer in that form,
 * so it is the ordinary shape of `socket.remoteAddress`. Truncating one to /64 would send every
 * IPv4 client to the single key `::`, collapsing the entire IPv4 internet into one bucket — a
 * denial of service against legitimate users, delivered by the anti-abuse control itself.
 *
 * Anything that is not a recognisable IPv6 address is returned untouched, which covers IPv4 and
 * the caller's own "address unavailable" sentinel.
 *
 * @param address - The client address, as read from the socket or the forwarding header.
 * @returns The address to key the counter on.
 */
export function rateLimitBucket(address: string): string {
  // A zone index (`fe80::1%eth0`) is link-local scope, not identity, and never part of a prefix.
  const zoneIndex = address.indexOf('%')
  const zoneless = zoneIndex === -1 ? address : address.slice(0, zoneIndex)
  if (!isIPv6(zoneless)) return address

  const groups = expandIPv6(zoneless)

  const mapped = toMappedIPv4(groups)
  if (mapped !== null) return mapped

  return groups
    .slice(0, IPV6_PREFIX_GROUPS)
    .concat(Array<number>(IPV6_GROUPS - IPV6_PREFIX_GROUPS).fill(0))
    .map((group) => group.toString(16))
    .join(':')
}

/**
 * Expands any textual IPv6 form into its eight numeric groups.
 *
 * Handles `::` compression and a trailing embedded IPv4 (`::ffff:1.2.3.4`), which is the form a
 * dual-stack socket reports.
 *
 * Total, because the caller has already run `isIPv6`. That check is what rejects a second `::`,
 * a group count other than eight, and an out-of-range octet in an embedded quad — verified
 * against Node directly rather than assumed — so re-testing any of it here would be branches no
 * input can reach, and a reader would have to work out that they are unreachable rather than
 * being told. The precondition is the contract: do not call this without that gate.
 */
function expandIPv6(address: string): number[] {
  let text = address
  const lastColon = text.lastIndexOf(':')
  const tail = text.slice(lastColon + 1)

  // A trailing dotted quad occupies the final two groups. Packed by folding rather than by
  // indexing: `noUncheckedIndexedAccess` would otherwise demand a fallback per octet, and each
  // one would be a branch no input can reach.
  if (tail.includes('.')) {
    const packed = tail.split('.').reduce((acc, octet) => (acc << 8) | Number(octet), 0)
    const high = (packed >>> 16) & 0xffff
    const low = packed & 0xffff
    text = `${text.slice(0, lastColon + 1)}${high.toString(16)}:${low.toString(16)}`
  }

  // `split` always yields at least one element, so `head` is a string; the cast says that once
  // rather than defaulting it and leaving an unreachable branch behind.
  const [head, compressed] = text.split('::') as [string, string | undefined]

  const parse = (part: string): number[] =>
    part === '' ? [] : part.split(':').map((group) => parseInt(group, 16))

  const left = parse(head)
  // No `::` means the address is already written out in full.
  if (compressed === undefined) return left

  const right = parse(compressed)
  const missing = IPV6_GROUPS - left.length - right.length
  return [...left, ...Array<number>(missing).fill(0), ...right]
}

/**
 * Returns the dotted-quad form when these groups are an IPv4-mapped address, otherwise `null`.
 *
 * The mapped range is `::ffff:0:0/96`: five zero groups, then `ffff`, then the IPv4 address in
 * the final two.
 */
function toMappedIPv4(groups: number[]): string | null {
  const isMapped = groups.slice(0, 5).every((group) => group === 0) && groups[5] === 0xffff
  if (!isMapped) return null

  // Reached only when group 5 is `ffff`, which means eight groups were parsed, so the last two
  // are present. The cast states that once; defaulting them would leave two branches no input
  // can reach.
  const [high, low] = groups.slice(6) as [number, number]
  return [high >> 8, high & 0xff, low >> 8, low & 0xff].join('.')
}
