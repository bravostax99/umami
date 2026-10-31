import ipaddr from 'ipaddr.js';
import ranges from './cloud-ranges.json';

/**
 * Which cloud provider, if any, an IP address belongs to.
 *
 * Visits from these networks are crawlers running a real browser or email
 * security services opening links, not people. They are still recorded, but
 * tagged `dc-<provider>` (api/send) so reports can leave them out and nothing
 * is lost. The ranges come from scripts/build-cloud-ranges.js.
 */

type Interval = { start: bigint; end: bigint; provider: string; maxEnd: bigint };

let v4: Interval[] | null = null;
let v6: Interval[] | null = null;

const toBigInt = (bytes: number[]) => bytes.reduce((n, b) => (n << 8n) | BigInt(b), 0n);

function build() {
  const four: Interval[] = [];
  const six: Interval[] = [];
  for (const [provider, cidrs] of Object.entries(ranges as Record<string, string[]>)) {
    for (const cidr of cidrs) {
      try {
        const [addr, bits] = ipaddr.parseCIDR(cidr);
        const width = addr.kind() === 'ipv4' ? 32 : 128;
        const start = toBigInt(addr.toByteArray()) & ~((1n << BigInt(width - bits)) - 1n);
        const end = start + (1n << BigInt(width - bits)) - 1n;
        (width === 32 ? four : six).push({ start, end, provider, maxEnd: end });
      } catch {
        // A malformed range is skipped, not fatal.
      }
    }
  }
  const byStart = (a: Interval, b: Interval) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0);
  // maxEnd: the furthest end of any interval up to here, so a lookup knows
  // when no earlier (larger, enclosing) range can contain the address.
  for (const list of [four, six]) {
    list.sort(byStart);
    for (let i = 1; i < list.length; i++) {
      if (list[i - 1].maxEnd > list[i].maxEnd) list[i].maxEnd = list[i - 1].maxEnd;
    }
  }
  v4 = four;
  v6 = six;
}

/** An interval containing `n`. Ranges may nest or overlap, so walk back while one still could. */
function find(list: Interval[], n: bigint): string | null {
  let lo = 0;
  let hi = list.length - 1;
  let at = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (list[mid].start <= n) {
      at = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  for (let i = at; i >= 0 && list[i].maxEnd >= n; i--) {
    if (list[i].end >= n) return list[i].provider;
  }
  return null;
}

export function cloudProvider(ip: string | undefined | null): string | null {
  if (!ip) return null;
  try {
    let addr = ipaddr.parse(ip);
    if (addr.kind() === 'ipv6' && (addr as ipaddr.IPv6).isIPv4MappedAddress()) {
      addr = (addr as ipaddr.IPv6).toIPv4Address();
    }
    if (!v4 || !v6) build();
    const n = toBigInt(addr.toByteArray());
    return find(addr.kind() === 'ipv4' ? v4! : v6!, n);
  } catch {
    return null;
  }
}
