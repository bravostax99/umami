/* eslint-disable no-console */
/**
 * Cloud and data-centre networks, for marking automated visits (src/lib/cloud.ts).
 *
 * Crawlers that run a real browser get past the user-agent bot check, and email
 * security services (Microsoft Safe Links, for one) open the links in emails
 * from their own networks. Neither is a person. Each provider publishes its
 * address ranges; this fetches them at build time into src/lib/cloud-ranges.json.
 *
 * A provider that cannot be fetched keeps the ranges already in the file, so a
 * build never fails over this and never quietly loses a provider.
 */
import fs from 'node:fs';
import path from 'node:path';

const OUT = path.resolve(process.cwd(), 'src/lib/cloud-ranges.json');
const UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36';

const get = async (url, as = 'json') => {
  const res = await fetch(url, {
    headers: { 'user-agent': UA, accept: 'text/html,application/json,*/*', 'accept-language': 'en-US' },
    signal: AbortSignal.timeout(60_000),
  });
  if (!res.ok) throw new Error(`${url}: ${res.status}`);
  return as === 'json' ? res.json() : res.text();
};

const csvFirstColumn = text =>
  text
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'))
    .map(l => l.split(',')[0].trim());

const PROVIDERS = {
  aws: async () => {
    const d = await get('https://ip-ranges.amazonaws.com/ip-ranges.json');
    return [...d.prefixes.map(p => p.ip_prefix), ...d.ipv6_prefixes.map(p => p.ipv6_prefix)];
  },
  google: async () => {
    const d = await get('https://www.gstatic.com/ipranges/cloud.json');
    return d.prefixes.map(p => p.ipv4Prefix || p.ipv6Prefix);
  },
  azure: async () => {
    const page = await get('https://www.microsoft.com/en-us/download/details.aspx?id=56519', 'text');
    const url = page.match(/https:\/\/download\.microsoft\.com\/[^"]*ServiceTags_Public_\d+\.json/)?.[0];
    if (!url) throw new Error('Azure service tags link not found');
    const d = await get(url);
    return d.values.find(v => v.name === 'AzureCloud').properties.addressPrefixes;
  },
  // Exchange Online, where Safe Links checks the links in incoming mail.
  microsoft365: async () => {
    const d = await get(
      'https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7',
    );
    return d.filter(e => e.serviceArea === 'Exchange').flatMap(e => e.ips || []);
  },
  oracle: async () => {
    const d = await get('https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json');
    return d.regions.flatMap(r => r.cidrs.map(c => c.cidr));
  },
  digitalocean: async () => csvFirstColumn(await get('https://digitalocean.com/geo/google.csv', 'text')),
  linode: async () => csvFirstColumn(await get('https://geoip.linode.com/', 'text')),
};

const previous = fs.existsSync(OUT) ? JSON.parse(fs.readFileSync(OUT, 'utf8')) : {};
const out = {};

for (const [name, load] of Object.entries(PROVIDERS)) {
  try {
    const cidrs = [...new Set((await load()).filter(c => /^[0-9a-f:.]+\/\d+$/i.test(c)))].sort();
    if (!cidrs.length) throw new Error('no ranges');
    out[name] = cidrs;
    console.log(`cloud ranges: ${name} ${cidrs.length}`);
  } catch (e) {
    out[name] = previous[name] || [];
    console.warn(`cloud ranges: ${name} not refreshed (${e.message}); kept ${out[name].length}`);
  }
}

fs.writeFileSync(OUT, JSON.stringify(out));
