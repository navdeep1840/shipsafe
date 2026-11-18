#!/usr/bin/env node
// Passive website security scanner. Normal GET requests only (homepage, http->https redirect,
// /.well-known/security.txt) plus public DNS lookups. No probing for secrets/exposed files:
// that is only safe on sites you own, so it is opt-in via --owned.
//
// Usage: see HELP below, or run `node scan.mjs --help`.
import tls from 'node:tls';
import dns from 'node:dns/promises';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Says who we are, so site owners can recognise (and block) the scan. Tested on 40 sites: no more blocks than a Chrome UA.
const UA = 'Mozilla/5.0 (compatible; shipsafe/0.1; +https://github.com/navdeep1840/shipsafe)';
const TIMEOUT = 15000;
const MAX_BODY = 3_000_000;

async function get(url, extraHeaders = {}) {
  const r = await fetch(url, { redirect: 'manual', headers: { 'user-agent': UA, ...extraHeaders }, signal: AbortSignal.timeout(TIMEOUT) });
  return r;
}

// Follow redirects by hand so we can see whether http:// ever lands on https://.
async function follow(url, extraHeaders) {
  const chain = [];
  for (let i = 0; i < 10; i++) {
    const r = await get(url, extraHeaders);
    chain.push({ url, status: r.status });
    const loc = r.headers.get('location');
    if (r.status >= 300 && r.status < 400 && loc) { url = new URL(loc, url).href; continue; }
    return { res: r, url, chain };
  }
  throw new Error('too many redirects');
}

// Approximate registrable domain: last two labels, or three for ccTLD second levels (co.uk, com.au...).
// Ceiling: not the full Public Suffix List (e.g. github.io tenants); a PSL lookup is the upgrade.
const site = (h) => { const p = h.split('.'); return p.slice(p.length > 2 && p.at(-1).length === 2 && /^(co|com|org|net|gov|edu|ac|or|ne|go)$/.test(p.at(-2)) ? -3 : -2).join('.'); };

function tlsInfo(host) {
  return new Promise((resolve) => {
    const s = tls.connect({ host, port: 443, servername: host, timeout: TIMEOUT }, () => {
      const c = s.getPeerCertificate();
      resolve({ protocol: s.getProtocol(), certDaysLeft: c.valid_to ? Math.round((new Date(c.valid_to) - Date.now()) / 864e5) : null, authorized: s.authorized, authError: s.authorizationError || null });
      s.end();
    });
    s.on('error', (e) => resolve({ error: e.code || e.message }));
    s.on('timeout', () => { s.destroy(); resolve({ error: 'timeout' }); });
  });
}

async function txt(name) { try { return (await dns.resolveTxt(name)).map((r) => r.join('')); } catch { return []; } }

async function dnsChecks(domain) {
  const [root, dmarc] = await Promise.all([txt(domain), txt('_dmarc.' + domain)]);
  let caa = [];
  try { caa = await dns.resolveCaa(domain); } catch {}
  const d = dmarc.find((t) => /^v=DMARC1/i.test(t));
  return {
    spf: root.find((t) => /^v=spf1/i.test(t)) || null,
    dmarc: d || null,
    dmarcPolicy: d ? (d.match(/;\s*p=(\w+)/i) || [])[1]?.toLowerCase() || null : null,
    caa: caa.length > 0,
  };
}

// CSP parsing per CSP3: a header may carry several policies separated by ",", directive names and
// keywords are case-insensitive, and the first occurrence of a directive wins.
export function parseCsp(v) {
  return (v || '').split(',').map((policy) => {
    const dirs = {};
    for (const part of policy.split(';')) {
      const [name, ...vals] = part.trim().split(/\s+/);
      if (name && !(name.toLowerCase() in dirs)) dirs[name.toLowerCase()] = vals.map((x) => (x.startsWith("'") ? x.toLowerCase() : x));
    }
    return dirs;
  }).filter((d) => Object.keys(d).length);
}

const ANY_HOST = ['*', 'https:', 'http:', 'https://*', 'http://*', 'data:', 'blob:'];
// How one policy treats scripts. Element loading falls back script-src-elem -> script-src -> default-src.
function scriptPolicy(d) {
  const src = d['script-src-elem'] || d['script-src'] || d['default-src'] || null;
  const evalSrc = d['script-src'] || d['default-src'] || null;
  if (!src) return null;
  const hasNonceOrHash = src.some((x) => /^'(nonce-|sha(256|384|512)-)/.test(x));
  return {
    unsafeInline: src.includes("'unsafe-inline'") && !hasNonceOrHash,
    unsafeEval: !!evalSrc && evalSrc.includes("'unsafe-eval'"), // 'wasm-unsafe-eval' only allows WebAssembly, not eval()
    strictDynamic: src.includes("'strict-dynamic'"),
    anyHost: src.some((x) => ANY_HOST.includes(x)) && !src.includes("'strict-dynamic'"),
  };
}

// Pure header analysis so every rule can be unit-tested. `h` maps lowercase header name -> value
// (duplicate headers arrive comma-joined, exactly as fetch() returns them).
export function analyzeHeaders(h, meta = {}) {
  const get = (n) => h[n] ?? null;
  const first = (n) => (get(n) || '').split(',')[0].trim();
  // <meta http-equiv=CSP> is enforced too, except frame-ancestors / report-uri / sandbox (CSP3 §6.4).
  const metaPols = parseCsp(meta.csp).map((d) => { const { 'frame-ancestors': _f, 'report-uri': _r, sandbox: _s, ...rest } = d; return rest; });
  const enforced = [...parseCsp(get('content-security-policy')), ...metaPols];
  const reportOnly = parseCsp(get('content-security-policy-report-only'));
  // Browsers enforce every policy, so scripts are as restricted as the strictest policy.
  const pols = enforced.map(scriptPolicy).filter(Boolean);
  const score = (p) => (p.anyHost || p.strictDynamic ? 0 : 2) + (p.unsafeEval ? 0 : 1);
  const best = pols.sort((a, b) => score(b) - score(a))[0] || null;
  const roPols = reportOnly.map(scriptPolicy).filter(Boolean);
  // RFC 6797: only the first STS header counts; directives are `name[=value]` with an optionally quoted value.
  // A header whose whole value is quoted (common nginx mistake) or a malformed max-age is ignored by browsers.
  const sts = first('strict-transport-security');
  const hstsMaxAge = sts.startsWith('"') ? 0 : Number(sts.split(';').map((x) => x.trim().match(/^max-age\s*=\s*"?(\d+)"?$/i)?.[1]).find(Boolean) || 0);
  const xfoVals = (get('x-frame-options') || '').split(',').map((x) => x.trim().toUpperCase()).filter(Boolean);
  const xfoOk = xfoVals.length > 0 && new Set(xfoVals).size === 1 && ['DENY', 'SAMEORIGIN'].includes(xfoVals[0]);
  const fa = enforced.find((d) => d['frame-ancestors'])?.['frame-ancestors'];
  const faOk = !!fa && !fa.includes('*') && !fa.includes('https:') && !fa.includes('http:');
  // Referrer-Policy: the last recognised token wins.
  const RP = ['no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url'];
  // <meta name=referrer> is honoured by browsers and overrides the header for the document.
  const rp = (meta.referrer || get('referrer-policy') || '').toLowerCase().split(',').map((x) => x.trim()).filter((x) => RP.includes(x)).pop() || null;
  const server = get('server'), poweredBy = get('x-powered-by');
  return {
    hsts: hstsMaxAge > 0 ? get('strict-transport-security') : null,
    hstsMaxAge,
    csp: enforced.length > 0,
    cspReportOnly: reportOnly.length > 0 && !enforced.length,
    cspRestrictsScripts: !!best,
    cspUnsafeInline: !!best && pols.every((p) => p.unsafeInline),
    cspUnsafeEval: !!best && best.unsafeEval,
    cspAnyHost: !!best && best.anyHost,
    cspStrictDynamic: !!best && best.strictDynamic,
    cspReportOnlyRestrictsScripts: !enforced.length && roPols.length > 0,
    cspReportOnlyIssues: !enforced.length && roPols[0] ? [['unsafeInline', "'unsafe-inline'"], ['unsafeEval', "'unsafe-eval'"], ['strictDynamic', "'strict-dynamic'"], ['anyHost', 'any-host source']].filter(([k]) => roPols[0][k]).map(([, v]) => v) : [],
    cspConnectSrc: enforced.some((d) => d['connect-src'] || d['default-src']),
    frameProtection: xfoOk || faOk,
    xcto: first('x-content-type-options').toLowerCase() === 'nosniff',
    referrerPolicy: rp,
    referrerFromMeta: !!meta.referrer && RP.includes(meta.referrer.toLowerCase().trim()),
    cspFromMeta: metaPols.length > 0,
    referrerLeaksFullUrl: rp === 'unsafe-url' || rp === 'no-referrer-when-downgrade',
    permissionsPolicy: !!get('permissions-policy'),
    coop: get('cross-origin-opener-policy'),
    server, poweredBy,
    serverVersionLeak: /\/\s*\d|\d+\.\d+/.test(server || '') || !!poweredBy,
  };
}

// Security-relevant <meta> tags, in any attribute order. Only tags in <head> count for CSP; we read the
// first 200 KB, which covers <head> on real pages.
const decodeEntities = (v) => v.replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16))).replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(+d))
  .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');

export function metaFromHtml(html) {
  const out = {};
  for (const [tag] of html.slice(0, 200000).matchAll(/<meta\b[^>]*>/gi)) {
    const attr = (n) => (tag.match(new RegExp(`\\b${n}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i')) || []).slice(1).find((x) => x !== undefined);
    const raw = attr('content');
    const equiv = (attr('http-equiv') || '').toLowerCase(), name = (attr('name') || '').toLowerCase(), content = raw == null ? raw : decodeEntities(raw);
    if (content == null) continue;
    if (equiv === 'content-security-policy') out.csp = out.csp ? `${out.csp}, ${content}` : content;
    if (name === 'referrer') out.referrer = content;
  }
  return out;
}

function analyzeHtml(html, pageUrl) {
  const host = new URL(pageUrl).hostname;
  const scripts = [...html.matchAll(/<script\b([^>]*)>/gi)].map((m) => m[1]);
  const ext = [];
  let inline = 0;
  for (const attrs of scripts) {
    const src = (attrs.match(/\bsrc\s*=\s*["']?([^"'\s>]+)/i) || [])[1];
    if (!src) { if (!/type\s*=\s*["']?(application\/(ld\+)?json|text\/template)/i.test(attrs)) inline++; continue; }
    let u; try { u = new URL(src, pageUrl); } catch { continue; }
    ext.push({ url: u.href, host: u.hostname, thirdParty: site(u.hostname) !== site(host), sri: /\bintegrity\s*=/i.test(attrs), http: u.protocol === 'http:' });
  }
  const third = ext.filter((s) => s.thirdParty);
  const unpinned = third.filter((s) => /(cdn\.jsdelivr\.net|unpkg\.com|cdnjs)/.test(s.host) && (/@(latest|master|main)\b/.test(s.url) || /(jsdelivr\.net\/npm|unpkg\.com)\/(@[^/]+\/)?[^@/]+\//.test(s.url)));
  // jQuery < 3.5.0 has known XSS CVEs (CVE-2020-11022/11023).
  const jq = [...html.matchAll(/jquery[.-]?(\d+)\.(\d+)\.(\d+)(\.min)?\.js|jquery@(\d+)\.(\d+)\.(\d+)/gi)].map((m) => m.slice(1).filter(Boolean).slice(0, 3).map(Number));
  const oldJquery = jq.some(([a, b]) => a < 3 || (a === 3 && b < 5));
  const mixed = /<(script|iframe|link|img)\b[^>]+(src|href)\s*=\s*["']http:\/\//i.test(html);
  const metaCsp = /<meta[^>]+http-equiv\s*=\s*["']?content-security-policy/i.test(html);
  return {
    scriptsExternal: ext.length, scriptsInline: inline, thirdPartyScripts: third.length,
    thirdPartyHosts: [...new Set(third.map((s) => s.host))],
    thirdPartyNoSri: third.filter((s) => !s.sri).length,
    unpinnedCdn: unpinned.map((s) => s.url), oldJquery, mixedContent: mixed || ext.some((s) => s.http), metaCsp,
    tagManager: /googletagmanager\.com\/gtm\.js|GTM-[A-Z0-9]{4,}/.test(html),
  };
}

export function analyzeCookies(list) {
  return list.map((c) => {
    const [pair, ...attrs] = c.split(';');
    const a = attrs.map((x) => x.trim().toLowerCase());
    const name = pair.split('=')[0].trim();
    const sameSite = (a.find((x) => x.startsWith('samesite=')) || '').split('=')[1] || null;
    return { name, secure: a.includes('secure'), httpOnly: a.includes('httponly'), sameSite,
      sameSiteNoneWithoutSecure: sameSite === 'none' && !a.includes('secure'),
      sessionLike: /sess|auth|token|sid|login|jwt/i.test(name) };
  });
}


// ---- Deeper outside-in checks (everything here is what a normal browser would fetch, or public DNS) ----

// Secret patterns that should never be in browser JS. We store only the type + a redacted prefix.
const SECRET_PATTERNS = {
  'AWS access key': /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
  'Stripe live secret key': /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/g,
  'GitHub token': /\bgh[pousr]_[A-Za-z0-9]{36}\b/g,
  'Slack token': /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
  'OpenAI key': /\bsk-(proj-)?[A-Za-z0-9_-]{40,}T3BlbkFJ[A-Za-z0-9_-]+|\bsk-proj-[A-Za-z0-9_-]{80,}\b/g,
  'Anthropic key': /\bsk-ant-(api|admin)\d{2}-[A-Za-z0-9_-]{80,}\b/g,
  'SendGrid key': /\bSG\.[\w-]{22}\.[\w-]{43}\b/g,
  'Private key': /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
  'Google OAuth client secret': /\bGOCSPX-[A-Za-z0-9_-]{28}\b/g,
  'GitLab token': /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
  'Shopify access token': /\bshp(at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g,
  'npm token': /\bnpm_[A-Za-z0-9]{36}\b/g,
  'Hugging Face token': /\bhf_[A-Za-z0-9]{34,}\b/g,
  'Supabase secret key': /\bsb_secret_[A-Za-z0-9_-]{20,}\b/g,
  'Groq API key': /\bgsk_[A-Za-z0-9]{52}\b/g,
  'Square access token': /\bsq0csp-[0-9A-Za-z_-]{43}\b/g,
};
const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

export function findSecrets(js) {
  const hits = [];
  for (const [type, re] of Object.entries(SECRET_PATTERNS)) for (const m of js.matchAll(re)) hits.push({ type, sample: m[0].slice(0, 8) + '…' });
  // Supabase service_role key in the browser = full database bypass of RLS.
  for (const m of js.matchAll(JWT)) {
    try { const p = JSON.parse(Buffer.from(m[0].split('.')[1], 'base64url').toString()); if (p.role === 'service_role') hits.push({ type: 'Supabase service_role key', sample: 'eyJ…' }); } catch {}
  }
  return hits;
}

// Library versions with known XSS/prototype-pollution CVEs. Minimal list; retire.js's repo is the upgrade path.
export function libVersions(text) {
  const found = [];
  const add = (name, v) => v && found.push({ name, version: v });
  for (const m of text.matchAll(/jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)|jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js|jquery@(\d+\.\d+\.\d+)/gi)) add('jquery', m[1] || m[2] || m[3]);
  for (const m of text.matchAll(/Bootstrap v(\d+\.\d+\.\d+)|bootstrap@(\d+\.\d+\.\d+)|bootstrap\/(\d+\.\d+\.\d+)\//gi)) add('bootstrap', m[1] || m[2] || m[3]);
  for (const m of text.matchAll(/AngularJS v(1\.\d+\.\d+)|angular(?:js)?[@/](1\.\d+\.\d+)/gi)) add('angularjs', m[1] || m[2]);
  for (const m of text.matchAll(/lodash@(\d+\.\d+\.\d+)|lodash\.js\/(\d+\.\d+\.\d+)|@license\s+Lodash[^\n]*?(\d+\.\d+\.\d+)/gi)) add('lodash', m[1] || m[2] || m[3]);
  return found;
}
const lt = (a, b) => { const x = a.split('.').map(Number), y = b.split('.').map(Number); for (let i = 0; i < 3; i++) if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) < (y[i] || 0); return false; };
export function isVulnerable({ name, version: v }) {
  if (name === 'jquery') return lt(v, '3.5.0');                       // CVE-2020-11022/11023
  if (name === 'bootstrap') return v.startsWith('3.') ? lt(v, '3.4.1') : v.startsWith('4.') && lt(v, '4.3.1'); // CVE-2019-8331
  if (name === 'angularjs') return true;                               // EOL since 2022, unpatched XSS
  if (name === 'lodash') return lt(v, '4.17.21');                      // CVE-2021-23337 / prototype pollution
  return false;
}

// Subdomains from Certificate Transparency logs (crt.sh, or Cert Spotter with your own key). Only used with --owned.
export async function ctSubdomains(apex) {
  const clean = (names) => [...new Set(names.flatMap((n) => String(n).split('\n')).map((n) => n.trim().toLowerCase().replace(/^\*\./, '')).filter((n) => n.endsWith('.' + apex) || n === apex))];
  try {
    const r = await fetch(`https://crt.sh/?q=%25.${apex}&output=json`, { signal: AbortSignal.timeout(30000) });
    if (r.ok) return clean((await r.json()).map((x) => x.name_value));
  } catch {}
  // Cert Spotter's unauthenticated API is for personal/evaluation use only, so it's used only when the
  // user supplies their own key (CERTSPOTTER_API_KEY), per SSLMate's terms.
  if (process.env.CERTSPOTTER_API_KEY) try {
    const r = await fetch(`https://api.certspotter.com/v1/issuances?domain=${apex}&include_subdomains=true&expand=dns_names`, { headers: { authorization: `Bearer ${process.env.CERTSPOTTER_API_KEY}` }, signal: AbortSignal.timeout(30000) });
    if (r.ok) return clean((await r.json()).flatMap((x) => x.dns_names || []));
  } catch {}
  return null;
}

// CNAME targets that are claimable by anyone once the customer resource is deleted.
const TAKEOVER_SUFFIXES = ['herokuapp.com', 'herokudns.com', 'github.io', 's3.amazonaws.com', 's3-website', 'azurewebsites.net', 'cloudapp.net', 'cloudapp.azure.com', 'trafficmanager.net', 'blob.core.windows.net', 'netlify.app', 'netlify.com', 'surge.sh', 'ghost.io', 'myshopify.com', 'zendesk.com', 'bitbucket.io', 'pantheonsite.io', 'fly.dev', 'readme.io', 'helpscoutdocs.com', 'wordpress.com', 'unbouncepages.com', 'webflow.io'];

async function dangling(host) {
  // Host does not resolve AND its registrable domain has no NS => likely unregistered = anyone can buy it.
  try { await dns.lookup(host); return null; } catch (e) { if (e.code !== 'ENOTFOUND') return null; }
  try { await dns.resolveNs(site(host)); return 'host-unresolvable'; } catch (e) { return e.code === 'ENOTFOUND' || e.code === 'ENODATA' ? 'domain-unregistered' : 'host-unresolvable'; }
}

async function takeover(name) {
  let cname;
  try { cname = (await dns.resolveCname(name))[0]; } catch { return null; }
  if (!TAKEOVER_SUFFIXES.some((s) => cname.endsWith(s) || cname.includes(s))) return null;
  try { await dns.lookup(cname); return null; } catch (e) { return e.code === 'ENOTFOUND' ? { name, cname } : null; }
}

const STACK_SIGNS = [
  [/Traceback \(most recent call last\)|You're seeing this error because you have <code>DEBUG = True/i, 'Django/Python debug'],
  [/Whoops! There was an error|Ignition|laravel\/framework\/src/i, 'Laravel debug'],
  [/Symfony\\Component|sf-toolbar|X-Debug-Token/i, 'Symfony debug'],
  [/Server Error in '\/' Application|ASP\.NET is configured to show verbose error/i, 'ASP.NET verbose errors'],
  [/<b>(Fatal error|Warning|Parse error)<\/b>:.*? in <b>\//i, 'PHP error display'],
  [/Whitelabel Error Page/i, 'Spring Boot default error'],
  [/\n\s+at [\w.<>]+ \((\/|[A-Z]:\\)[^)]+:\d+:\d+\)/, 'Node.js stack trace'],
  [/__nextjs_original-stack-frame|webpack-hmr|\/@vite\/client/i, 'Dev server in production'],
];

// ---- Vulnerable libraries via the retire.js database (thousands of versions across ~77 libraries). ----
// Downloaded once a day into the OS temp dir. If offline, the built-in 4-library list above is used.
const RETIRE_URL = 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-v4.json';
const RETIRE_CACHE = path.join(os.tmpdir(), 'shipsafe-retire-v4.json');
let retireDb;
export async function loadRetire() {
  if (retireDb !== undefined) return retireDb;
  try {
    const st = fs.statSync(RETIRE_CACHE);
    if (Date.now() - st.mtimeMs < 864e5) return (retireDb = compileRetire(JSON.parse(fs.readFileSync(RETIRE_CACHE, 'utf8'))));
  } catch {}
  try {
    const r = await fetch(RETIRE_URL, { signal: AbortSignal.timeout(TIMEOUT) });
    const txt = await r.text(); const db = JSON.parse(txt);
    try { fs.writeFileSync(RETIRE_CACHE, txt); } catch {}
    return (retireDb = compileRetire(db));
  } catch {
    try { return (retireDb = compileRetire(JSON.parse(fs.readFileSync(RETIRE_CACHE, 'utf8')))); } catch { return (retireDb = null); }
  }
}
const VERSION_RE = '[0-9][0-9.a-z_\\-]+'; // retire.js's own §§version§§ pattern
export function compileRetire(db) {
  const libs = [];
  for (const [name, lib] of Object.entries(db)) {
    if (name === 'retire-example' || !lib.extractors) continue;
    const mk = (list) => (list || []).map((x) => { try { return new RegExp(x.replace(/§§version§§/g, VERSION_RE)); } catch { return null; } }).filter(Boolean);
    libs.push({ name, uri: mk(lib.extractors.uri), filename: mk(lib.extractors.filename), filecontent: mk(lib.extractors.filecontent), vulns: lib.vulnerabilities || [] });
  }
  return libs;
}
const cmpVer = (a, b) => {
  const pa = a.split(/[.\-+]/), pb = b.split(/[.\-+]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? '0', y = pb[i] ?? '0';
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    if (nx && ny) { if (+x !== +y) return +x < +y ? -1 : 1; }
    else if (x !== y) return nx ? 1 : ny ? -1 : x < y ? -1 : 1; // a release sorts after a pre-release tag
  }
  return 0;
};
// Find libraries + versions in a script URL and/or its content; return those with known vulnerabilities.
export function retireScan(db, { url = '', content = '' }) {
  const found = [];
  const file = url.split('?')[0].split('/').pop() || '';
  for (const lib of db) {
    const tryAll = (res, text) => { for (const re of res) { const m = text.match(re); if (m?.[1]) return m[1]; } return null; };
    const raw = (url && (tryAll(lib.uri, url) || tryAll(lib.filename, file))) || (content && tryAll(lib.filecontent, content));
    if (!raw) continue;
    // The greedy version pattern can swallow file suffixes ("1.12.4.min"); strip them.
    const version = raw.replace(/([.\-](min|slim|js|prod|production|umd|bundle))+$/i, '');
    const hits = lib.vulns.filter((v) => (!v.below || cmpVer(version, v.below) < 0) && (!v.atOrAbove || cmpVer(version, v.atOrAbove) >= 0));
    if (hits.length) found.push({ name: lib.name, version, severity: hits.some((h) => h.severity === 'high' || h.severity === 'critical') ? 'high' : 'medium',
      ids: [...new Set(hits.flatMap((h) => [...(h.identifiers?.CVE || []), ...(h.identifiers?.githubID ? [h.identifiers.githubID] : [])]))].slice(0, 5) });
  }
  return found;
}

export async function deepChecks(out, html, finalUrl) {
  const retire = await loadRetire();
  const origin = new URL(finalUrl).origin, host = new URL(finalUrl).hostname;
  // 1. Error page: one ordinary request to a page that doesn't exist.
  try {
    const r = await get(`${origin}/this-page-does-not-exist-${Date.now()}`);
    const b = (await r.text()).slice(0, 200000);
    out.errorPage = { status: r.status, leaks: STACK_SIGNS.filter(([re]) => re.test(b)).map(([, n]) => n), debugHeader: !!r.headers.get('x-debug-token') };
  } catch { out.errorPage = null; }
  // Also check the homepage itself for dev-server markers.
  out.devServerOnHome = /\/@vite\/client|webpack-hmr|__nextjs_original-stack-frame/i.test(html);
  // 2. First-party JS bundles: secrets, source maps, library versions.
  const srcs = [...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']?([^"'\s>]+)/gi)].map((m) => { try { return new URL(m[1], finalUrl); } catch { return null; } }).filter(Boolean);
  const firstParty = srcs.filter((u) => site(u.hostname) === site(host)).slice(0, 8);
  const secrets = [], maps = [], libs = libVersions(html), retireHits = [];
  // Third-party script URLs usually carry the version (cdnjs, jsdelivr, unpkg); match them by URL only.
  if (retire) for (const u of srcs.filter((u) => site(u.hostname) !== site(host))) retireHits.push(...retireScan(retire, { url: u.href }));
  await Promise.all(firstParty.map(async (u) => {
    try {
      const r = await get(u.href);
      if (r.status !== 200) return;
      const js = Buffer.from(await r.arrayBuffer()).subarray(0, 4_000_000).toString('utf8');
      secrets.push(...findSecrets(js));
      libs.push(...libVersions(js.slice(0, 3000)), ...libVersions(u.href));
      if (retire) retireHits.push(...retireScan(retire, { url: u.href, content: js }));
      const sm = r.headers.get('sourcemap') || (js.slice(-500).match(/\/\/# sourceMappingURL=(\S+)/) || [])[1];
      if (sm && !sm.startsWith('data:')) {
        const mu = new URL(sm, u.href);
        const mr = await fetch(mu, { method: 'HEAD', headers: { 'user-agent': UA }, signal: AbortSignal.timeout(TIMEOUT) }).catch(() => null);
        maps.push({ map: mu.href, public: !!mr && mr.status === 200 && !/text\/html/i.test(mr.headers.get('content-type') || '') });
      }
    } catch {}
  }));
  // retire.js when available; built-in list only as an offline fallback.
  const vulnLibs = retire ? retireHits : libs.filter(isVulnerable);
  out.bundles = { checked: firstParty.length, secrets, sourceMaps: maps, publicSourceMap: maps.some((m) => m.public), libs: [...new Map(libs.map((l) => [l.name + l.version, l])).values()], vulnerableLibs: [...new Map(vulnLibs.map((l) => [l.name + l.version, l])).values()] };
  // 3. Third-party script hosts that no longer resolve (anyone could register them and serve code).
  const third = [...new Set(srcs.filter((u) => site(u.hostname) !== site(host)).map((u) => u.hostname))];
  out.danglingScripts = (await Promise.all(third.map(async (h) => ({ host: h, state: await dangling(h) })))).filter((d) => d.state);
  // 4. Subdomain takeover on apex + www (full enumeration needs crt.sh; only for --owned later).
  const apex = site(out.domain);
  let names = [apex, 'www.' + apex];
  if (out.owned) {
    const ct = await ctSubdomains(apex);
    out.subdomainsChecked = ct ? Math.min(ct.length, 300) : null; // cap keeps DNS load sane; raise for big estates
    if (ct) names = [...new Set([...names, ...ct.slice(0, 300)])];
  }
  const results = [];
  for (let i = 0; i < names.length; i += 20) results.push(...(await Promise.all(names.slice(i, i + 20).map(takeover))));
  out.takeover = results.filter(Boolean);
}

const OWNED_PROBES = [
  ['/.git/HEAD', (b) => b.startsWith('ref:')],
  ['/.git/config', (b) => b.includes('[core]')],
  ['/.env', (b) => /^[A-Z_][A-Z0-9_]*=/m.test(b)],
  ['/.env.local', (b) => /^[A-Z_][A-Z0-9_]*=/m.test(b)],
  ['/.env.production', (b) => /^[A-Z_][A-Z0-9_]*=/m.test(b)],
  ['/.DS_Store', (b) => b.includes('Bud1')],
  ['/backup.zip', (b) => b.startsWith('PK')],
  ['/backup.sql', (b) => /CREATE TABLE|INSERT INTO/i.test(b)],
  ['/dump.sql', (b) => /CREATE TABLE|INSERT INTO/i.test(b)],
  ['/phpinfo.php', (b) => b.includes('phpinfo()')],
];

// 'example.com', 'https://example.com/login?x=1' -> host + path (path defaults to '/').
export function splitTarget(input) {
  const rest = input.trim().replace(/^https?:\/\//i, '');
  const i = rest.search(/[/?#]/);
  return i < 0 ? { domain: rest, pagePath: '/' } : { domain: rest.slice(0, i), pagePath: (rest[i] === '/' ? '' : '/') + rest.slice(i) };
}

export async function scan(input, { owned = false } = {}) {
  const { domain, pagePath } = splitTarget(input); // scan the page given, not always the homepage
  const out = { domain, owned, scannedAt: new Date().toISOString() };
  // 1. Does plain http:// end up on https://?
  try { const h = await follow('http://' + domain); out.httpRedirectsToHttps = h.url.startsWith('https://'); } catch (e) { out.httpRedirectsToHttps = null; out.httpError = e.cause?.code || e.name; }
  // 2. Main HTTPS fetch; Origin header lets us see if CORS reflects arbitrary origins.
  let res, finalUrl, html = '';
  try {
    const f = await follow('https://' + domain + pagePath, { origin: 'https://scanner-test.invalid' });
    res = f.res; finalUrl = f.url; out.finalUrl = finalUrl; out.status = res.status;
    const buf = Buffer.from(await res.arrayBuffer());
    html = buf.subarray(0, MAX_BODY).toString('utf8');
  } catch (e) { out.error = e.cause?.code || e.name || String(e); return out; }
  const H = (n) => res.headers.get(n);
  out.isHtml = /text\/html/i.test(H('content-type') || '');
  out.headers = analyzeHeaders(Object.fromEntries(res.headers), /text\/html/i.test(res.headers.get('content-type') || '') ? metaFromHtml(html) : {});
  const acao = H('access-control-allow-origin');
  out.cors = { acao, credentials: H('access-control-allow-credentials') === 'true', reflectsOrigin: acao === 'https://scanner-test.invalid' };
  out.cookies = analyzeCookies(res.headers.getSetCookie?.() || []);
  if (out.isHtml) out.html = analyzeHtml(html, finalUrl);
  const host = new URL(finalUrl).hostname;
  const [t, dn, sec] = await Promise.all([
    tlsInfo(host),
    dnsChecks(site(domain)),
    get(`https://${host}/.well-known/security.txt`).then(async (r) => r.status === 200 && /contact:/i.test(await r.text())).catch(() => false),
  ]);
  out.tls = t; out.dns = dn; out.securityTxt = sec;
  if (out.httpRedirectsToHttps === false) {
    // Browsers never use http:// for preloaded domains, so a missing redirect is harmless there.
    try { const p = await (await fetch(`https://hstspreload.org/api/v2/status?domain=${site(domain)}`, { signal: AbortSignal.timeout(TIMEOUT) })).json(); out.hstsPreloaded = p.status === 'preloaded'; } catch {}
  }
  if (out.isHtml) await deepChecks(out, html, finalUrl);
  if (owned) {
    // Only for sites the user owns: request files that must never be public. Content is checked,
    // because single-page apps answer 200 with index.html for any path.
    out.exposed = {};
    for (const [path, looksReal] of OWNED_PROBES) {
      try { const r = await get(`https://${host}${path}`); const b = r.status === 200 ? Buffer.from(await r.arrayBuffer()).subarray(0, 2000).toString('latin1') : ''; out.exposed[path] = r.status === 200 && looksReal(b); } catch { out.exposed[path] = null; }
    }
  }
  return out;
}

async function batch(csvPath, outPath, opts) {
  const rows = fs.readFileSync(csvPath, 'utf8').trim().split('\n').slice(1).map((l) => l.split(','));
  const outStream = fs.createWriteStream(outPath);
  let i = 0, done = 0;
  async function worker() {
    while (i < rows.length) {
      const [tier, domain] = rows[i++];
      let r;
      try { r = await Promise.race([scan(domain, opts), new Promise((_, rej) => setTimeout(() => rej(new Error('overall-timeout')), 60000))]); }
      catch (e) { r = { domain, error: e.message }; }
      outStream.write(JSON.stringify({ tier, ...r }) + '\n');
      if (++done % 25 === 0) process.stderr.write(`${done}/${rows.length}\n`);
    }
  }
  await Promise.all(Array.from({ length: 25 }, worker));
  outStream.end();
}

// ---- Findings: turn raw results into a ranked list. Severity reflects real-incident evidence (see research/FINDINGS.md). ----
const SEV = { critical: 0, high: 1, medium: 2, low: 3 };
export function findings(r) {
  const f = [];
  const add = (id, severity, title, evidence) => f.push({ id, severity, title, ...(evidence ? { evidence } : {}) });
  if (r.error) return [{ id: 'scan-failed', severity: 'critical', title: `Could not load the site (${r.error})` }];
  const h = r.headers || {};
  // critical
  for (const [p, hit] of Object.entries(r.exposed || {})) if (hit) add('exposed-file', 'critical', `${p} is publicly downloadable`, p);
  if (r.bundles?.secrets.length) add('secret-in-js', 'critical', 'Secret key shipped in public JavaScript', [...new Set(r.bundles.secrets.map((x) => x.type))].join(', '));
  if (r.cors?.reflectsOrigin && r.cors.credentials) add('cors-any-origin-credentials', 'critical', 'CORS trusts any website and allows credentials');
  for (const t of r.takeover || []) add('subdomain-takeover', 'critical', `${t.name} points to a deleted service (${t.cname})`);
  for (const d of r.danglingScripts || []) add('dangling-script', d.state === 'domain-unregistered' ? 'critical' : 'medium', `Script loaded from ${d.host}, which no longer resolves`, d.state);
  if (r.errorPage?.leaks.length || r.errorPage?.debugHeader || r.devServerOnHome) add('debug-exposed', 'critical', 'Error page or dev server leaks internal details', (r.errorPage?.leaks || []).join(', ') || 'dev server');
  // high
  if (r.httpRedirectsToHttps === false && !r.hstsPreloaded) add('no-https-redirect', 'high', 'http:// does not redirect to https://');
  if (h.cspReportOnlyRestrictsScripts) add('csp-report-only', 'high', 'CSP is report-only: it logs violations but blocks nothing', h.cspReportOnlyIssues.length ? `report-only policy also contains ${h.cspReportOnlyIssues.join(' ')}` : undefined);
  else if (!h.cspRestrictsScripts || h.cspAnyHost || h.cspStrictDynamic) add('csp-no-script-protection', 'high', !h.csp && !h.cspReportOnly ? 'No Content-Security-Policy' : 'CSP does not stop an injected script from loading', h.cspAnyHost ? 'script-src allows any host' : h.cspStrictDynamic ? "'strict-dynamic' trusts scripts added by trusted scripts" : h.csp && !h.cspRestrictsScripts ? 'CSP has no script-src/default-src' : undefined);
  if (h.cspUnsafeEval) add('csp-unsafe-eval', 'high', "CSP allows 'unsafe-eval' (the inline fallback in the Optimizely attack ran through eval)");
  if (r.bundles?.vulnerableLibs.length) add('vulnerable-js-library', 'high', 'JavaScript library with known vulnerabilities', r.bundles.vulnerableLibs.map((l) => `${l.name}@${l.version}${l.ids?.length ? ` (${l.ids.slice(0, 2).join(', ')})` : ''}`).join('; '));
  if (r.bundles?.publicSourceMap) add('public-source-map', 'high', 'Source maps are public (your original source code is downloadable)', r.bundles.sourceMaps.filter((m) => m.public).map((m) => m.map)[0]);
  const weakSession = (r.cookies || []).filter((c) => c.sessionLike && (!c.httpOnly || !c.secure));
  if (weakSession.length) add('session-cookie-flags', 'high', 'Session-like cookie readable by JavaScript or sent over http', weakSession.map((c) => c.name).join(', '));
  if (r.html?.mixedContent) add('mixed-content', 'high', 'Page loads http:// resources on an https:// page');
  if (r.tls?.certDaysLeft != null && r.tls.certDaysLeft < 14) add('cert-expiring', 'high', `TLS certificate expires in ${r.tls.certDaysLeft} days`);
  // medium
  if (!h.hsts) add('no-hsts', 'medium', 'No Strict-Transport-Security (HSTS)');
  else if (h.hstsMaxAge < 15552000) add('weak-hsts', 'medium', 'HSTS max-age is under 180 days', String(h.hstsMaxAge));
  if (!h.frameProtection) add('no-clickjacking-protection', 'medium', 'Site can be framed by other sites (clickjacking)');
  if (h.cspUnsafeInline) add('csp-unsafe-inline', 'medium', "CSP allows 'unsafe-inline' scripts");
  if (r.html?.unpinnedCdn.length) add('unpinned-cdn', 'medium', 'Third-party script loaded without a fixed version', r.html.unpinnedCdn[0]);
  if (r.cors?.reflectsOrigin && !r.cors.credentials) add('cors-any-origin', 'medium', 'CORS reflects any origin');
  const otherCookies = (r.cookies || []).filter((c) => !c.sessionLike && (!c.secure || !c.sameSite || c.sameSiteNoneWithoutSecure));
  if (otherCookies.length) add('cookie-flags', 'medium', 'Cookies missing Secure or SameSite', otherCookies.map((c) => c.name).slice(0, 5).join(', '));
  if (!r.dns?.dmarc) add('no-dmarc', 'medium', 'No DMARC record: anyone can send email as your domain');
  else if (r.dns.dmarcPolicy === 'none') add('dmarc-not-enforced', 'medium', 'DMARC is p=none (monitor only, spoofed mail still delivered)');
  if (!r.dns?.spf) add('no-spf', 'medium', 'No SPF record');
  if (h.serverVersionLeak) add('version-leak', 'medium', 'Server or framework version is visible', [h.server, h.poweredBy].filter(Boolean).join(' / '));
  // low
  if (!h.xcto) add('no-xcto', 'low', 'No X-Content-Type-Options: nosniff');
  if (!h.referrerPolicy) add('no-referrer-policy', 'low', 'No Referrer-Policy');
  if (!h.permissionsPolicy) add('no-permissions-policy', 'low', 'No Permissions-Policy');
  if (h.referrerLeaksFullUrl) add('weak-referrer-policy', 'low', `Referrer-Policy '${h.referrerPolicy}' sends full URLs to other sites`);
  if (!r.dns?.caa) add('no-caa', 'low', 'No CAA record (any CA may issue certificates for you)');
  if (!r.securityTxt) add('no-security-txt', 'low', 'No /.well-known/security.txt');
  if (r.html?.thirdPartyHosts.length) add('third-party-scripts', 'low', `${r.html.thirdPartyHosts.length} third-party script host(s) can run code on this page`, r.html.thirdPartyHosts.join(', '));
  return f.sort((a, b) => SEV[a.severity] - SEV[b.severity]);
}

// Checks evaluated on every scan; anything here without a finding counts as passed.
const BASIC_IDS = ['no-https-redirect', 'csp-no-script-protection', 'csp-unsafe-eval', 'vulnerable-js-library', 'public-source-map', 'session-cookie-flags', 'mixed-content', 'cert-expiring', 'no-hsts', 'no-clickjacking-protection', 'csp-unsafe-inline', 'unpinned-cdn', 'cors-any-origin', 'cookie-flags', 'no-dmarc', 'no-spf', 'version-leak', 'no-xcto', 'no-referrer-policy', 'no-permissions-policy', 'no-caa', 'no-security-txt', 'secret-in-js', 'debug-exposed', 'dangling-script', 'subdomain-takeover'];
const SAME = { 'csp-no-script-protection': ['csp-report-only'], 'no-hsts': ['weak-hsts'], 'no-dmarc': ['dmarc-not-enforced'], 'cors-any-origin': ['cors-any-origin-credentials'] };
// Human-readable names for checks that came back clean (finding ids read like failures).
const PASS_LABEL = { 'no-https-redirect': 'https-redirect', 'csp-no-script-protection': 'csp-blocks-injected-scripts', 'csp-unsafe-eval': 'csp-no-unsafe-eval', 'vulnerable-js-library': 'js-libraries-up-to-date', 'public-source-map': 'source-maps-private', 'session-cookie-flags': 'session-cookie-flags-ok', 'mixed-content': 'no-mixed-content', 'cert-expiring': 'certificate-valid', 'no-hsts': 'hsts', 'no-clickjacking-protection': 'clickjacking-protection', 'csp-unsafe-inline': 'csp-no-unsafe-inline', 'unpinned-cdn': 'cdn-scripts-pinned', 'cors-any-origin': 'cors-restricted', 'cookie-flags': 'cookie-flags-ok', 'no-dmarc': 'dmarc', 'no-spf': 'spf', 'version-leak': 'no-version-leak', 'no-xcto': 'x-content-type-options', 'no-referrer-policy': 'referrer-policy', 'no-permissions-policy': 'permissions-policy', 'no-caa': 'caa', 'no-security-txt': 'security-txt', 'secret-in-js': 'no-secrets-in-js', 'debug-exposed': 'no-debug-pages', 'dangling-script': 'no-dead-script-domains', 'subdomain-takeover': 'no-subdomain-takeover' };
export const passed = (list, owned = true) => { const ids = new Set(list.map((x) => x.id)); return BASIC_IDS.filter((id) => !ids.has(id) && !(SAME[id] || []).some((o) => ids.has(o)) && (owned || id !== 'subdomain-takeover')).map((id) => PASS_LABEL[id] || id); };

const HELP = `shipsafe scanner (passive, zero dependencies)

  node scan.mjs <url-or-domain> [--owned] [--raw]
      Prints JSON: { target, owned, skipped, counts, findings[], passed[], raw? }.
      findings are sorted critical -> low; passed lists check ids with no problem.
      --owned  also request files that must never be public (.env, .git, backups).
               Only use on sites the user owns or is authorised to test.
      --raw    include the raw measurements under "raw".
  node scan.mjs --batch <tier,domain.csv> <out.jsonl> [--owned]
      Research mode: scan many sites, 25 in parallel, one raw JSON per line.

Exit codes: 0 scan completed (findings may exist), 2 site could not be scanned, 64 bad usage.`;

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const owned = args.includes('--owned');
  const pos = args.filter((a) => !a.startsWith('--'));
  if (args.includes('--help') || !pos.length) { console.log(HELP); process.exit(pos.length || args.includes('--help') ? 0 : 64); }
  if (args.includes('--batch')) await batch(pos[0], pos[1], { owned });
  else {
    const raw = await scan(pos[0], { owned });
    const list = findings(raw);
    const counts = Object.fromEntries(Object.keys(SEV).map((k) => [k, list.filter((x) => x.severity === k).length]));
    const skipped = owned ? (raw.subdomainsChecked == null && !raw.error ? ['subdomain-takeover beyond apex/www: certificate-transparency lookup failed'] : []) : ['exposed-file (.env, .git, backups): needs --owned', 'subdomain-takeover beyond apex/www: needs --owned'];
    console.log(JSON.stringify({ target: raw.finalUrl || raw.domain, owned, skipped, counts, findings: list, passed: raw.error ? [] : passed(list, owned), ...(args.includes('--raw') ? { raw } : {}) }, null, 2));
    process.exit(raw.error ? 2 : 0);
  }
}
