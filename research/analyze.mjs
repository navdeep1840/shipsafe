// Aggregate scanner results into "% of sites missing X", per popularity tier.
import fs from 'node:fs';
const rows = fs.readFileSync(process.argv[2], 'utf8').trim().split('\n').map(JSON.parse);
const ok = rows.filter((r) => r.isHtml && r.status < 400 && r.headers);
const checks = {
  'No HTTP->HTTPS redirect': (r) => r.httpRedirectsToHttps === false,
  'No HSTS': (r) => !r.headers.hsts,
  'No CSP at all (enforcing)': (r) => !r.headers.csp,
  'CSP but does not restrict scripts': (r) => r.headers.csp && !r.headers.cspRestrictsScripts,
  'CSP report-only only': (r) => r.headers.cspReportOnly,
  "script CSP allows 'unsafe-inline'": (r) => r.headers.cspUnsafeInline,
  "script CSP allows 'unsafe-eval'": (r) => r.headers.cspUnsafeEval,
  'Real script protection (CSP restricts scripts, no unsafe-inline)': (r) => r.headers.cspRestrictsScripts && !r.headers.cspUnsafeInline,
  "script CSP allows any host (*, https:)": (r) => r.headers.cspAnyHost,
  // Optimizely-style loader: blocked by a host allowlist; its inline fallback is blocked only without 'unsafe-eval'.
  'Blocks injected external script (host allowlist, no strict-dynamic/any-host)': (r) => r.headers.cspRestrictsScripts && !r.headers.cspAnyHost && !r.headers.cspStrictDynamic,
  '...and also blocks the eval fallback (no unsafe-eval)': (r) => r.headers.cspRestrictsScripts && !r.headers.cspAnyHost && !r.headers.cspStrictDynamic && !r.headers.cspUnsafeEval,
  'No clickjacking protection': (r) => !r.headers.frameProtection,
  'No X-Content-Type-Options': (r) => !r.headers.xcto,
  'No Referrer-Policy': (r) => !r.headers.referrerPolicy,
  'No Permissions-Policy': (r) => !r.headers.permissionsPolicy,
  'Server/framework version leaked': (r) => r.headers.serverVersionLeak,
  'CORS reflects any origin': (r) => r.cors.reflectsOrigin,
  'CORS reflects any origin + credentials': (r) => r.cors.reflectsOrigin && r.cors.credentials,
  'Cookie missing Secure (any)': (r) => r.cookies.some((c) => !c.secure),
  'Cookie missing HttpOnly (session-like)': (r) => r.cookies.some((c) => c.sessionLike && !c.httpOnly),
  'Cookie missing SameSite (any)': (r) => r.cookies.some((c) => !c.sameSite),
  'Loads 3rd-party scripts': (r) => r.html?.thirdPartyScripts > 0,
  '3rd-party script without SRI': (r) => r.html?.thirdPartyNoSri > 0,
  '5+ third-party script hosts': (r) => (r.html?.thirdPartyHosts.length || 0) >= 5,
  'Unpinned CDN script (@latest/no version)': (r) => r.html?.unpinnedCdn.length > 0,
  'jQuery < 3.5 (known XSS)': (r) => r.html?.oldJquery,
  'Mixed content (http:// on https page)': (r) => r.html?.mixedContent,
  'Error page leaks stack trace / debug info': (r) => r.errorPage?.leaks.length > 0 || r.errorPage?.debugHeader,
  'Dev server running in production': (r) => r.devServerOnHome || r.errorPage?.leaks.includes('Dev server in production'),
  'Secret key in public JS bundle': (r) => r.bundles?.secrets.length > 0,
  'Public source map (.map) for first-party JS': (r) => r.bundles?.publicSourceMap,
  'Vulnerable JS library (jQuery/Bootstrap/AngularJS/lodash)': (r) => r.bundles?.vulnerableLibs.length > 0,
  'Script from domain that no longer resolves': (r) => r.danglingScripts?.length > 0,
  'Apex/www CNAME takeover candidate': (r) => r.takeover?.length > 0,
  'Cert expires in < 14 days': (r) => r.tls?.certDaysLeft != null && r.tls.certDaysLeft < 14,
  'No SPF': (r) => !r.dns.spf,
  'No DMARC': (r) => !r.dns.dmarc,
  'DMARC p=none (not enforced)': (r) => r.dns.dmarcPolicy === 'none',
  'No CAA record': (r) => !r.dns.caa,
  'No security.txt': (r) => !r.securityTxt,
};
const tiers = [...new Set(ok.map((r) => r.tier))];
const pct = (set, f) => (set.length ? Math.round((100 * set.filter(f).length) / set.length) : 0);
const by = Object.fromEntries(tiers.map((t) => [t, ok.filter((r) => r.tier === t)]));
console.log(`scanned ${rows.length}, usable HTML sites ${ok.length} (${tiers.map((t) => t + ' ' + by[t].length).join(', ')})\n`);
console.log('check'.padEnd(74) + 'all'.padStart(5) + tiers.map((t) => t.slice(0, 5).padStart(7)).join(''));
for (const [name, f] of Object.entries(checks)) console.log(name.padEnd(74) + `${pct(ok, f)}%`.padStart(5) + tiers.map((t) => `${pct(by[t], f)}%`.padStart(7)).join(''));
const fails = ok.map((r) => Object.entries(checks).filter(([n]) => !/Loads|Real script/.test(n)).filter(([, f]) => f(r)).length);
fails.sort((a, b) => a - b);
console.log(`\nmedian issues per site: ${fails[fails.length >> 1]}; sites with 0 issues: ${fails.filter((x) => x === 0).length}`);
const hosts = {};
ok.forEach((r) => r.html?.thirdPartyHosts.forEach((h) => (hosts[h] = (hosts[h] || 0) + 1)));
console.log('\ntop 3rd-party script hosts:', Object.entries(hosts).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([h, n]) => `${h}(${n})`).join(', '));
const errs = {}; rows.filter((r) => !ok.includes(r)).forEach((r) => { const k = r.error || (r.status >= 400 ? 'http ' + r.status : r.isHtml === false ? 'not html' : 'other'); errs[k] = (errs[k] || 0) + 1; });
const det = (k, f) => console.log(k + ':', JSON.stringify(ok.filter(f).map((r) => r.domain + ' ' + JSON.stringify(k === 'secrets' ? r.bundles.secrets.map((x) => x.type) : k === 'debug' ? r.errorPage.leaks : k === 'libs' ? r.bundles.vulnerableLibs.map((l) => l.name + '@' + l.version) : k === 'dangling' ? r.danglingScripts : r.takeover))));
console.log('');
det('secrets', (r) => r.bundles?.secrets.length); det('debug', (r) => r.errorPage?.leaks.length); det('dangling', (r) => r.danglingScripts?.length); det('takeover', (r) => r.takeover?.length);
const lc = {}; ok.forEach((r) => r.bundles?.vulnerableLibs.forEach((l) => (lc[l.name] = (lc[l.name] || 0) + 1))); console.log('vuln libs by name:', JSON.stringify(lc));
console.log('excluded:', JSON.stringify(errs));
