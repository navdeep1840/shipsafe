// Compare our scanner against Mozilla Observatory and nuclei, check by check, on the same hosts.
import fs from 'node:fs';
const read = (f) => fs.readFileSync(new URL(f, import.meta.url), 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
const ours = Object.fromEntries(read('ours.jsonl').filter((r) => r.headers).map((r) => [r.domain, r]));
const obs = Object.fromEntries(read('observatory.jsonl').filter((r) => r.tests && Object.keys(r.tests).length).map((r) => [r.host, r.tests]));
const nuc = {};
for (const r of read('nuclei.jsonl')) { const h = new URL(r['matched-at'] || r.host).hostname; (nuc[h] ||= new Set()).add(r['matcher-name']); }
const nucHosts = new Set(read('nuclei.jsonl').map((r) => new URL(r['matched-at'] || r.host).hostname));

const vsObs = {
  'HSTS (>= 6 months)': [(o) => o['strict-transport-security'].pass, (r) => !!r.headers.hsts && r.headers.hstsMaxAge >= 15552000],
  'CSP enforced': [(o) => !/not-implemented/.test(o['content-security-policy'].result), (r) => r.headers.csp],
  'Clickjacking protection': [(o) => o['x-frame-options'].pass, (r) => r.headers.frameProtection],
  'X-Content-Type-Options': [(o) => o['x-content-type-options'].pass, (r) => r.headers.xcto],
  'Referrer-Policy set': [(o) => !/not-implemented/.test(o['referrer-policy'].result), (r) => !!r.headers.referrerPolicy],
  'Referrer-Policy safe': [(o) => o['referrer-policy'].result !== 'referrer-policy-unsafe', (r) => !r.headers.referrerLeaksFullUrl],
  'HTTP->HTTPS redirect': [(o) => o.redirection.pass, (r) => r.httpRedirectsToHttps === true],
  'CORS safe': [(o) => o['cross-origin-resource-sharing'].pass, (r) => !r.cors.reflectsOrigin],
};
const vsNuc = {
  'HSTS present': ['strict-transport-security', (r) => !!r.headers.hsts],
  'CSP present (enforced)': ['content-security-policy', (r) => r.headers.csp],
  'X-Frame-Options present': ['x-frame-options', (r) => (r.headers.frameProtection)],
  'X-Content-Type-Options': ['x-content-type-options', (r) => r.headers.xcto],
  'Referrer-Policy present': ['referrer-policy', (r) => !!r.headers.referrerPolicy],
  'Permissions-Policy present': ['permissions-policy', (r) => r.headers.permissionsPolicy],
};
const out = [], diffs = [];
for (const [name, [o, u]] of Object.entries(vsObs)) {
  let agree = 0, n = 0;
  for (const h of Object.keys(ours)) { if (!obs[h]) continue; n++; const a = o(obs[h]), b = u(ours[h]); if (a === b) agree++; else diffs.push(`observatory | ${name} | ${h} | them=${a} us=${b}`); }
  out.push(`| ${name} | Observatory | ${agree}/${n} |`);
}
for (const [name, [m, u]] of Object.entries(vsNuc)) {
  let agree = 0, n = 0;
  for (const h of Object.keys(ours)) { if (!nucHosts.has(h) && !nuc[h]) {} n++; const missingThem = !!nuc[h]?.has(m); const presentUs = u(ours[h]); if (missingThem !== presentUs) agree++; else diffs.push(`nuclei | ${name} | ${h} | them=${missingThem ? 'missing' : 'present'} us=${presentUs ? 'present' : 'missing'}`); }
  out.push(`| ${name} | nuclei | ${agree}/${n} |`);
}
console.log(`hosts: ours ${Object.keys(ours).length}, observatory ${Object.keys(obs).length}, nuclei hosts with any hit ${nucHosts.size}\n`);
console.log('| Check | Compared with | Agree |\n|---|---|---|\n' + out.join('\n'));
console.log('\nDisagreements:\n' + diffs.join('\n'));
