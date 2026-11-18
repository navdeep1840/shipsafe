// node --test scan.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { findSecrets, libVersions, isVulnerable, findings, passed, analyzeHeaders, analyzeCookies, metaFromHtml } from './scan.mjs';

test('finds secrets in bundles, ignores public keys', () => {
  const role = (r) => 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from(JSON.stringify({ role: r })).toString('base64url') + '.c2lnbmF0dXJlc2lnbmF0dXJl';
  const js = `a="AKIAABCDEFGHIJKLMNOP";b="sk_live_${'x'.repeat(24)}";c="${role('service_role')}";d="${role('anon')}";e="AIzaSyPublicMapsKey"`;
  assert.deepEqual(findSecrets(js).map((h) => h.type).sort(), ['AWS access key', 'Stripe live secret key', 'Supabase service_role key']);
});

test('flags vulnerable library versions only', () => {
  const libs = libVersions('/*! jQuery v1.12.4 */ <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/x.js"> lodash@4.17.21');
  assert.deepEqual(libs.filter(isVulnerable).map((l) => l.name + '@' + l.version), ['jquery@1.12.4']);
});

test('ranks critical findings first and recognises a real CSP', () => {
  const raw = { headers: { cspRestrictsScripts: true, hsts: 'max-age=31536000', hstsMaxAge: 31536000, frameProtection: true, xcto: true, referrerPolicy: 'no-referrer', permissionsPolicy: true },
    exposed: { '/.env': true }, cookies: [], dns: { dmarc: 'v=DMARC1; p=reject', dmarcPolicy: 'reject', spf: 'v=spf1 -all', caa: true }, securityTxt: true };
  assert.deepEqual(findings(raw).map((x) => x.id), ['exposed-file']);
  raw.headers.cspUnsafeEval = true;
  assert.ok(findings(raw).some((x) => x.id === 'csp-unsafe-eval'));
});

test('report-only CSP gets its own finding, not "no CSP"', () => {
  const raw = { headers: { cspReportOnly: true, cspReportOnlyRestrictsScripts: true, cspReportOnlyIssues: ["'unsafe-inline'"] }, cookies: [], dns: {} };
  const ids = findings(raw).map((x) => x.id);
  assert.ok(ids.includes('csp-report-only') && !ids.includes('csp-no-script-protection'));
  assert.ok(!passed(findings(raw)).includes('csp-blocks-injected-scripts'));
  assert.ok(passed(findings(raw)).includes('no-secrets-in-js'));
});

// Ground truth for every header rule. Each row: headers in, expected fields out.
const H = (o) => analyzeHeaders(o);
const cases = [
  // HSTS
  ['HSTS normal', { 'strict-transport-security': 'max-age=31536000; includeSubDomains' }, { hstsMaxAge: 31536000 }, (r) => !!r.hsts],
  ['HSTS max-age=0 disables it', { 'strict-transport-security': 'max-age=0' }, {}, (r) => r.hsts === null],
  ['HSTS quoted max-age', { 'strict-transport-security': 'max-age="63072000"' }, { hstsMaxAge: 63072000 }],
  ['HSTS duplicated header uses first', { 'strict-transport-security': 'max-age=100, max-age=200' }, { hstsMaxAge: 100 }],
  // CSP
  ['no CSP', {}, { csp: false, cspRestrictsScripts: false }],
  ['strict host allowlist', { 'content-security-policy': "default-src 'self'; script-src 'self' https://cdn.example.com" }, { cspRestrictsScripts: true, cspAnyHost: false, cspUnsafeEval: false, cspUnsafeInline: false }],
  ['default-src fallback', { 'content-security-policy': "default-src 'self'" }, { cspRestrictsScripts: true }],
  ['frame-ancestors only does not restrict scripts', { 'content-security-policy': "frame-ancestors 'none'" }, { csp: true, cspRestrictsScripts: false, frameProtection: true }],
  ['unsafe-eval detected', { 'content-security-policy': "script-src 'self' 'unsafe-eval'" }, { cspUnsafeEval: true }],
  ['keywords are case-insensitive', { 'content-security-policy': "SCRIPT-SRC 'self' 'UNSAFE-EVAL'" }, { cspRestrictsScripts: true, cspUnsafeEval: true }],
  ['wasm-unsafe-eval is not eval', { 'content-security-policy': "script-src 'self' 'wasm-unsafe-eval'" }, { cspUnsafeEval: false }],
  ['unsafe-inline ignored when nonce present', { 'content-security-policy': "script-src 'nonce-abc' 'unsafe-inline'" }, { cspUnsafeInline: false }],
  ['https: allows any host', { 'content-security-policy': "script-src 'self' https:" }, { cspAnyHost: true }],
  ['https://* allows any host', { 'content-security-policy': "script-src https://*" }, { cspAnyHost: true }],
  ['data: in script-src is weak', { 'content-security-policy': "script-src 'self' data:" }, { cspAnyHost: true }],
  ['strict-dynamic flagged', { 'content-security-policy': "script-src 'nonce-x' 'strict-dynamic' https:" }, { cspStrictDynamic: true, cspAnyHost: false }],
  ['first duplicate directive wins', { 'content-security-policy': "script-src 'self'; script-src *" }, { cspAnyHost: false }],
  ['two policies: strictest wins', { 'content-security-policy': "script-src *, script-src 'self'" }, { cspRestrictsScripts: true, cspAnyHost: false }],
  ['script-src-elem governs elements', { 'content-security-policy': "script-src *; script-src-elem 'self'" }, { cspAnyHost: false }],
  ['report-only only', { 'content-security-policy-report-only': "script-src 'self' 'unsafe-inline'" }, { csp: false, cspReportOnly: true, cspReportOnlyRestrictsScripts: true, cspReportOnlyIssues: ["'unsafe-inline'"] }],
  ['report-only ignored when enforced exists', { 'content-security-policy': "script-src 'self'", 'content-security-policy-report-only': "script-src 'none'" }, { cspReportOnly: false, cspReportOnlyRestrictsScripts: false }],
  // Framing
  ['XFO DENY', { 'x-frame-options': 'DENY' }, { frameProtection: true }],
  ['XFO lowercase sameorigin', { 'x-frame-options': 'sameorigin' }, { frameProtection: true }],
  ['XFO ALLOW-FROM is obsolete', { 'x-frame-options': 'ALLOW-FROM https://x.com' }, { frameProtection: false }],
  ['XFO conflicting duplicates invalid', { 'x-frame-options': 'DENY, SAMEORIGIN' }, { frameProtection: false }],
  ['XFO identical duplicates ok', { 'x-frame-options': 'DENY, DENY' }, { frameProtection: true }],
  ['frame-ancestors * is no protection', { 'content-security-policy': 'frame-ancestors *' }, { frameProtection: false }],
  ['frame-ancestors in report-only does not count', { 'content-security-policy-report-only': "frame-ancestors 'none'" }, { frameProtection: false }],
  // Others
  ['XCTO nosniff', { 'x-content-type-options': 'nosniff' }, { xcto: true }],
  ['XCTO duplicated', { 'x-content-type-options': 'nosniff, nosniff' }, { xcto: true }],
  ['XCTO wrong value', { 'x-content-type-options': 'sniff' }, { xcto: false }],
  ['Referrer last valid token wins', { 'referrer-policy': 'no-referrer, unsafe-url' }, { referrerPolicy: 'unsafe-url', referrerLeaksFullUrl: true }],
  ['Referrer unknown token ignored', { 'referrer-policy': 'strict-origin-when-cross-origin, foo' }, { referrerPolicy: 'strict-origin-when-cross-origin', referrerLeaksFullUrl: false }],
  ['Referrer invalid only = missing', { 'referrer-policy': 'nope' }, { referrerPolicy: null }],
  ['Permissions-Policy present', { 'permissions-policy': 'camera=()' }, { permissionsPolicy: true }],
  ['Server name only is fine', { server: 'cloudflare' }, { serverVersionLeak: false }],
  ['Server with version leaks', { server: 'nginx/1.25.3' }, { serverVersionLeak: true }],
  ['IIS version leaks', { server: 'Microsoft-IIS/10.0' }, { serverVersionLeak: true }],
  ['X-Powered-By leaks', { 'x-powered-by': 'Express' }, { serverVersionLeak: true }],
];
for (const [name, input, expected, extra] of cases) {
  test(`headers: ${name}`, () => {
    const r = H(input);
    for (const [k, v] of Object.entries(expected)) assert.deepEqual(r[k], v, `${k}`);
    if (extra) assert.ok(extra(r));
  });
}

test('cookies: flags parsed from attributes only, case-insensitive', () => {
  const [a, b, c, d] = analyzeCookies([
    'session_id=abc; Path=/; HttpOnly; Secure; SameSite=Lax',
    'pref=secure-mode; path=/',           // "secure" in the value must not count
    'auth_token=x; secure; samesite=None', // no HttpOnly
    'tracker=1; SameSite=None',            // None without Secure is rejected by browsers
  ]);
  assert.deepEqual([a.secure, a.httpOnly, a.sameSite, a.sessionLike], [true, true, 'lax', true]);
  assert.deepEqual([b.secure, b.sessionLike], [false, false]);
  assert.deepEqual([c.secure, c.httpOnly, c.sameSite], [true, false, 'none']);
  assert.equal(d.sameSiteNoneWithoutSecure, true);
});

// Cases found by comparing against Mozilla Observatory and nuclei on 40 real sites.
test('HSTS: whole value quoted (nginx mistake) is ignored by browsers', () => {
  assert.equal(analyzeHeaders({ 'strict-transport-security': '"max-age=31536000; includeSubDomains" always' }).hsts, null);
});
test('HSTS: malformed max-age is ignored', () => {
  assert.equal(analyzeHeaders({ 'strict-transport-security': 'max-age-16000000; includeSubDomains' }).hsts, null);
});
test('meta referrer and meta CSP count; meta frame-ancestors does not', () => {
  const meta = metaFromHtml(`<head><meta content="no-referrer" name="referrer"><meta http-equiv='Content-Security-Policy' content="script-src 'self'; frame-ancestors 'none'"></head>`);
  const r = analyzeHeaders({}, meta);
  assert.equal(r.referrerPolicy, 'no-referrer');
  assert.equal(r.cspRestrictsScripts, true);
  assert.equal(r.frameProtection, false);
});
test('meta CSP with HTML-encoded quotes is decoded (seen on a real site)', () => {
  const r = analyzeHeaders({}, metaFromHtml(`<meta http-equiv="Content-Security-Policy" content="script-src &#x27;self&#x27; &#x27;unsafe-eval&#x27;">`));
  assert.equal(r.cspUnsafeEval, true);
});

test('retire.js database: finds vulnerable versions by URL and content, not patched ones', async () => {
  const { loadRetire, retireScan } = await import('./scan.mjs');
  const db = await loadRetire();
  if (!db) return; // offline: built-in fallback is covered by the test above
  const jq = retireScan(db, { url: 'https://code.jquery.com/jquery-1.12.4.min.js' });
  assert.equal(jq[0]?.name + '@' + jq[0]?.version, 'jquery@1.12.4');
  assert.ok(jq[0].ids.includes('CVE-2020-11023'));
  assert.deepEqual(retireScan(db, { content: '/*! jQuery v3.7.1 | (c) OpenJS Foundation */' }), []);
  assert.equal(retireScan(db, { content: '/*! jQuery v3.4.1 | (c) JS Foundation */' })[0]?.version, '3.4.1');
});

test('new secret patterns', () => {
  const js = `x="glpat-${'a'.repeat(20)}";y="npm_${'b'.repeat(36)}";z="GOCSPX-${'c'.repeat(28)}"`;
  assert.deepEqual(findSecrets(js).map((h) => h.type).sort(), ['GitLab token', 'Google OAuth client secret', 'npm token']);
});
test('no-https-redirect is not reported for HSTS-preloaded domains', () => {
  const base = { headers: {}, cookies: [], dns: {}, httpRedirectsToHttps: false };
  assert.ok(findings(base).some((f) => f.id === 'no-https-redirect'));
  assert.ok(!findings({ ...base, hstsPreloaded: true }).some((f) => f.id === 'no-https-redirect'));
});

test('splitTarget keeps the page path and accepts bare domains', async () => {
  const { splitTarget } = await import('./scan.mjs');
  assert.deepEqual(splitTarget('live.com'), { domain: 'live.com', pagePath: '/' });
  assert.deepEqual(splitTarget('https://shop.example.com/login'), { domain: 'shop.example.com', pagePath: '/login' });
  assert.deepEqual(splitTarget('HTTPS://example.com?ref=1'), { domain: 'example.com', pagePath: '/?ref=1' });
  assert.deepEqual(splitTarget('example.com/a/b#x'), { domain: 'example.com', pagePath: '/a/b#x' });
});
