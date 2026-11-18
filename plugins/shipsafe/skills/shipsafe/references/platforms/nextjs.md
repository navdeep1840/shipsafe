# Next.js

Headers go in `next.config.(js|mjs|ts)` → `headers()`. If an nginx or Cloudflare layer sits in front and sets headers too, set them in one place only.

```js
const securityHeaders = [
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' },
  // Built per references/csp.md. Report-only until the user approves enforcing.
  { key: 'Content-Security-Policy-Report-Only', value: "default-src 'self'; script-src 'self' 'unsafe-inline' <hosts>; connect-src 'self' <hosts>; frame-ancestors 'none'; object-src 'none'; base-uri 'self'" },
];

const nextConfig = {
  poweredByHeader: false,            // removes X-Powered-By: Next.js (version-leak)
  productionBrowserSourceMaps: false, // public-source-map
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  },
};
```
Merge into the existing config object. Don't replace the user's other settings.

## Notes
- The App Router injects inline scripts for hydration. Without nonces, `script-src` needs `'unsafe-inline'`. To drop it, generate a per-request nonce in middleware (`middleware.ts`, renamed `proxy.ts` in Next.js 16+), set the CSP header there, and read the nonce in the layout. Nonces make pages dynamic (no static caching), so explain that cost and treat it as a follow-up, not part of the first fix.
- Dev mode needs `'unsafe-eval'` for fast refresh. While the CSP is report-only this doesn't matter. When the user approves enforcing, send the enforced header only in production (`process.env.NODE_ENV === 'production' ? enforced : reportOnly`) rather than adding `'unsafe-eval'`.
- Static export (`output: 'export'`) ignores `headers()`. Set the headers at the host (vercel.md, netlify.md, nginx.md, cloudflare.md).
- Cookies: set flags where they are created (`cookies().set(name, value, { httpOnly: true, secure: true, sameSite: 'lax' })`, or the auth library's cookie options).
