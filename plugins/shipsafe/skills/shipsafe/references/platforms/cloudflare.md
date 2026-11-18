# Cloudflare

Pick the layer the project already uses.

**Cloudflare Pages:** `_headers` file in the build output dir (same syntax as Netlify, see netlify.md).

**Workers:** set headers on the response:
```js
const h = new Headers(response.headers);
h.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
h.set('X-Content-Type-Options', 'nosniff');
h.set('X-Frame-Options', 'DENY');
h.set('Referrer-Policy', 'strict-origin-when-cross-origin');
h.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
h.set('Content-Security-Policy-Report-Only', "default-src 'self'; script-src 'self' <hosts>; frame-ancestors 'none'; object-src 'none'; base-uri 'self'");
return new Response(response.body, { status: response.status, headers: h });
```

**Proxy only (orange cloud in front of another origin):** there is nothing to edit in the repo. Tell the user the dashboard steps:
- SSL/TLS → Edge Certificates → turn on **Always Use HTTPS** and **HSTS**.
- Rules → Transform Rules → **Modify Response Header**: add the headers above.

Rocket Loader rewrites script tags and can conflict with a strict CSP. Mention it if CSP violations show up.
