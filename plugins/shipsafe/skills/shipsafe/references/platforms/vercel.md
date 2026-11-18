# Vercel (non-Next.js, or static)

`vercel.json` at the project root:

```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=(), payment=()" },
        { "key": "Content-Security-Policy-Report-Only", "value": "default-src 'self'; script-src 'self' <hosts>; connect-src 'self' <hosts>; frame-ancestors 'none'; object-src 'none'; base-uri 'self'" }
      ]
    }
  ]
}
```
Merge into the existing `headers` array if there is one. Vercel already redirects HTTP→HTTPS and sends HSTS on its own domains. Custom domains still benefit from the explicit header.

For a Next.js app on Vercel, use nextjs.md instead.
