# Express / Node server

If `helmet` is already installed, use it. Otherwise suggest installing it: it is the standard package for this and adds the headers in one line. If the user declines a new dependency, set the headers manually with `res.setHeader` in a middleware.

```js
import helmet from 'helmet';
app.disable('x-powered-by'); // version-leak
app.use(helmet({
  contentSecurityPolicy: {
    reportOnly: true, // until the user approves enforcing
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'" /*, '<hosts>' */],
      connectSrc: ["'self'" /*, '<hosts>' */],
      frameAncestors: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
    },
  },
  strictTransportSecurity: { maxAge: 63072000, includeSubDomains: true },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));
```
helmet does not set `Permissions-Policy`. Add it with `res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()')`.

Session cookies (`express-session`): `cookie: { httpOnly: true, secure: true, sameSite: 'lax' }`, plus `app.set('trust proxy', 1)` when running behind a proxy.

CORS (`cors` package): `cors({ origin: ['https://example.com'], credentials: true })`. Never use `origin: true` together with `credentials: true`.
