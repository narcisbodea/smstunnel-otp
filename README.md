# SMSTunnel OTP

Send the sign-in and verification codes of **Supabase Auth, Auth0, Clerk, Better Auth and Ory** from **your own Android phone**, from **your own number**, with [SMSTunnel](https://smstunnel.io).

Your auth platform creates the code as usual. This package hands it to your SMSTunnel account, and your phone sends it from its own SIM, so people get the code from a number they know. There is no per-message bill from an SMS provider. Codes go through SMSTunnel's 2FA endpoint (`POST /api/v1/sms/send-2fa`), which has its own allowance, separate from your regular texts.

Your phone needs the SMSTunnel app from Google Play:

<a href="https://play.google.com/store/apps/details?id=io.smstunnel.app"><img src="https://smstunnel.io/google-play-badge.png" alt="Get it on Google Play" height="56"></a>

No runtime dependencies (Fetch and WebCrypto only): it runs in Node 18+, Deno (Supabase Edge Functions), Bun, Cloudflare Workers and Auth0 Actions.

```bash
npm install @narcisbodea/smstunnel-otp
```

## Before you start

1. Install the [SMSTunnel app from Google Play](https://play.google.com/store/apps/details?id=io.smstunnel.app) on your Android phone and sign in. Sign in at [smstunnel.io](https://smstunnel.io) with the same account: the phone appears under **Devices**.
2. In your SMSTunnel dashboard, create an API key with the `sms:send` permission. Keep it in your platform's secrets, never in client code.
3. Keep the default **6-digit** codes. SMSTunnel's code endpoint recognizes codes of 4, 6, 7 or 8 digits. If you change the code length (in Auth0 or Better Auth, for example), pick one of these.

If your phone is offline, the code waits and goes out as soon as the phone is back.

## Supabase Auth: Send SMS hook

Supabase calls an HTTPS endpoint with the user's number and the code instead of its built-in SMS provider. This package gives you that endpoint, including the Standard Webhooks signature check.

`supabase/functions/send-sms/index.ts`:

```ts
import { createSupabaseSendSmsHook } from 'npm:@narcisbodea/smstunnel-otp@^1.0.0';

Deno.serve(
  createSupabaseSendSmsHook({
    apiKey: Deno.env.get('SMSTUNNEL_API_KEY')!,
    hookSecret: Deno.env.get('SEND_SMS_HOOK_SECRETS')!, // v1,whsec_...
    template: 'Your Acme code is {code}', // optional
  }),
);
```

A ready copy, with a `deno.json` for the import, is in [`examples/supabase/functions/send-sms`](examples/supabase/functions/send-sms).

1. Deploy it without JWT checks (the signature protects it): `supabase functions deploy send-sms --no-verify-jwt`
2. Dashboard → **Authentication → Hooks** → **Add a new hook** → **Send SMS hook** → type **HTTPS**, URL `https://<project-ref>.supabase.co/functions/v1/send-sms` → **Generate secret** → **Create**.
3. Store the secrets: `supabase secrets set SMSTUNNEL_API_KEY=... SEND_SMS_HOOK_SECRETS='v1,whsec_...'`
4. Dashboard → **Authentication → Sign In / Providers → Phone**: enable it and save. The SMS provider fields aren't used while the hook is on. Keep phone auto-confirm off, or sign-ups never ask for a code.

What the hook does:

- It verifies the signature with your secret: `webhook-id`, `webhook-timestamp` and `webhook-signature`, HMAC-SHA256, constant-time comparison, 5-minute window. Several secrets separated by `|` are accepted while you rotate.
- It sends the code to `sms.phone` (Supabase sets it to the new number when a user changes theirs, and to the MFA factor's number), or else to `user.phone`. It adds the `+` that Supabase leaves out.
- It answers `200 {}` on success. Errors use Supabase's shape, `{"error":{"http_code":…,"message":"…"}}`. A rate limit or an unreachable server answers 429 or 503 with `retry-after`, which Supabase retries within its 5-second budget. The default timeout is 4 s.

For local development, add this to `supabase/config.toml`:

```toml
[auth.hook.send_sms]
enabled = true
uri = "http://host.docker.internal:54321/functions/v1/send-sms"
secrets = "env(SEND_SMS_HOOK_SECRETS)"

[functions.send-sms]
verify_jwt = false
```

## Auth0: Actions

Auth0 can hand phone messages to an Action. Use the `custom-phone-provider` trigger, which Auth0 recommends (one provider for MFA, passwordless SMS and phone sign-up). The older `send-phone-message` trigger, for MFA only, is supported too.

### Custom Phone Provider (recommended)

**Branding → Phone Provider → Custom**, delivery method **Text**. In the Action editor, add the dependency `@narcisbodea/smstunnel-otp` and the secret `SMSTUNNEL_API_KEY`, then paste:

```js
const { createAuth0CustomPhoneProvider } = require('@narcisbodea/smstunnel-otp');

const sendWithSmsTunnel = createAuth0CustomPhoneProvider();

exports.onExecuteCustomPhoneProvider = async (event, api) => {
  await sendWithSmsTunnel(event, api);
};
```

Save, then use **Send Test Message**. For MFA, also turn on **Use Tenant-Level Messaging Provider** under **Security → Multi-factor Auth → Phone Message**.

- Codes (`otp_verify`, `otp_enroll`) go through the 2FA endpoint, using the text Auth0 rendered (your template and the user's language). Pass `{ template: 'Your Acme code is {code}' }` to write your own.
- Notices without a code (`blocked_account`, `change_password`, `password_breach`) are sent as regular texts. Pass `{ nonCodeMessages: 'skip' }` to ignore them.
- Failures are reported to Auth0 as documented. Rate limits and network errors call `api.notification.retry(reason)`, which Auth0 retries up to 5 times. A bad key or a bad number calls `api.notification.drop(reason)`.
- SMSTunnel sends text messages only. A voice delivery is dropped with a clear reason; set the delivery method to **Text**.

If you'd rather not add a dependency, [`examples/auth0/custom-phone-provider.no-dependency.js`](examples/auth0/custom-phone-provider.no-dependency.js) does the same in about twenty lines.

### Send Phone Message (MFA)

**Security → Multi-factor Auth → Phone Message**, delivery method **SMS**, provider **Custom**. Same dependency and secret, then:

```js
const { createAuth0SendPhoneMessage } = require('@narcisbodea/smstunnel-otp');

const sendWithSmsTunnel = createAuth0SendPhoneMessage();

exports.onExecuteSendPhoneMessage = async (event, api) => {
  await sendWithSmsTunnel(event, api);
};
```

It throws when the code can't be sent, so Auth0 logs the failure; a `voice` message throws a clear error. Optional secrets for both triggers: `SMSTUNNEL_DEVICE_ID` (send from one phone of your account) and `SMSTUNNEL_SERVER_URL` (self-hosted SMSTunnel).

## Clerk: `sms.created` webhook

When you turn **Delivered by Clerk** off for an SMS template, Clerk stops sending that text and sends you an `sms.created` webhook instead. This package gives you the endpoint, with the Svix (Standard Webhooks) signature check.

Next.js, `app/api/webhooks/clerk-sms/route.ts`:

```ts
import { createClerkSmsWebhook } from '@narcisbodea/smstunnel-otp';

export const POST = createClerkSmsWebhook({
  apiKey: process.env.SMSTUNNEL_API_KEY!,
  signingSecret: process.env.CLERK_SMS_WEBHOOK_SIGNING_SECRET!, // whsec_...
});
```

1. Clerk Dashboard → **Webhooks** → **Add Endpoint** → your URL, subscribe to `sms.created` → copy the **Signing Secret**.
2. **Customization → SMS** → open each template you want sent from your phone (Verification code, Reset password code…) → turn **Delivered by Clerk** off. The setting is per template.
3. Keep the route public in your Clerk middleware: webhooks carry no session.

It sends `data.to_phone_number` the text Clerk rendered (`data.message`) through the 2FA endpoint, making sure `data.data.otp_code` is in it. Events with `delivered_by_clerk: true` and other event types get a `200` and nothing is sent. Templates without a code are sent as regular texts; pass `nonCodeMessages: 'skip'` to ignore them. A bad signature answers `400`.

Other frameworks: `handler.process({ method, headers, body })` returns `{ status, headers, body }`. It needs the raw body; see [`examples/clerk/express.mjs`](examples/clerk/express.mjs).

## Better Auth: `phoneNumber` plugin

```ts
import { betterAuth } from 'better-auth';
import { phoneNumber } from 'better-auth/plugins';
import { smstunnelSendOTP } from '@narcisbodea/smstunnel-otp';

const apiKey = process.env.SMSTUNNEL_API_KEY!;

export const auth = betterAuth({
  plugins: [
    phoneNumber({
      sendOTP: smstunnelSendOTP({ apiKey, template: 'Your Acme code is {code}' }),
      sendPasswordResetOTP: smstunnelSendOTP({ apiKey, template: 'Your Acme password reset code is {code}' }),
    }),
  ],
});
```

Better Auth runs `sendOTP` in the background when it can, so sign-in doesn't wait for the send. If people type local numbers, add `defaultCountryCode: '40'` (or your country), or validate numbers with the plugin's `phoneNumberValidator`.

## Ory: Kratos and Ory Network

No code needed: Ory's courier HTTP channel calls SMSTunnel directly. Merge this into your identity config ([`examples/ory/kratos.courier.yml`](examples/ory/kratos.courier.yml)):

```yaml
courier:
  channels:
    - id: sms
      type: http
      request_config:
        url: https://smstunnel.io/api/v1/sms/send-2fa
        method: POST
        body: base64://ZnVuY3Rpb24oY3R4KSB7CiAgdG86IGN0eC5yZWNpcGllbnQsCiAgbWVzc2FnZTogY3R4LmJvZHksCn0K
        headers:
          Content-Type: application/json
        auth:
          type: api_key
          config:
            name: X-API-Key
            value: YOUR_SMSTUNNEL_API_KEY
            in: header
```

The `body` is this Jsonnet, base64-encoded ([`examples/ory/smstunnel-sms.jsonnet`](examples/ory/smstunnel-sms.jsonnet); self-hosted Kratos can also use `file://…`):

```jsonnet
function(ctx) {
  to: ctx.recipient,
  message: ctx.body,
}
```

- **Ory Network:** `ory get identity-config --project <id> --workspace <id> --format yaml > identity-config.yaml`, add the block, then `ory update identity-config --project <id> --workspace <id> --file identity-config.yaml`. You can also enter it in the Console's SMS configuration.
- **Self-hosted Kratos:** add the block to `kratos.yml` and run the courier (`kratos serve --watch-courier` or `kratos courier watch`).
- Your identity schema needs a phone trait with `"via": "sms"` (for example `"credentials": { "code": { "identifier": true, "via": "sms" } }` for sign-in codes, `"verification": { "via": "sms" }` for verification). Ory has SMS templates for `login_code`, `verification_code` and `recovery_code`, and they include the code.

## Any other platform

```ts
import { sendCode, SmsTunnelOtpError } from '@narcisbodea/smstunnel-otp';

await sendCode({
  apiKey: process.env.SMSTUNNEL_API_KEY!,
  to: '+14155550123',
  code: '123456',
  template: 'Your Acme code is {code}', // or message: 'full text'; the code is added if it is missing
  // deviceId, defaultCountryCode, serverUrl, timeoutMs (default 10000)
});
```

`sendCode` always puts the code in the text, as a word of its own, and refuses texts over 320 characters before calling SMSTunnel. It sends one recipient per call.

## Errors

Everything throws (or reports) a `SmsTunnelOtpError`:

| Field | Meaning |
| --- | --- |
| `status` | HTTP status from SMSTunnel; `0` for a timeout, a network error or a refused argument |
| `code` | SMSTunnel's own code when it sends one (for example `PERMISSION_REQUIRED`), else `UNAUTHORIZED` (401), `FORBIDDEN` (403), `BAD_REQUEST` (400), `RATE_LIMITED` (429), `SERVER_ERROR` (5xx), `TIMEOUT`, `NETWORK_ERROR`, `INVALID_ARGUMENT`, `MESSAGE_TOO_LONG`, `UNSUPPORTED_DELIVERY_METHOD` |
| `retryable` | `true` for 429, 5xx, timeouts and network errors |
| `message` | What went wrong, in words |

A webhook that fails the signature check throws `WebhookVerificationError` (inside the Supabase and Clerk handlers it becomes a 401 or 400 answer, and nothing is sent). `verifyWebhook()` and `signWebhook()` are exported if you need the check elsewhere.

## Security notes

- Signatures are checked over the raw body before anything is parsed. Old or future timestamps (more than 5 minutes off) are refused, and malformed or short secrets fail at start-up.
- Each handler remembers recent webhook ids, so a retry of a code that already went out isn't sent twice. This memory is per instance.
- Nothing in this package logs codes or keys.

## Development

```bash
npm install
npm run build        # ESM + CJS + types in dist/
npm run typecheck
npm test             # unit tests (mocked fetch), CJS build, Node 18 WebCrypto fallback
SMSTUNNEL_LOCAL_KEY_FILE=key.json npm run test:e2e   # every adapter against a LOCAL SMSTunnel API ({ serverUrl, apiKey, deviceId }), never production
DENO_BIN=deno npm run test:deno   # the Supabase example, run by Deno, against the local API
```

The Ory config is checked with a real Kratos in Docker; the steps are at the top of [`test/ory/make-config.mjs`](test/ory/make-config.mjs).

## License

MIT © NARBOWEB SRL

Supabase, Auth0, Clerk, Better Auth and Ory are trademarks of their respective owners. SMSTunnel OTP is not affiliated with, endorsed by, or sponsored by Supabase, Auth0 (Okta), Clerk, Better Auth or Ory.
