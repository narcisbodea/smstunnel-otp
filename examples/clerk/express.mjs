// Express: the webhook needs the raw body (the signature covers the exact bytes Clerk sent).
import express from 'express';
import { createClerkSmsWebhook } from '@narcisbodea/smstunnel-otp';

const clerkSms = createClerkSmsWebhook({
  apiKey: process.env.SMSTUNNEL_API_KEY,
  signingSecret: process.env.CLERK_SMS_WEBHOOK_SIGNING_SECRET,
});

const app = express();
app.post('/api/webhooks/clerk-sms', express.raw({ type: 'application/json' }), async (req, res) => {
  const out = await clerkSms.process({ method: req.method, headers: req.headers, body: req.body });
  res.status(out.status).set(out.headers).send(out.body);
});
app.listen(3000);
