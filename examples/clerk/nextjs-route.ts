// Next.js App Router: app/api/webhooks/clerk-sms/route.ts
// Clerk Dashboard → Webhooks → Add Endpoint → this URL, event `sms.created` → copy the Signing Secret.
// Then Customization → SMS → each template → turn "Delivered by Clerk" off.
import { createClerkSmsWebhook } from '@narcisbodea/smstunnel-otp';

export const POST = createClerkSmsWebhook({
  apiKey: process.env.SMSTUNNEL_API_KEY!,
  signingSecret: process.env.CLERK_SMS_WEBHOOK_SIGNING_SECRET!,
});
