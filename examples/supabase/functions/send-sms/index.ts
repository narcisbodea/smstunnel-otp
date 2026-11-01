// Supabase Edge Function for the Auth "Send SMS" hook: your sign-in codes go out from your own phone and number
// through SMSTunnel instead of an SMS provider.
//
// Deploy:   supabase functions deploy send-sms --no-verify-jwt
// Secrets:  supabase secrets set SMSTUNNEL_API_KEY=... SEND_SMS_HOOK_SECRETS='v1,whsec_...'
// Then:     Dashboard → Authentication → Hooks → Send SMS hook → HTTPS →
//           https://<project-ref>.supabase.co/functions/v1/send-sms
import { createSupabaseSendSmsHook } from '@narcisbodea/smstunnel-otp';

Deno.serve(
  createSupabaseSendSmsHook({
    apiKey: Deno.env.get('SMSTUNNEL_API_KEY')!,
    // The secret Supabase generated for the hook, as shown: v1,whsec_...
    hookSecret: Deno.env.get('SEND_SMS_HOOK_SECRETS')!,
    // Optional: the text around the code (default "Your verification code is {code}").
    template: Deno.env.get('SMSTUNNEL_TEMPLATE') || undefined,
    // Optional: only for a self-hosted SMSTunnel; defaults to https://smstunnel.io.
    serverUrl: Deno.env.get('SMSTUNNEL_SERVER_URL') || undefined,
  }),
);
