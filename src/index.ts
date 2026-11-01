/**
 * @narcisbodea/smstunnel-otp: send the sign-in and verification codes of your auth platform from your own Android
 * phone and number, with SMSTunnel (https://smstunnel.io).
 */
export {
  sendCode,
  sendText,
  buildCodeMessage,
  containsCode,
  DEFAULT_SERVER_URL,
  DEFAULT_TEMPLATE,
  DEFAULT_TIMEOUT_MS,
  MAX_CODE_TEXT_LENGTH,
} from './core';
export type { SmsTunnelConnection, CodeTextOptions, SendCodeOptions, SendTextOptions, SendResult } from './core';

export { SmsTunnelOtpError, WebhookVerificationError, errorMessageOf } from './errors';
export type { SmsTunnelOtpErrorCode, WebhookVerificationErrorCode } from './errors';

export {
  verifyWebhook,
  signWebhook,
  parseWebhookSecrets,
  headerOf,
  timingSafeEqual,
  RecentWebhookIds,
  DEFAULT_TOLERANCE_SECONDS,
} from './webhooks';
export type { VerifyWebhookOptions, VerifiedWebhook, HeadersInput } from './webhooks';

export { toResponse } from './http';
export type { WebhookResult, RawWebhookRequest, WebhookHandler } from './http';

export {
  createSupabaseSendSmsHook,
  parseSupabaseSendSmsPayload,
  supabasePhone,
  SUPABASE_DEFAULT_TIMEOUT_MS,
} from './supabase';
export type { SupabaseSendSmsHookOptions, SupabaseSendSmsPayload } from './supabase';

export { createAuth0CustomPhoneProvider, createAuth0SendPhoneMessage } from './auth0';
export type {
  Auth0Options,
  Auth0CustomPhoneProviderEvent,
  Auth0CustomPhoneProviderApi,
  Auth0SendPhoneMessageEvent,
} from './auth0';

export { createClerkSmsWebhook, planClerkSmsEvent } from './clerk';
export type { ClerkSmsWebhookOptions, ClerkSmsMessage, ClerkSmsEventAction } from './clerk';

export { smstunnelSendOTP } from './better-auth';
export type { BetterAuthSendOtpOptions, BetterAuthSendOtp } from './better-auth';
