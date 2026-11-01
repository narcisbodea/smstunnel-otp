/**
 * Better Auth `phoneNumber` plugin: `sendOTP` (and `sendPasswordResetOTP`) take `({ phoneNumber, code }, ctx?)`.
 * Better Auth runs them in the background when it can (`runInBackgroundOrAwait`), so the sign-in request isn't held
 * up by the send.
 *
 * Docs: https://www.better-auth.com/docs/plugins/phone-number
 */
import { sendCode, type CodeTextOptions, type SmsTunnelConnection } from './core';

export interface BetterAuthSendOtpOptions extends SmsTunnelConnection {
  /** Text around the code, default `"Your verification code is {code}"`. */
  template?: CodeTextOptions['template'];
}

/** The function shape Better Auth's `phoneNumber({ sendOTP })` expects. */
export type BetterAuthSendOtp = (data: { phoneNumber: string; code: string }, ctx?: unknown) => Promise<void>;

/**
 * ```ts
 * phoneNumber({
 *   sendOTP: smstunnelSendOTP({ apiKey: process.env.SMSTUNNEL_API_KEY! }),
 *   sendPasswordResetOTP: smstunnelSendOTP({ apiKey: process.env.SMSTUNNEL_API_KEY!, template: 'Your password reset code is {code}' }),
 * })
 * ```
 *
 * Rejects with {@link SmsTunnelOtpError} when the code can't be sent.
 */
export function smstunnelSendOTP(options: BetterAuthSendOtpOptions): BetterAuthSendOtp {
  return async ({ phoneNumber, code }) => {
    await sendCode({ ...options, to: phoneNumber, code, template: options.template });
  };
}
