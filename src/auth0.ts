/**
 * Auth0 Actions. Two triggers can hand phone messages to your own code; both are supported:
 *
 * - `custom-phone-provider` (Branding → Phone Provider → Custom). Auth0's recommended path ("Unified Phone
 *   Experience"): one provider for MFA, passwordless SMS and phone-number sign-up. Handler
 *   `exports.onExecuteCustomPhoneProvider(event, api)`, message in `event.notification`; failures are reported
 *   with `api.notification.retry(reason)` / `api.notification.drop(reason)`.
 *   Docs: https://auth0.com/docs/customize/phone-messages/configure-phone-messaging-providers/configure-a-custom-phone-provider
 * - `send-phone-message` (Security → Multi-factor Auth → Phone Message → Custom, when "Use Tenant-Level Messaging
 *   Provider" is off). Handler `exports.onExecuteSendPhoneMessage(event, api)`, message in `event.message_options`;
 *   a failure is a thrown error.
 *   Docs: https://auth0.com/docs/customize/actions/explore-triggers/mfa-notifications-trigger
 *
 * SMSTunnel sends text messages only: a voice delivery is refused with a clear reason.
 */
import { sendCode, sendText, type CodeTextOptions, type SmsTunnelConnection } from './core';
import { SmsTunnelOtpError } from './errors';

/** Settings for both Auth0 handlers. Anything left out is read from the Action's secrets at run time. */
export interface Auth0Options extends Partial<SmsTunnelConnection> {
  /** Default: the Action secret `SMSTUNNEL_API_KEY`. */
  apiKey?: string;
  /** Default: the Action secret `SMSTUNNEL_SERVER_URL`, else `https://smstunnel.io`. */
  serverUrl?: string;
  /** Default: the Action secret `SMSTUNNEL_DEVICE_ID`, else the phone of your account that is online. */
  deviceId?: string;
  /**
   * Text around the code. By default the text Auth0 rendered (your tenant's template and the user's language) is sent;
   * the code is added if it is missing.
   */
  template?: CodeTextOptions['template'];
  /**
   * `custom-phone-provider` also sends notices without a code (`blocked_account`, `change_password`,
   * `password_breach`). `'send'` (default) sends them through `/api/v1/sms/send` as regular texts; `'skip'` ignores them.
   */
  nonCodeMessages?: 'send' | 'skip';
}

type Secrets = Record<string, string | undefined>;

/** `event` of the `custom-phone-provider` trigger (the fields this handler reads). */
export interface Auth0CustomPhoneProviderEvent {
  notification: {
    /** `otp_verify`, `otp_enroll`, `blocked_account`, `change_password`, `password_breach`. */
    message_type: string;
    /** `text` or `voice`. */
    delivery_method: string;
    /** E.164. */
    recipient: string;
    as_text?: string;
    as_voice?: string;
    /** The one-time code, for `otp_verify` and `otp_enroll`. */
    code?: string;
    from?: string;
    locale?: string;
    [key: string]: unknown;
  };
  secrets?: Secrets;
  [key: string]: unknown;
}

/** `api` of the `custom-phone-provider` trigger. */
export interface Auth0CustomPhoneProviderApi {
  notification: {
    /** Failed for good: logged, not retried. */
    drop(reason: string): void;
    /** Failed for now: logged, retried up to 5 times in the next minutes. */
    retry(reason: string): void;
  };
  [key: string]: unknown;
}

/** `event` of the `send-phone-message` trigger (the fields this handler reads). */
export interface Auth0SendPhoneMessageEvent {
  message_options: {
    /** `enrollment` or `second-factor-authentication`. */
    action?: string;
    code: string;
    /** `sms` or `voice`. */
    message_type: string;
    recipient: string;
    text?: string;
    [key: string]: unknown;
  };
  secrets?: Secrets;
  [key: string]: unknown;
}

const VOICE_REFUSED =
  'SMSTunnel sends text messages only, so it cannot deliver this code by voice call. Set the delivery method to Text / SMS in Auth0.';

/**
 * Handler for the `custom-phone-provider` trigger.
 *
 * ```js
 * const { createAuth0CustomPhoneProvider } = require('@narcisbodea/smstunnel-otp');
 * exports.onExecuteCustomPhoneProvider = createAuth0CustomPhoneProvider();
 * ```
 *
 * On failure it calls `api.notification.retry(reason)` (rate limit, SMSTunnel unreachable) or
 * `api.notification.drop(reason)` (bad key, bad number, voice), as Auth0 documents, and returns. Without an `api`
 * object it throws the {@link SmsTunnelOtpError} instead.
 */
export function createAuth0CustomPhoneProvider(options: Auth0Options = {}) {
  return async function onExecuteCustomPhoneProvider(
    event: Auth0CustomPhoneProviderEvent,
    api?: Auth0CustomPhoneProviderApi,
  ): Promise<void> {
    try {
      const n = event?.notification;
      if (!n || typeof n !== 'object') {
        throw new SmsTunnelOtpError('The Auth0 event has no notification', { code: 'INVALID_ARGUMENT' });
      }
      if (String(n.delivery_method).toLowerCase() === 'voice') {
        throw new SmsTunnelOtpError(VOICE_REFUSED, { code: 'UNSUPPORTED_DELIVERY_METHOD' });
      }
      const connection = connectionFor(options, event.secrets);
      const code = typeof n.code === 'string' || typeof n.code === 'number' ? String(n.code).trim() : '';
      if (code) {
        await sendCode({ ...connection, to: n.recipient, code, message: options.template ? undefined : n.as_text, template: options.template });
      } else if ((options.nonCodeMessages ?? 'send') === 'send') {
        await sendText({ ...connection, to: n.recipient, message: n.as_text ?? '' });
      }
    } catch (err) {
      const error = asOtpError(err);
      if (!api?.notification) throw error;
      const reason = (/^SMSTunnel\b/.test(error.message) ? error.message : `SMSTunnel: ${error.message}`).slice(0, 1024);
      if (error.retryable) api.notification.retry(reason);
      else api.notification.drop(reason);
    }
  };
}

/**
 * Handler for the `send-phone-message` trigger (MFA with a custom provider).
 *
 * ```js
 * const { createAuth0SendPhoneMessage } = require('@narcisbodea/smstunnel-otp');
 * exports.onExecuteSendPhoneMessage = createAuth0SendPhoneMessage();
 * ```
 *
 * Throws {@link SmsTunnelOtpError} when the code can't be sent (Auth0 then fails the MFA challenge and logs it).
 */
export function createAuth0SendPhoneMessage(options: Auth0Options = {}) {
  return async function onExecuteSendPhoneMessage(event: Auth0SendPhoneMessageEvent, _api?: unknown): Promise<void> {
    const m = event?.message_options;
    if (!m || typeof m !== 'object') {
      throw new SmsTunnelOtpError('The Auth0 event has no message_options', { code: 'INVALID_ARGUMENT' });
    }
    if (String(m.message_type).toLowerCase() === 'voice') {
      throw new SmsTunnelOtpError(VOICE_REFUSED, { code: 'UNSUPPORTED_DELIVERY_METHOD' });
    }
    await sendCode({
      ...connectionFor(options, event.secrets),
      to: m.recipient,
      code: m.code,
      message: options.template ? undefined : m.text,
      template: options.template,
    });
  };
}

function connectionFor(options: Auth0Options, secrets: Secrets | undefined): SmsTunnelConnection {
  const s = secrets ?? {};
  const apiKey = options.apiKey ?? s.SMSTUNNEL_API_KEY;
  if (!apiKey || !apiKey.trim()) {
    throw new SmsTunnelOtpError('Add your SMSTunnel API key as the Action secret SMSTUNNEL_API_KEY', { code: 'INVALID_ARGUMENT' });
  }
  const connection: SmsTunnelConnection = { ...options, apiKey };
  const serverUrl = options.serverUrl ?? s.SMSTUNNEL_SERVER_URL;
  const deviceId = options.deviceId ?? s.SMSTUNNEL_DEVICE_ID;
  if (serverUrl) connection.serverUrl = serverUrl;
  if (deviceId) connection.deviceId = deviceId;
  return connection;
}

function asOtpError(err: unknown): SmsTunnelOtpError {
  if (err instanceof SmsTunnelOtpError) return err;
  return new SmsTunnelOtpError(err instanceof Error ? err.message : String(err), { code: 'INVALID_ARGUMENT', cause: err });
}
