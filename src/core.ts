/**
 * The one call every adapter ends in: hand a sign-in code to your SMSTunnel account, and your own phone sends it
 * from its own number. Fetch only, so it runs in Node 18+, Deno, Bun, Cloudflare Workers and Auth0 Actions.
 */
import { SmsTunnelOtpError } from './errors';

export const DEFAULT_SERVER_URL = 'https://smstunnel.io';
export const DEFAULT_TEMPLATE = 'Your verification code is {code}';
export const DEFAULT_TIMEOUT_MS = 10_000;
/** SMSTunnel refuses longer code texts (two SMS at most). */
export const MAX_CODE_TEXT_LENGTH = 320;

/** How to reach your SMSTunnel account. Shared by every function in this package. */
export interface SmsTunnelConnection {
  /** Your SMSTunnel API key (dashboard → Apps → Add an app), with the `sms:send` permission. Sent as `X-API-Key`. */
  apiKey: string;
  /** `https://smstunnel.io` unless you run your own instance. */
  serverUrl?: string;
  /** Send from this phone of your account. Leave it out to let SMSTunnel pick your phone that is online. */
  deviceId?: string;
  /** Country code for numbers written without one, for example `"40"` or `"+1"`. */
  defaultCountryCode?: string;
  /** Give up after this many milliseconds (default 10000). */
  timeoutMs?: number;
  /** A `fetch` to use instead of the global one (tests, proxies). */
  fetch?: (input: string, init: RequestInit) => Promise<Response>;
}

/** How the text around the code is written. */
export interface CodeTextOptions {
  /**
   * The full text to send. If it doesn't contain the code as a separate word, the code is added at the end.
   * Takes precedence over `template`.
   */
  message?: string;
  /**
   * A text with a `{code}` placeholder (`{{code}}` works too), default `"Your verification code is {code}"`.
   * If the placeholder is missing, the code is added at the end.
   */
  template?: string;
}

export interface SendCodeOptions extends SmsTunnelConnection, CodeTextOptions {
  /** The recipient, in international format (`+14155550123`), or local when `defaultCountryCode` is set. */
  to: string;
  /** The code your auth platform generated. It always ends up in the text. */
  code: string;
}

export interface SendTextOptions extends SmsTunnelConnection {
  to: string;
  message: string;
}

/** What SMSTunnel answered. */
export interface SendResult {
  success: true;
  messageId: string;
  /** `true` when your phone was offline: the text waits and goes out as soon as the phone is back. */
  queued: boolean;
  /** `true` when the free plan's daily allowance is used up and SMSTunnel added a short footer. */
  branded: boolean;
  remaining?: unknown;
}

/**
 * Builds the text for a code: `message` if given, else `template` (default `"Your verification code is {code}"`).
 * Guarantees the result contains the code as a separate word, and that it fits SMSTunnel's 320-character limit.
 */
export function buildCodeMessage(code: string, options: CodeTextOptions = {}): string {
  const value = typeof code === 'string' || typeof code === 'number' ? String(code).trim() : '';
  if (!value) throw invalid('code is required');

  let text: string;
  if (typeof options.message === 'string' && options.message.trim()) {
    text = options.message.trim();
  } else {
    const template = typeof options.template === 'string' && options.template.trim() ? options.template : DEFAULT_TEMPLATE;
    text = template.replace(/\{\{\s*code\s*\}\}|\{code\}/g, value).trim();
  }
  if (!containsCode(text, value)) text = text ? `${text} ${value}` : value;

  if (text.length > MAX_CODE_TEXT_LENGTH) {
    throw new SmsTunnelOtpError(
      `The code text is ${text.length} characters; SMSTunnel accepts at most ${MAX_CODE_TEXT_LENGTH}. Use a shorter template.`,
      { code: 'MESSAGE_TOO_LONG' },
    );
  }
  return text;
}

/** `true` when `text` contains `code` as a word of its own (not inside a longer number or word). */
export function containsCode(text: string, code: string): boolean {
  if (!code) return false;
  let from = 0;
  for (;;) {
    const at = text.indexOf(code, from);
    if (at < 0) return false;
    const before = at > 0 ? text[at - 1] : '';
    const after = text[at + code.length] ?? '';
    if (!isWordChar(before) && !isWordChar(after)) return true;
    from = at + 1;
  }
}

function isWordChar(ch: string): boolean {
  return /[0-9A-Za-z]/.test(ch);
}

/**
 * Sends a sign-in / verification code through `POST /api/v1/sms/send-2fa`, so it counts against your 2FA allowance,
 * not your regular texts. One recipient per call.
 *
 * @throws {SmsTunnelOtpError} with the HTTP `status`, a `code` and `retryable`.
 */
export async function sendCode(options: SendCodeOptions): Promise<SendResult> {
  const to = requireRecipient(options?.to);
  const message = buildCodeMessage(options.code, options);
  return post('/api/v1/sms/send-2fa', { to, message }, options);
}

/**
 * Sends a text that carries no code (for example an Auth0 "your password was changed" notice) through
 * `POST /api/v1/sms/send`. It counts against your regular texts.
 */
export async function sendText(options: SendTextOptions): Promise<SendResult> {
  const to = requireRecipient(options?.to);
  const message = typeof options.message === 'string' ? options.message.trim() : '';
  if (!message) throw invalid('message is required');
  return post('/api/v1/sms/send', { to, message }, options);
}

function requireRecipient(to: unknown): string {
  const value = typeof to === 'string' ? to.trim() : '';
  if (!value) throw invalid('to (the recipient phone number) is required');
  return value;
}

function invalid(message: string): SmsTunnelOtpError {
  return new SmsTunnelOtpError(message, { code: 'INVALID_ARGUMENT' });
}

async function post(
  path: string,
  fields: { to: string; message: string },
  connection: SmsTunnelConnection,
): Promise<SendResult> {
  const apiKey = typeof connection.apiKey === 'string' ? connection.apiKey.trim() : '';
  if (!apiKey) throw invalid('apiKey is required (your SMSTunnel API key)');

  const base = (connection.serverUrl?.trim() || DEFAULT_SERVER_URL).replace(/\/+$/, '');
  const body: Record<string, string> = { ...fields };
  if (connection.deviceId?.trim()) body.deviceId = connection.deviceId.trim();
  if (connection.defaultCountryCode?.trim()) body.defaultCountryCode = connection.defaultCountryCode.trim();

  const timeoutMs = connection.timeoutMs && connection.timeoutMs > 0 ? connection.timeoutMs : DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const init: RequestInit = {
    method: 'POST',
    headers: { 'X-API-Key': apiKey, 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
    signal: controller.signal,
  };

  let status: number;
  let ok: boolean;
  let text: string;
  try {
    // Call the global `fetch` directly (not a detached reference): some runtimes refuse a fetch called on another `this`.
    const res = connection.fetch ? await connection.fetch(`${base}${path}`, init) : await fetch(`${base}${path}`, init);
    status = res.status;
    ok = res.ok;
    text = await res.text();
  } catch (err) {
    if (controller.signal.aborted) {
      throw new SmsTunnelOtpError(`SMSTunnel did not answer within ${timeoutMs} ms`, { code: 'TIMEOUT', retryable: true, cause: err });
    }
    const reason = err instanceof Error ? err.message : String(err);
    throw new SmsTunnelOtpError(`Could not reach SMSTunnel at ${base}: ${reason}`, { code: 'NETWORK_ERROR', retryable: true, cause: err });
  } finally {
    clearTimeout(timer);
  }

  let data: unknown = undefined;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }
  if (!ok) throw SmsTunnelOtpError.fromResponse(status, data);

  const answer = data && typeof data === 'object' ? (data as Record<string, any>) : undefined;
  if (!answer) {
    throw new SmsTunnelOtpError('SMSTunnel answered with something that is not JSON', { status, code: 'INVALID_RESPONSE', body: data });
  }
  if (answer.success === false) throw SmsTunnelOtpError.fromResponse(status, answer);

  const inner = answer.data && typeof answer.data === 'object' ? answer.data : {};
  return {
    success: true,
    messageId: String(answer.messageId ?? inner.messageId ?? ''),
    queued: Boolean(answer.queued ?? inner.queued),
    branded: Boolean(inner.branded),
    ...(inner.remaining !== undefined ? { remaining: inner.remaining } : {}),
  };
}
