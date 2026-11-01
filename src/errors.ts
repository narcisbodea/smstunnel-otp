/**
 * Errors, in one shape for every adapter.
 */

/** Codes set by this library itself, when SMSTunnel's answer has no `code` of its own. */
export type SmsTunnelOtpErrorCode =
  /** A required option or field is missing or empty (apiKey, to, code...). */
  | 'INVALID_ARGUMENT'
  /** The final text is longer than SMSTunnel accepts for a code (320 characters). */
  | 'MESSAGE_TOO_LONG'
  /** The platform asked for a voice call. SMSTunnel sends text messages only. */
  | 'UNSUPPORTED_DELIVERY_METHOD'
  /** No answer from SMSTunnel before `timeoutMs`. */
  | 'TIMEOUT'
  /** The request did not reach SMSTunnel (DNS, TLS, connection refused...). */
  | 'NETWORK_ERROR'
  /** SMSTunnel answered 2xx with a body that is not the expected JSON. */
  | 'INVALID_RESPONSE'
  /** 400: SMSTunnel refused the request, for example a text without a recognizable code or a bad number. */
  | 'BAD_REQUEST'
  /** 401: the API key is wrong, expired or revoked. */
  | 'UNAUTHORIZED'
  /** 403: the key lacks a permission (`sms:send`) or the plan does not allow the send. */
  | 'FORBIDDEN'
  /** 404 */
  | 'NOT_FOUND'
  /** 429: too many requests, or a daily limit is reached. */
  | 'RATE_LIMITED'
  /** 5xx */
  | 'SERVER_ERROR'
  /** Any other status. */
  | 'HTTP_ERROR'
  | (string & {});

const STATUS_CODES: Record<number, SmsTunnelOtpErrorCode> = {
  400: 'BAD_REQUEST',
  401: 'UNAUTHORIZED',
  403: 'FORBIDDEN',
  404: 'NOT_FOUND',
  429: 'RATE_LIMITED',
};

/**
 * Thrown when a code could not be handed to SMSTunnel.
 *
 * - `status`: the HTTP status SMSTunnel answered with, or `0` when there was no answer (timeout, network) or the
 *   call was refused before it was made (bad arguments).
 * - `code`: SMSTunnel's own `code` when its body has one (for example `PERMISSION_REQUIRED`), otherwise one of
 *   {@link SmsTunnelOtpErrorCode}.
 * - `retryable`: `true` for 429, 5xx, timeouts and network errors: trying again a little later may work.
 */
export class SmsTunnelOtpError extends Error {
  readonly status: number;
  readonly code: SmsTunnelOtpErrorCode;
  readonly retryable: boolean;
  /** With `PERMISSION_REQUIRED`: the permission the key lacks. */
  readonly permission?: string;
  /** SMSTunnel's error body, when there was one. */
  readonly body?: unknown;

  constructor(
    message: string,
    options: { status?: number; code: SmsTunnelOtpErrorCode; retryable?: boolean; body?: unknown; permission?: string; cause?: unknown },
  ) {
    super(message);
    this.name = 'SmsTunnelOtpError';
    this.status = options.status ?? 0;
    this.code = options.code;
    this.retryable = options.retryable ?? false;
    if (options.body !== undefined) this.body = options.body;
    if (options.permission) this.permission = options.permission;
    if (options.cause !== undefined) (this as { cause?: unknown }).cause = options.cause;
  }

  /** Builds the error for a non-2xx answer from SMSTunnel. */
  static fromResponse(status: number, body: unknown): SmsTunnelOtpError {
    const fields = body && typeof body === 'object' && !Array.isArray(body) ? (body as Record<string, unknown>) : {};
    const own = typeof fields.code === 'string' && fields.code ? fields.code : undefined;
    const code = own ?? STATUS_CODES[status] ?? (status >= 500 ? 'SERVER_ERROR' : 'HTTP_ERROR');
    return new SmsTunnelOtpError(`SMSTunnel: ${errorMessageOf(body, status)}`, {
      status,
      code,
      retryable: status === 429 || status >= 500,
      body,
      ...(typeof fields.permission === 'string' ? { permission: fields.permission } : {}),
    });
  }
}

/** The words of an SMSTunnel error body, whatever its shape (same rules as `@narcisbodea/smstunnel-sdk`). */
export function errorMessageOf(body: unknown, status: number): string {
  if (typeof body === 'string' && body.trim()) return body.trim().slice(0, 300);
  const fields = (body && typeof body === 'object' ? body : {}) as { message?: unknown; error?: unknown };
  const message = Array.isArray(fields.message) ? fields.message.join('; ') : fields.message;
  if (typeof message === 'string' && message) return message;
  if (typeof fields.error === 'string' && fields.error) return fields.error;
  return `request failed with status ${status}`;
}

/** Why a webhook request was refused before anything was sent. */
export type WebhookVerificationErrorCode =
  | 'INVALID_SECRET'
  | 'MISSING_HEADERS'
  | 'INVALID_TIMESTAMP'
  | 'TIMESTAMP_TOO_OLD'
  | 'TIMESTAMP_TOO_NEW'
  | 'NO_MATCHING_SIGNATURE'
  | 'WEBCRYPTO_UNAVAILABLE';

/** Thrown by {@link verifyWebhook} when a request is not signed with your secret. Nothing is sent. */
export class WebhookVerificationError extends Error {
  readonly code: WebhookVerificationErrorCode;

  constructor(message: string, code: WebhookVerificationErrorCode) {
    super(message);
    this.name = 'WebhookVerificationError';
    this.code = code;
  }
}
