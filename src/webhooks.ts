/**
 * Standard Webhooks (https://www.standardwebhooks.com) signature check, used by Supabase Auth hooks and by Clerk
 * (which sends through Svix, the same scheme with `svix-*` header names). WebCrypto only.
 *
 * Signed content: `${webhook-id}.${webhook-timestamp}.${raw body}`, HMAC-SHA256 with the base64-decoded secret,
 * sent as `v1,<base64 signature>`; the header may carry several signatures separated by spaces.
 */
import { WebhookVerificationError } from './errors';

export const DEFAULT_TOLERANCE_SECONDS = 5 * 60;

/** Request headers: a Fetch `Headers`, or a plain object such as Node's `req.headers`. */
export type HeadersInput = Headers | Record<string, string | string[] | undefined>;

export interface VerifyWebhookOptions {
  /**
   * Your signing secret, in any of the forms the platforms show it: `v1,whsec_<base64>` (Supabase),
   * `whsec_<base64>` (Clerk / Svix) or the bare base64. Pass a list, or one string with several secrets separated
   * by `|`, `,` or spaces, while you rotate secrets: a request signed with any of them is accepted.
   */
  secret: string | string[];
  headers: HeadersInput;
  /** The raw request body, exactly as received (before any JSON parsing). */
  body: string | Uint8Array | ArrayBuffer;
  /** How far the `webhook-timestamp` may be from now, in seconds (default 300). */
  toleranceSeconds?: number;
  /** "Now" in seconds since the epoch. For tests. */
  now?: number;
}

export interface VerifiedWebhook {
  /** The `webhook-id` (or `svix-id`): the same for every retry of one event. */
  id: string;
  /** The `webhook-timestamp`, in seconds. */
  timestamp: number;
}

/**
 * Checks that a request was signed with your secret and is recent.
 *
 * @throws {WebhookVerificationError} when headers are missing, the timestamp is out of range, or no signature matches.
 */
export async function verifyWebhook(options: VerifyWebhookOptions): Promise<VerifiedWebhook> {
  const keys = parseWebhookSecrets(options.secret);

  const id = headerOf(options.headers, 'webhook-id') ?? headerOf(options.headers, 'svix-id');
  const stamp = headerOf(options.headers, 'webhook-timestamp') ?? headerOf(options.headers, 'svix-timestamp');
  const signatures = headerOf(options.headers, 'webhook-signature') ?? headerOf(options.headers, 'svix-signature');
  if (!id || !stamp || !signatures) {
    throw new WebhookVerificationError('Missing webhook-id, webhook-timestamp or webhook-signature header', 'MISSING_HEADERS');
  }

  if (!/^\d{1,12}$/.test(stamp)) {
    throw new WebhookVerificationError('Invalid webhook-timestamp header', 'INVALID_TIMESTAMP');
  }
  const timestamp = Number(stamp);
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const tolerance = options.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
  if (now - timestamp > tolerance) throw new WebhookVerificationError('Webhook timestamp too old', 'TIMESTAMP_TOO_OLD');
  if (timestamp - now > tolerance) throw new WebhookVerificationError('Webhook timestamp too new', 'TIMESTAMP_TOO_NEW');

  const candidates = signatures.split(/\s+/).filter((s) => s.startsWith('v1,'));
  if (candidates.length) {
    const encoder = new TextEncoder();
    const content = signedContent(id, timestamp, options.body);
    for (const key of keys) {
      const expected = encoder.encode(`v1,${encodeBase64(await hmacSha256(key, content))}`);
      let matched = false;
      // Compare against every candidate (no early exit), each in constant time.
      for (const candidate of candidates) {
        if (timingSafeEqual(encoder.encode(candidate), expected)) matched = true;
      }
      if (matched) return { id, timestamp };
    }
  }
  throw new WebhookVerificationError('No matching signature found', 'NO_MATCHING_SIGNATURE');
}

/**
 * Signs a body the way Supabase and Clerk do, returning the `webhook-signature` value (`v1,<base64>`). Handy for
 * testing your own endpoint.
 */
export async function signWebhook(options: {
  secret: string;
  id: string;
  /** Seconds since the epoch. */
  timestamp: number;
  body: string | Uint8Array | ArrayBuffer;
}): Promise<string> {
  const [key] = parseWebhookSecrets(options.secret);
  return `v1,${encodeBase64(await hmacSha256(key!, signedContent(options.id, options.timestamp, options.body)))}`;
}

/** Shorter keys are refused: they would be guessable. Supabase and Clerk generate 24 to 32 bytes. */
const MIN_SECRET_BYTES = 16;

/**
 * Decodes the signing key(s) from the forms Supabase, Clerk and Svix use. Anything that is not a well-formed secret
 * throws (`INVALID_SECRET`) instead of being skipped, so a misconfigured secret can never turn into a weak key.
 */
export function parseWebhookSecrets(secret: string | string[]): Uint8Array[] {
  const items = (Array.isArray(secret) ? secret : [secret]).filter((s): s is string => typeof s === 'string');
  const keys: Uint8Array[] = [];
  for (const item of items) {
    for (const token of item.split(/[|\s]+/)) {
      if (!token) continue;
      if (token.includes('whsec_')) {
        // `whsec_A`, `v1,whsec_A`, or a comma list `v1,whsec_A,v1,whsec_B`.
        for (const part of token.split(',')) {
          if (!part || part === 'v1') continue;
          if (!part.startsWith('whsec_')) throw badSecret();
          keys.push(decodeSecret(part.slice('whsec_'.length)));
        }
      } else {
        keys.push(decodeSecret(token.replace(/^v1,/, '')));
      }
    }
  }
  if (!keys.length) {
    throw new WebhookVerificationError('The webhook secret is empty', 'INVALID_SECRET');
  }
  return keys;
}

function badSecret(): WebhookVerificationError {
  return new WebhookVerificationError(
    'The webhook secret is not valid (expected v1,whsec_<base64> from Supabase or whsec_<base64> from Clerk)',
    'INVALID_SECRET',
  );
}

function decodeSecret(b64: string): Uint8Array {
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(b64)) throw badSecret();
  let bytes: Uint8Array;
  try {
    bytes = decodeBase64(b64);
  } catch {
    throw badSecret();
  }
  if (bytes.length < MIN_SECRET_BYTES) {
    throw new WebhookVerificationError(`The webhook secret is too short (${bytes.length} bytes, at least ${MIN_SECRET_BYTES})`, 'INVALID_SECRET');
  }
  return bytes;
}

/** Reads one header from `Headers` or a plain object, case-insensitively. Several values are joined with a space. */
export function headerOf(headers: HeadersInput, name: string): string | undefined {
  if (!headers) return undefined;
  if (typeof (headers as Headers).get === 'function') {
    const value = (headers as Headers).get(name);
    return value?.trim() || undefined;
  }
  const record = headers as Record<string, string | string[] | undefined>;
  for (const key of Object.keys(record)) {
    if (key.toLowerCase() !== name) continue;
    const value = record[key];
    const joined = Array.isArray(value) ? value.join(' ') : value;
    if (typeof joined === 'string' && joined.trim()) return joined.trim();
  }
  return undefined;
}

function signedContent(id: string, timestamp: number, body: string | Uint8Array | ArrayBuffer): Uint8Array {
  const prefix = new TextEncoder().encode(`${id}.${timestamp}.`);
  const payload =
    typeof body === 'string'
      ? new TextEncoder().encode(body)
      : body instanceof ArrayBuffer
        ? new Uint8Array(body)
        : new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
  const out = new Uint8Array(prefix.length + payload.length);
  out.set(prefix);
  out.set(payload, prefix.length);
  return out;
}

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const subtle = await getSubtle();
  const cryptoKey = await subtle.importKey('raw', copy(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await subtle.sign('HMAC', cryptoKey, copy(data)));
}

/** A fresh `ArrayBuffer`-backed copy, which every WebCrypto implementation (and TypeScript) accepts. */
function copy(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(bytes.length));
  out.set(bytes);
  return out;
}

let subtlePromise: Promise<SubtleCrypto> | undefined;

function getSubtle(): Promise<SubtleCrypto> {
  subtlePromise ??= (async () => {
    const global = (globalThis as { crypto?: Crypto }).crypto;
    if (global?.subtle) return global.subtle;
    // Node 18 only exposes WebCrypto as `require('node:crypto').webcrypto`. The specifier is in a variable so that
    // bundlers for Workers / browsers leave it alone; those runtimes have `globalThis.crypto` and never get here.
    try {
      const specifier = 'node:crypto';
      const mod = (await import(/* @vite-ignore */ /* webpackIgnore: true */ specifier)) as { webcrypto?: Crypto };
      if (mod.webcrypto?.subtle) return mod.webcrypto.subtle;
    } catch {
      // fall through
    }
    subtlePromise = undefined;
    throw new WebhookVerificationError('WebCrypto (crypto.subtle) is not available in this runtime', 'WEBCRYPTO_UNAVAILABLE');
  })();
  return subtlePromise;
}

/** Constant-time comparison: the time depends only on the length, never on where the bytes differ. */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function decodeBase64(b64: string): Uint8Array {
  const normalized = b64.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(normalized);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]!);
  return btoa(binary);
}

/**
 * Remembers the ids of events already handled, so a retry of an event that did go out doesn't send the code twice.
 * Per process: on serverless platforms it only catches retries that reach the same instance.
 */
export class RecentWebhookIds {
  private readonly seen = new Map<string, number>();

  constructor(
    private readonly maxEntries = 1000,
    private readonly ttlMs = 2 * DEFAULT_TOLERANCE_SECONDS * 1000,
  ) {}

  has(id: string): boolean {
    const at = this.seen.get(id);
    if (at === undefined) return false;
    if (Date.now() - at > this.ttlMs) {
      this.seen.delete(id);
      return false;
    }
    return true;
  }

  add(id: string): void {
    this.seen.delete(id);
    this.seen.set(id, Date.now());
    while (this.seen.size > this.maxEntries) {
      const oldest = this.seen.keys().next().value;
      if (oldest === undefined) break;
      this.seen.delete(oldest);
    }
  }
}
