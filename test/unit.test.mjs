// Unit tests: run with `npm test` (builds first). They use the ESM build, so they also check that it imports in plain Node.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  sendCode,
  sendText,
  buildCodeMessage,
  containsCode,
  SmsTunnelOtpError,
  WebhookVerificationError,
  verifyWebhook,
  signWebhook,
  parseWebhookSecrets,
  timingSafeEqual,
  createSupabaseSendSmsHook,
  parseSupabaseSendSmsPayload,
  supabasePhone,
  createClerkSmsWebhook,
  planClerkSmsEvent,
  createAuth0CustomPhoneProvider,
  createAuth0SendPhoneMessage,
  smstunnelSendOTP,
  MAX_CODE_TEXT_LENGTH,
} from '../dist/index.mjs';
import { mockFetch, okBody, randomSecretB64, nowSeconds } from './helpers.mjs';

const SERVER = 'http://smstunnel.test';
const KEY = 'sk_test_unit';

// ─── Standard Webhooks signatures ────────────────────────────────────────────

describe('verifyWebhook / signWebhook', () => {
  // Fixed vector from the Standard Webhooks reference test suite (libraries/python/tests/test_webhooks.py,
  // test_sign_function): same secret, id, timestamp and payload as the JavaScript library tests.
  const VECTOR = {
    secret: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw',
    id: 'msg_p5jXN8AQM9LWM0D4loKWxJek',
    timestamp: 1614265330,
    body: '{"test": 2432232314}',
    signature: 'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=',
  };

  test('reproduces the Standard Webhooks test vector', async () => {
    assert.equal(await signWebhook(VECTOR), VECTOR.signature);
  });

  test('accepts the test vector (whsec_, v1,whsec_ and bare base64 secrets)', async () => {
    const headers = { 'webhook-id': VECTOR.id, 'webhook-timestamp': String(VECTOR.timestamp), 'webhook-signature': VECTOR.signature };
    for (const secret of [VECTOR.secret, `v1,${VECTOR.secret}`, 'MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw']) {
      const out = await verifyWebhook({ secret, headers, body: VECTOR.body, now: VECTOR.timestamp + 10 });
      assert.deepEqual(out, { id: VECTOR.id, timestamp: VECTOR.timestamp });
    }
  });

  test('a one-bit change in the vector signature is refused', async () => {
    const headers = {
      'webhook-id': VECTOR.id,
      'webhook-timestamp': String(VECTOR.timestamp),
      'webhook-signature': 'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OA=',
    };
    await assert.rejects(verifyWebhook({ secret: VECTOR.secret, headers, body: VECTOR.body, now: VECTOR.timestamp }), {
      name: 'WebhookVerificationError',
      code: 'NO_MATCHING_SIGNATURE',
    });
  });

  async function signed(secret, body, { id = 'msg_1', timestamp = nowSeconds(), prefix = 'webhook' } = {}) {
    const signature = await signWebhook({ secret, id, timestamp, body });
    return { [`${prefix}-id`]: id, [`${prefix}-timestamp`]: String(timestamp), [`${prefix}-signature`]: signature };
  }

  test('valid signature with Fetch Headers, plain objects and svix-* names', async () => {
    const secret = `v1,whsec_${randomSecretB64()}`;
    const body = '{"hello":"world"}';
    await verifyWebhook({ secret, headers: new Headers(await signed(secret, body)), body });
    const upper = Object.fromEntries(Object.entries(await signed(secret, body)).map(([k, v]) => [k.toUpperCase(), v]));
    await verifyWebhook({ secret, headers: upper, body });
    await verifyWebhook({ secret, headers: await signed(secret, body, { prefix: 'svix' }), body });
  });

  test('raw bytes bodies (Uint8Array, ArrayBuffer, Buffer) verify like the string', async () => {
    const secret = `whsec_${randomSecretB64()}`;
    const body = '{"emoji":"✓ ă î ș"}';
    const headers = await signed(secret, body);
    const bytes = new TextEncoder().encode(body);
    await verifyWebhook({ secret, headers, body: bytes });
    await verifyWebhook({ secret, headers, body: bytes.buffer });
    await verifyWebhook({ secret, headers, body: Buffer.from(body) });
  });

  test('wrong secret is refused', async () => {
    const body = '{}';
    const headers = await signed(`whsec_${randomSecretB64()}`, body);
    await assert.rejects(verifyWebhook({ secret: `whsec_${randomSecretB64()}`, headers, body }), { code: 'NO_MATCHING_SIGNATURE' });
  });

  test('tampered body is refused', async () => {
    const secret = `whsec_${randomSecretB64()}`;
    const headers = await signed(secret, '{"sms":{"otp":"123456"}}');
    await assert.rejects(verifyWebhook({ secret, headers, body: '{"sms":{"otp":"654321"}}' }), { code: 'NO_MATCHING_SIGNATURE' });
  });

  test('tampered id or timestamp is refused', async () => {
    const secret = `whsec_${randomSecretB64()}`;
    const body = '{}';
    const headers = await signed(secret, body);
    await assert.rejects(verifyWebhook({ secret, headers: { ...headers, 'webhook-id': 'msg_other' }, body }), { code: 'NO_MATCHING_SIGNATURE' });
    const ts = String(Number(headers['webhook-timestamp']) - 1);
    await assert.rejects(verifyWebhook({ secret, headers: { ...headers, 'webhook-timestamp': ts }, body }), { code: 'NO_MATCHING_SIGNATURE' });
  });

  test('old, future and malformed timestamps are refused (default tolerance 5 minutes)', async () => {
    const secret = `whsec_${randomSecretB64()}`;
    const body = '{}';
    const old = await signed(secret, body, { timestamp: nowSeconds() - 301 });
    await assert.rejects(verifyWebhook({ secret, headers: old, body }), { code: 'TIMESTAMP_TOO_OLD' });
    const future = await signed(secret, body, { timestamp: nowSeconds() + 301 });
    await assert.rejects(verifyWebhook({ secret, headers: future, body }), { code: 'TIMESTAMP_TOO_NEW' });
    const ok = await signed(secret, body, { timestamp: nowSeconds() - 290 });
    await verifyWebhook({ secret, headers: ok, body });
    await assert.rejects(verifyWebhook({ secret, headers: old, body, toleranceSeconds: 60 }), { code: 'TIMESTAMP_TOO_OLD' });
    await assert.rejects(verifyWebhook({ secret, headers: { ...ok, 'webhook-timestamp': '12a' }, body }), { code: 'INVALID_TIMESTAMP' });
  });

  test('several signatures in one header: any v1 match is enough; v1a and other versions are ignored', async () => {
    const secret = `whsec_${randomSecretB64()}`;
    const body = '{"a":1}';
    const headers = await signed(secret, body);
    const good = headers['webhook-signature'];
    const b64 = good.slice(3);
    headers['webhook-signature'] = `v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc= v1a,${b64} ${good}`;
    await verifyWebhook({ secret, headers, body });
    headers['webhook-signature'] = `v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc= v1a,${b64} v2,${b64}`;
    await assert.rejects(verifyWebhook({ secret, headers, body }), { code: 'NO_MATCHING_SIGNATURE' });
  });

  test('secret rotation: several secrets (list, or "|" / "," separated like SEND_SMS_HOOK_SECRETS)', async () => {
    const oldS = randomSecretB64();
    const newS = randomSecretB64();
    const body = '{}';
    const headers = await signed(`whsec_${newS}`, body);
    await verifyWebhook({ secret: [`whsec_${oldS}`, `whsec_${newS}`], headers, body });
    await verifyWebhook({ secret: `v1,whsec_${oldS}|v1,whsec_${newS}`, headers, body });
    await verifyWebhook({ secret: `v1,whsec_${oldS},v1,whsec_${newS}`, headers, body });
    assert.equal(parseWebhookSecrets(`v1,whsec_${oldS}|v1,whsec_${newS}`).length, 2);
  });

  test('missing headers and bad secrets', async () => {
    const secret = `whsec_${randomSecretB64()}`;
    const headers = await signed(secret, '{}');
    delete headers['webhook-signature'];
    await assert.rejects(verifyWebhook({ secret, headers, body: '{}' }), { code: 'MISSING_HEADERS' });
    // A misconfigured secret must fail loudly, never become a short (guessable) key.
    for (const bad of ['', '   ', 'whsec_', 'v1,whsec_', 'not base64 !!', 'my secret', 'whsec_c2hvcnQ=', `whsec_${randomSecretB64()},garbage`, `v1,whsec_${randomSecretB64()}|whsec_`]) {
      assert.throws(() => parseWebhookSecrets(bad), { code: 'INVALID_SECRET' }, JSON.stringify(bad));
    }
    assert.throws(() => parseWebhookSecrets(undefined), WebhookVerificationError);
    assert.throws(() => parseWebhookSecrets([]), WebhookVerificationError);
  });

  test('timingSafeEqual', () => {
    assert.equal(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])), true);
    assert.equal(timingSafeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])), false);
    assert.equal(timingSafeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])), false);
  });
});

// ─── Text of the code ────────────────────────────────────────────────────────

describe('buildCodeMessage: the text always contains the code', () => {
  test('default template', () => {
    assert.equal(buildCodeMessage('123456'), 'Your verification code is 123456');
  });
  test('{code} and {{ code }} placeholders, repeated', () => {
    assert.equal(buildCodeMessage('4321', { template: 'Acme: {code}. Code {{ code }} expires in 5 min.' }), 'Acme: 4321. Code 4321 expires in 5 min.');
  });
  test('template without a placeholder: the code is appended', () => {
    assert.equal(buildCodeMessage('987654', { template: 'Your Acme sign-in code:' }), 'Your Acme sign-in code: 987654');
  });
  test('message wins over template; a message without the code gets it appended', () => {
    assert.equal(buildCodeMessage('111222', { message: '111222 is your code', template: 'x {code}' }), '111222 is your code');
    assert.equal(buildCodeMessage('111222', { message: 'Your code is' }), 'Your code is 111222');
  });
  test('the code must be a word of its own, not part of a longer number', () => {
    assert.equal(containsCode('Order 12345678 shipped', '1234'), false);
    assert.equal(containsCode('Code: 1234.', '1234'), true);
    assert.equal(buildCodeMessage('1234', { message: 'Order 12345678' }), 'Order 12345678 1234');
  });
  test('numbers are accepted as codes; empty codes are refused', () => {
    assert.equal(buildCodeMessage(246810), 'Your verification code is 246810');
    assert.throws(() => buildCodeMessage(''), { name: 'SmsTunnelOtpError', code: 'INVALID_ARGUMENT', status: 0 });
    assert.throws(() => buildCodeMessage('   '), { code: 'INVALID_ARGUMENT' });
  });
  test('texts over 320 characters are refused before any call', () => {
    assert.throws(() => buildCodeMessage('123456', { template: 'x'.repeat(MAX_CODE_TEXT_LENGTH) + ' {code}' }), { code: 'MESSAGE_TOO_LONG' });
  });
});

// ─── sendCode / sendText and error mapping ───────────────────────────────────

describe('sendCode', () => {
  test('POSTs to /api/v1/sms/send-2fa with X-API-Key and the code in the text', async () => {
    const fetch = mockFetch({ status: 200, body: okBody('m1') });
    const out = await sendCode({ apiKey: KEY, serverUrl: `${SERVER}/`, to: ' +14155550123 ', code: '123456', deviceId: 'dev1', defaultCountryCode: '1', fetch });
    assert.deepEqual(out, { success: true, messageId: 'm1', queued: false, branded: false, remaining: { clean: 99, total: 'unlimited' } });
    const [call] = fetch.calls;
    assert.equal(call.url, `${SERVER}/api/v1/sms/send-2fa`);
    assert.equal(call.init.method, 'POST');
    assert.equal(call.headers['X-API-Key'], KEY);
    assert.equal(call.headers['Content-Type'], 'application/json');
    assert.deepEqual(call.body, { to: '+14155550123', message: 'Your verification code is 123456', deviceId: 'dev1', defaultCountryCode: '1' });
  });

  test('optional fields are left out; default server is https://smstunnel.io', async () => {
    const fetch = mockFetch();
    await sendCode({ apiKey: KEY, to: '+14155550123', code: '123456', fetch });
    assert.equal(fetch.calls[0].url, 'https://smstunnel.io/api/v1/sms/send-2fa');
    assert.deepEqual(Object.keys(fetch.calls[0].body), ['to', 'message']);
  });

  test('queued answer (phone offline)', async () => {
    const fetch = mockFetch({ status: 200, body: okBody('m2', { queued: true }) });
    const out = await sendCode({ apiKey: KEY, to: '+14155550123', code: '123456', fetch });
    assert.equal(out.queued, true);
  });

  test('missing apiKey / to are refused without a call', async () => {
    const fetch = mockFetch();
    await assert.rejects(sendCode({ apiKey: '', to: '+14155550123', code: '1', fetch }), { code: 'INVALID_ARGUMENT' });
    await assert.rejects(sendCode({ apiKey: KEY, to: '', code: '123456', fetch }), { code: 'INVALID_ARGUMENT' });
    assert.equal(fetch.calls.length, 0);
  });

  const cases = [
    [401, { message: 'Invalid or expired API key', error: 'Unauthorized', statusCode: 401 }, 'UNAUTHORIZED', false, 'SMSTunnel: Invalid or expired API key'],
    [403, { message: 'This API key needs sms:send', error: 'Forbidden', statusCode: 403, code: 'PERMISSION_REQUIRED', permission: 'sms:send' }, 'PERMISSION_REQUIRED', false, 'SMSTunnel: This API key needs sms:send'],
    [400, { message: ['to must be a phone number', 'message too long'], error: 'Bad Request', statusCode: 400 }, 'BAD_REQUEST', false, 'SMSTunnel: to must be a phone number; message too long'],
    [404, { message: 'Device not found', statusCode: 404 }, 'NOT_FOUND', false, 'SMSTunnel: Device not found'],
    [429, { message: 'ThrottlerException: Too Many Requests', statusCode: 429 }, 'RATE_LIMITED', true, 'SMSTunnel: ThrottlerException: Too Many Requests'],
    [500, { message: 'Internal server error', statusCode: 500 }, 'SERVER_ERROR', true, 'SMSTunnel: Internal server error'],
    [502, '<html>Proxy error</html>', 'SERVER_ERROR', true, 'SMSTunnel: <html>Proxy error</html>'],
    [418, {}, 'HTTP_ERROR', false, 'SMSTunnel: request failed with status 418'],
  ];
  for (const [status, body, code, retryable, message] of cases) {
    test(`HTTP ${status} → ${code}`, async () => {
      const fetch = mockFetch({ status, body });
      const err = await sendCode({ apiKey: KEY, to: '+14155550123', code: '123456', fetch }).catch((e) => e);
      assert.ok(err instanceof SmsTunnelOtpError);
      assert.ok(err instanceof Error);
      assert.equal(err.status, status);
      assert.equal(err.code, code);
      assert.equal(err.retryable, retryable);
      assert.equal(err.message, message);
      assert.deepEqual(err.body, body);
      if (code === 'PERMISSION_REQUIRED') assert.equal(err.permission, 'sms:send');
    });
  }

  test('2xx that is not JSON → INVALID_RESPONSE', async () => {
    const fetch = mockFetch({ status: 200, body: 'ok' });
    await assert.rejects(sendCode({ apiKey: KEY, to: '+14155550123', code: '123456', fetch }), { code: 'INVALID_RESPONSE', status: 200 });
  });

  test('network error → NETWORK_ERROR (retryable)', async () => {
    const fetch = mockFetch(new TypeError('fetch failed'));
    await assert.rejects(sendCode({ apiKey: KEY, to: '+14155550123', code: '123456', fetch }), {
      code: 'NETWORK_ERROR',
      status: 0,
      retryable: true,
    });
  });

  test('timeout → TIMEOUT (retryable)', async () => {
    const hang = (_call, init) =>
      new Promise((_resolve, reject) => init.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError'))));
    const fetch = mockFetch(hang);
    const started = Date.now();
    await assert.rejects(sendCode({ apiKey: KEY, to: '+14155550123', code: '123456', timeoutMs: 50, fetch }), {
      code: 'TIMEOUT',
      retryable: true,
    });
    assert.ok(Date.now() - started < 2000);
  });

  test('sendText uses /api/v1/sms/send', async () => {
    const fetch = mockFetch();
    await sendText({ apiKey: KEY, serverUrl: SERVER, to: '+14155550123', message: 'Your password was changed.', fetch });
    assert.equal(fetch.calls[0].url, `${SERVER}/api/v1/sms/send`);
    assert.deepEqual(fetch.calls[0].body, { to: '+14155550123', message: 'Your password was changed.' });
  });
});

// ─── Supabase Send SMS hook ──────────────────────────────────────────────────

// The example payload from https://supabase.com/docs/guides/auth/auth-hooks/send-sms-hook (identities trimmed).
const SUPABASE_DOC_PAYLOAD = {
  user: {
    id: '6481a5c1-3d37-4a56-9f6a-bee08c554965',
    aud: 'authenticated',
    role: 'authenticated',
    email: '',
    phone: '+1333363128',
    app_metadata: { provider: 'phone', providers: ['phone'] },
    user_metadata: {},
    identities: [],
    is_anonymous: false,
  },
  sms: { otp: '561166' },
};

describe('Supabase Send SMS hook', () => {
  const secretB64 = randomSecretB64();
  const hookSecret = `v1,whsec_${secretB64}`;

  async function supabaseRequest(payload, { secret = hookSecret, id = `msg_${Math.random().toString(36).slice(2)}`, timestamp = nowSeconds(), method = 'POST' } = {}) {
    const body = JSON.stringify(payload);
    const signature = await signWebhook({ secret, id, timestamp, body });
    return new Request('https://example.supabase.co/functions/v1/send-sms', {
      method,
      headers: { 'content-type': 'application/json', 'webhook-id': id, 'webhook-timestamp': String(timestamp), 'webhook-signature': signature },
      body: method === 'POST' ? body : undefined,
    });
  }

  test('payload parsing: doc example, sms.phone first, + added to digits-only numbers', () => {
    assert.equal(parseSupabaseSendSmsPayload(JSON.stringify(SUPABASE_DOC_PAYLOAD)).to, '+1333363128');
    const changed = parseSupabaseSendSmsPayload(JSON.stringify({ user: { phone: '14155550100' }, sms: { otp: '123456', phone: '14155550199', sms_type: 'mfa' } }));
    assert.equal(changed.to, '+14155550199');
    assert.equal(changed.sms.otp, '123456');
    assert.equal(parseSupabaseSendSmsPayload(JSON.stringify({ user: { phone: '14155550100' }, sms: { otp: '123456' } })).to, '+14155550100');
    assert.equal(parseSupabaseSendSmsPayload(JSON.stringify({ user: { phone: '' }, sms: { otp: '123456' } })), undefined);
    assert.equal(parseSupabaseSendSmsPayload(JSON.stringify({ user: { phone: '+1415' }, sms: {} })), undefined);
    assert.equal(parseSupabaseSendSmsPayload('not json'), undefined);
    assert.equal(supabasePhone('+40712345678'), '+40712345678');
    assert.equal(supabasePhone('40712345678'), '+40712345678');
  });

  test('valid request: sends the code and answers 200 {} (application/json)', async () => {
    const fetch = mockFetch();
    const hook = createSupabaseSendSmsHook({ apiKey: KEY, hookSecret, serverUrl: SERVER, template: 'Acme code: {code}', fetch });
    const res = await hook(await supabaseRequest(SUPABASE_DOC_PAYLOAD));
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'application/json');
    assert.deepEqual(await res.json(), {});
    assert.equal(fetch.calls.length, 1);
    assert.equal(fetch.calls[0].url, `${SERVER}/api/v1/sms/send-2fa`);
    assert.deepEqual(fetch.calls[0].body, { to: '+1333363128', message: 'Acme code: 561166' });
  });

  test('wrong signature: 401 in Supabase error shape, nothing sent', async () => {
    const fetch = mockFetch();
    const hook = createSupabaseSendSmsHook({ apiKey: KEY, hookSecret, serverUrl: SERVER, fetch });
    const res = await hook(await supabaseRequest(SUPABASE_DOC_PAYLOAD, { secret: `v1,whsec_${randomSecretB64()}` }));
    assert.equal(res.status, 401);
    assert.equal(res.headers.get('content-type'), 'application/json');
    const body = await res.json();
    assert.equal(body.error.http_code, 401);
    assert.match(body.error.message, /signature/i);
    assert.equal(fetch.calls.length, 0);
  });

  test('replayed old request is refused', async () => {
    const fetch = mockFetch();
    const hook = createSupabaseSendSmsHook({ apiKey: KEY, hookSecret, serverUrl: SERVER, fetch });
    const res = await hook(await supabaseRequest(SUPABASE_DOC_PAYLOAD, { timestamp: nowSeconds() - 3600 }));
    assert.equal(res.status, 401);
    assert.equal(fetch.calls.length, 0);
  });

  test('a retry with the same webhook-id after success does not send twice', async () => {
    const fetch = mockFetch();
    const hook = createSupabaseSendSmsHook({ apiKey: KEY, hookSecret, serverUrl: SERVER, fetch });
    const first = await supabaseRequest(SUPABASE_DOC_PAYLOAD, { id: 'msg_same' });
    const again = await supabaseRequest(SUPABASE_DOC_PAYLOAD, { id: 'msg_same' });
    assert.equal((await hook(first)).status, 200);
    assert.equal((await hook(again)).status, 200);
    assert.equal(fetch.calls.length, 1);
  });

  test('non-POST → 405; payload without otp → 400', async () => {
    const fetch = mockFetch();
    const hook = createSupabaseSendSmsHook({ apiKey: KEY, hookSecret, serverUrl: SERVER, fetch });
    const get = await hook(new Request('https://x.test/', { method: 'GET' }));
    assert.equal(get.status, 405);
    assert.equal((await get.json()).error.http_code, 405);
    const bad = await hook(await supabaseRequest({ user: { phone: '+14155550123' }, sms: {} }));
    assert.equal(bad.status, 400);
    assert.equal((await bad.json()).error.http_code, 400);
    assert.equal(fetch.calls.length, 0);
  });

  const failures = [
    [429, 429, true],
    [500, 503, true],
    [401, 500, false],
    [403, 500, false],
    [400, 400, false],
  ];
  for (const [upstream, expected, retryAfter] of failures) {
    test(`SMSTunnel ${upstream} → hook answers ${expected}${retryAfter ? ' with retry-after' : ''}`, async () => {
      const fetch = mockFetch({ status: upstream, body: { message: 'nope', statusCode: upstream } });
      const hook = createSupabaseSendSmsHook({ apiKey: KEY, hookSecret, serverUrl: SERVER, fetch });
      const res = await hook(await supabaseRequest(SUPABASE_DOC_PAYLOAD));
      assert.equal(res.status, expected);
      assert.equal(res.headers.get('content-type'), 'application/json');
      assert.equal(Boolean(res.headers.get('retry-after')), retryAfter);
      const body = await res.json();
      assert.equal(body.error.http_code, expected);
      assert.match(body.error.message, /^Failed to send SMS: SMSTunnel: nope$/);
    });
  }

  test('timeout default is 4 s (inside Supabase’s 5 s budget) and maps to 503', async () => {
    const hang = (_call, init) => new Promise((_r, reject) => init.signal.addEventListener('abort', () => reject(new Error('aborted'))));
    const hook = createSupabaseSendSmsHook({ apiKey: KEY, hookSecret, serverUrl: SERVER, fetch: mockFetch(hang), timeoutMs: 30 });
    const res = await hook(await supabaseRequest(SUPABASE_DOC_PAYLOAD));
    assert.equal(res.status, 503);
    assert.match((await res.json()).error.message, /did not answer within 30 ms/);
  });

  test('process() works with Node-style headers and a Buffer body (Express)', async () => {
    const fetch = mockFetch();
    const hook = createSupabaseSendSmsHook({ apiKey: KEY, hookSecret, serverUrl: SERVER, fetch });
    const req = await supabaseRequest(SUPABASE_DOC_PAYLOAD);
    const headers = Object.fromEntries(req.headers);
    const out = await hook.process({ method: 'POST', headers, body: Buffer.from(await req.text()) });
    assert.equal(out.status, 200);
    assert.equal(out.body, '{}');
    assert.equal(fetch.calls.length, 1);
  });

  test('bad configuration fails at start-up', () => {
    assert.throws(() => createSupabaseSendSmsHook({ apiKey: '', hookSecret }), { code: 'INVALID_ARGUMENT' });
    assert.throws(() => createSupabaseSendSmsHook({ apiKey: KEY, hookSecret: undefined }), { code: 'INVALID_SECRET' });
  });
});

// ─── Clerk sms.created webhook ───────────────────────────────────────────────

// The example from Clerk's webhooks OpenAPI spec (clerk/openapi-specs webhooks/2025-04-15.yml, sms.created).
function clerkEvent(overrides = {}, dataOverrides = {}) {
  return {
    event_attributes: { http_request: { client_ip: '192.168.1.100', user_agent: 'Mozilla/5.0' } },
    object: 'event',
    type: 'sms.created',
    instance_id: 'ins_2g7np7Hrk0SN6kj5EDMLDaKNL0S',
    timestamp: 1716883200,
    data: {
      object: 'sms_message',
      id: 'sms_2g7np7Hrk0SN6kj5EDMLDaKNL0S',
      slug: 'verification_code',
      from_phone_number: '+12345678901',
      to_phone_number: '+19876543210',
      phone_number_id: 'idn_2g7np7Hrk0SN6kj5EDMLDaKNL0S',
      user_id: 'user_2g7np7Hrk0SN6kj5EDMLDaKNL0S',
      message: 'Your verification code is 123456',
      status: 'queued',
      data: { otp_code: '123456', app: { name: 'Acme' } },
      delivered_by_clerk: false,
      created_at: 1716883200000,
      ...dataOverrides,
    },
    ...overrides,
  };
}

describe('Clerk sms.created webhook', () => {
  const signingSecret = `whsec_${randomSecretB64(24)}`;

  async function clerkRequest(event, { secret = signingSecret, id = `msg_${Math.random().toString(36).slice(2)}`, timestamp = nowSeconds() } = {}) {
    const body = JSON.stringify(event);
    const signature = await signWebhook({ secret, id, timestamp, body });
    return new Request('https://app.example.com/api/webhooks/clerk-sms', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'svix-id': id, 'svix-timestamp': String(timestamp), 'svix-signature': signature },
      body,
    });
  }

  test('planClerkSmsEvent', () => {
    assert.deepEqual(planClerkSmsEvent(clerkEvent()), { action: 'send-code', to: '+19876543210', code: '123456', message: 'Your verification code is 123456' });
    assert.equal(planClerkSmsEvent(clerkEvent({}, { delivered_by_clerk: true })).action, 'skip');
    assert.equal(planClerkSmsEvent(clerkEvent({ type: 'user.created' })).action, 'skip');
    assert.deepEqual(planClerkSmsEvent(clerkEvent({}, { data: {}, slug: 'password_changed', message: 'Your password was changed' })), {
      action: 'send-text',
      to: '+19876543210',
      message: 'Your password was changed',
    });
    assert.equal(planClerkSmsEvent(clerkEvent({}, { data: null }), 'skip').action, 'skip');
    assert.equal(planClerkSmsEvent(clerkEvent({}, { to_phone_number: '' })).action, 'skip');
  });

  test('signed sms.created: sends Clerk’s rendered text through send-2fa', async () => {
    const fetch = mockFetch({ status: 200, body: okBody('clerk1') });
    const handler = createClerkSmsWebhook({ apiKey: KEY, signingSecret, serverUrl: SERVER, fetch });
    const res = await handler(await clerkRequest(clerkEvent()));
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { ok: true, messageId: 'clerk1', queued: false });
    assert.equal(fetch.calls[0].url, `${SERVER}/api/v1/sms/send-2fa`);
    assert.deepEqual(fetch.calls[0].body, { to: '+19876543210', message: 'Your verification code is 123456' });
  });

  test('template override, and a template that lost the code still carries it', async () => {
    const fetch = mockFetch();
    const handler = createClerkSmsWebhook({ apiKey: KEY, signingSecret, serverUrl: SERVER, fetch, template: '{code} is your Acme code' });
    await handler(await clerkRequest(clerkEvent()));
    assert.equal(fetch.calls[0].body.message, '123456 is your Acme code');
    const plain = createClerkSmsWebhook({ apiKey: KEY, signingSecret, serverUrl: SERVER, fetch });
    await plain(await clerkRequest(clerkEvent({}, { message: 'Your Acme code is below' })));
    assert.equal(fetch.calls[1].body.message, 'Your Acme code is below 123456');
  });

  test('wrong signature → 400, nothing sent', async () => {
    const fetch = mockFetch();
    const handler = createClerkSmsWebhook({ apiKey: KEY, signingSecret, serverUrl: SERVER, fetch });
    const res = await handler(await clerkRequest(clerkEvent(), { secret: `whsec_${randomSecretB64(24)}` }));
    assert.equal(res.status, 400);
    assert.match((await res.json()).error, /verification failed/i);
    assert.equal(fetch.calls.length, 0);
  });

  test('delivered_by_clerk: true and other event types → 200 skipped, nothing sent', async () => {
    const fetch = mockFetch();
    const handler = createClerkSmsWebhook({ apiKey: KEY, signingSecret, serverUrl: SERVER, fetch });
    const a = await handler(await clerkRequest(clerkEvent({}, { delivered_by_clerk: true })));
    const b = await handler(await clerkRequest(clerkEvent({ type: 'email.created' })));
    assert.equal(a.status, 200);
    assert.match((await a.json()).skipped, /Delivered by Clerk/);
    assert.equal(b.status, 200);
    assert.equal(fetch.calls.length, 0);
  });

  test('texts without a code: sent through /sms/send by default, skipped with nonCodeMessages: "skip"', async () => {
    const fetch = mockFetch();
    const send = createClerkSmsWebhook({ apiKey: KEY, signingSecret, serverUrl: SERVER, fetch });
    const skip = createClerkSmsWebhook({ apiKey: KEY, signingSecret, serverUrl: SERVER, fetch, nonCodeMessages: 'skip' });
    const notice = clerkEvent({}, { data: {}, slug: 'password_changed', message: 'Your Acme password was changed.' });
    assert.equal((await send(await clerkRequest(notice))).status, 200);
    assert.equal((await skip(await clerkRequest(notice))).status, 200);
    assert.equal(fetch.calls.length, 1);
    assert.equal(fetch.calls[0].url, `${SERVER}/api/v1/sms/send`);
  });

  test('SMSTunnel errors: retryable → 503, refused number → 400, bad key → 500 (Clerk retries non-2xx)', async () => {
    for (const [upstream, expected] of [[503, 503], [400, 400], [401, 500]]) {
      const fetch = mockFetch({ status: upstream, body: { message: 'x', statusCode: upstream } });
      const handler = createClerkSmsWebhook({ apiKey: KEY, signingSecret, serverUrl: SERVER, fetch });
      const res = await handler(await clerkRequest(clerkEvent()));
      assert.equal(res.status, expected, `upstream ${upstream}`);
    }
  });

  test('duplicate svix-id after success → not sent twice', async () => {
    const fetch = mockFetch();
    const handler = createClerkSmsWebhook({ apiKey: KEY, signingSecret, serverUrl: SERVER, fetch });
    await handler(await clerkRequest(clerkEvent(), { id: 'msg_dup' }));
    const again = await handler(await clerkRequest(clerkEvent(), { id: 'msg_dup' }));
    assert.equal(again.status, 200);
    assert.equal(fetch.calls.length, 1);
  });
});

// ─── Auth0 Actions ───────────────────────────────────────────────────────────

function auth0Api() {
  const calls = [];
  return {
    calls,
    notification: {
      drop: (reason) => calls.push(['drop', reason]),
      retry: (reason) => calls.push(['retry', reason]),
    },
  };
}

function customPhoneEvent(notification = {}, secrets = { SMSTUNNEL_API_KEY: KEY, SMSTUNNEL_SERVER_URL: SERVER }) {
  return {
    client: { client_id: 'abc', name: 'Acme' },
    notification: {
      as_text: 'Your Acme verification code is: 482913',
      as_voice: 'Your Acme verification code is 4, 8, 2, 9, 1, 3',
      code: '482913',
      delivery_method: 'text',
      from: '+15005550006',
      locale: 'en_US',
      message_type: 'otp_verify',
      recipient: '+14155550123',
      ...notification,
    },
    secrets,
    tenant: { id: 'acme' },
    user: {},
  };
}

describe('Auth0 custom-phone-provider', () => {
  test('otp_verify: sends Auth0’s rendered text through send-2fa, settings from event.secrets', async () => {
    const fetch = mockFetch();
    const api = auth0Api();
    const handler = createAuth0CustomPhoneProvider({ fetch });
    await handler(customPhoneEvent({}, { SMSTUNNEL_API_KEY: KEY, SMSTUNNEL_SERVER_URL: SERVER, SMSTUNNEL_DEVICE_ID: 'dev9' }), api);
    assert.deepEqual(api.calls, []);
    assert.equal(fetch.calls[0].url, `${SERVER}/api/v1/sms/send-2fa`);
    assert.equal(fetch.calls[0].headers['X-API-Key'], KEY);
    assert.deepEqual(fetch.calls[0].body, { to: '+14155550123', message: 'Your Acme verification code is: 482913', deviceId: 'dev9' });
  });

  test('options win over secrets; template override; missing code in as_text gets appended', async () => {
    const fetch = mockFetch();
    await createAuth0CustomPhoneProvider({ fetch, apiKey: 'sk_opt', serverUrl: 'http://other.test', template: 'Acme {code}' })(customPhoneEvent(), auth0Api());
    assert.equal(fetch.calls[0].url, 'http://other.test/api/v1/sms/send-2fa');
    assert.equal(fetch.calls[0].headers['X-API-Key'], 'sk_opt');
    assert.equal(fetch.calls[0].body.message, 'Acme 482913');
    await createAuth0CustomPhoneProvider({ fetch })(customPhoneEvent({ message_type: 'otp_enroll', as_text: 'Your Acme enrollment code:' }), auth0Api());
    assert.equal(fetch.calls[1].body.message, 'Your Acme enrollment code: 482913');
  });

  test('voice: dropped with a clear reason, nothing sent; without api it throws', async () => {
    const fetch = mockFetch();
    const api = auth0Api();
    const handler = createAuth0CustomPhoneProvider({ fetch });
    await handler(customPhoneEvent({ delivery_method: 'voice' }), api);
    assert.equal(api.calls.length, 1);
    assert.equal(api.calls[0][0], 'drop');
    assert.match(api.calls[0][1], /text messages only.*voice/i);
    await assert.rejects(handler(customPhoneEvent({ delivery_method: 'voice' })), { name: 'SmsTunnelOtpError', code: 'UNSUPPORTED_DELIVERY_METHOD' });
    assert.equal(fetch.calls.length, 0);
  });

  test('notices without a code (change_password): /sms/send by default, skipped with nonCodeMessages: "skip"', async () => {
    const fetch = mockFetch();
    const notice = customPhoneEvent({ message_type: 'change_password', code: undefined, as_text: 'Your Acme password was changed.' });
    await createAuth0CustomPhoneProvider({ fetch })(notice, auth0Api());
    await createAuth0CustomPhoneProvider({ fetch, nonCodeMessages: 'skip' })(notice, auth0Api());
    assert.equal(fetch.calls.length, 1);
    assert.equal(fetch.calls[0].url, `${SERVER}/api/v1/sms/send`);
    assert.deepEqual(fetch.calls[0].body, { to: '+14155550123', message: 'Your Acme password was changed.' });
  });

  test('SMSTunnel 429 / timeout → api.notification.retry; 401 → drop; missing key → drop', async () => {
    const cases = [
      [{ status: 429, body: { message: 'Too Many Requests' } }, 'retry'],
      [{ status: 503, body: { message: 'Unavailable' } }, 'retry'],
      [{ status: 401, body: { message: 'Invalid or expired API key' } }, 'drop'],
    ];
    for (const [answer, expected] of cases) {
      const api = auth0Api();
      await createAuth0CustomPhoneProvider({ fetch: mockFetch(answer) })(customPhoneEvent(), api);
      assert.equal(api.calls[0][0], expected, `status ${answer.status}`);
      assert.match(api.calls[0][1], /^SMSTunnel: /);
      assert.ok(!api.calls[0][1].startsWith('SMSTunnel: SMSTunnel'));
    }
    const api = auth0Api();
    await createAuth0CustomPhoneProvider({ fetch: mockFetch() })(customPhoneEvent({}, {}), api);
    assert.deepEqual(api.calls[0][0], 'drop');
    assert.match(api.calls[0][1], /SMSTUNNEL_API_KEY/);
  });
});

describe('Auth0 send-phone-message', () => {
  const event = (o = {}) => ({
    message_options: { action: 'second-factor-authentication', code: '730154', message_type: 'sms', recipient: '+14155550123', text: '730154 is your Acme verification code', ...o },
    secrets: { SMSTUNNEL_API_KEY: KEY, SMSTUNNEL_SERVER_URL: SERVER },
  });

  test('sms: sends message_options.text through send-2fa', async () => {
    const fetch = mockFetch();
    await createAuth0SendPhoneMessage({ fetch })(event(), {});
    assert.equal(fetch.calls[0].url, `${SERVER}/api/v1/sms/send-2fa`);
    assert.deepEqual(fetch.calls[0].body, { to: '+14155550123', message: '730154 is your Acme verification code' });
  });

  test('voice → throws UNSUPPORTED_DELIVERY_METHOD with a clear message, nothing sent', async () => {
    const fetch = mockFetch();
    await assert.rejects(createAuth0SendPhoneMessage({ fetch })(event({ message_type: 'voice' })), (err) => {
      assert.equal(err.code, 'UNSUPPORTED_DELIVERY_METHOD');
      assert.match(err.message, /text messages only/);
      return true;
    });
    assert.equal(fetch.calls.length, 0);
  });

  test('SMSTunnel error → throws SmsTunnelOtpError', async () => {
    const fetch = mockFetch({ status: 401, body: { message: 'Invalid or expired API key', statusCode: 401 } });
    await assert.rejects(createAuth0SendPhoneMessage({ fetch })(event()), { name: 'SmsTunnelOtpError', status: 401, code: 'UNAUTHORIZED' });
  });
});

// ─── Better Auth ─────────────────────────────────────────────────────────────

describe('Better Auth sendOTP', () => {
  test('({ phoneNumber, code }, ctx) → send-2fa with the template', async () => {
    const fetch = mockFetch();
    const sendOTP = smstunnelSendOTP({ apiKey: KEY, serverUrl: SERVER, fetch });
    const out = await sendOTP({ phoneNumber: '+14155550123', code: '135790' }, { request: undefined });
    assert.equal(out, undefined);
    assert.equal(fetch.calls[0].url, `${SERVER}/api/v1/sms/send-2fa`);
    assert.deepEqual(fetch.calls[0].body, { to: '+14155550123', message: 'Your verification code is 135790' });
    const reset = smstunnelSendOTP({ apiKey: KEY, serverUrl: SERVER, fetch, template: 'Acme password reset code: {code}', defaultCountryCode: '40' });
    await reset({ phoneNumber: '0712345678', code: '864200' });
    assert.deepEqual(fetch.calls[1].body, { to: '0712345678', message: 'Acme password reset code: 864200', defaultCountryCode: '40' });
  });

  test('rejects with SmsTunnelOtpError on failure', async () => {
    const fetch = mockFetch({ status: 403, body: { message: 'Forbidden', code: 'PERMISSION_REQUIRED', permission: 'sms:send' } });
    await assert.rejects(smstunnelSendOTP({ apiKey: KEY, serverUrl: SERVER, fetch })({ phoneNumber: '+14155550123', code: '135790' }), {
      code: 'PERMISSION_REQUIRED',
      status: 403,
    });
  });
});
