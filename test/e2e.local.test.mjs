// End to end against a local SMSTunnel API (never production). Run: `npm run build && npm run test:e2e`.
//
// Needs:
// - SMSTUNNEL_LOCAL_KEY_FILE: JSON file with { serverUrl, apiKey } for a local API with an online (simulated) phone;
// - SMSTUNNEL_LOCAL_MONGO (default mongodb://127.0.0.1:27018/smstunnel_app_dev): the API's database, read only;
// - SMSTUNNEL_SERVER_DIR (default D:/ANDROID/SMSserver): where the `mongodb` driver is installed.
//
// Each adapter runs exactly as on its platform (signed Supabase and Clerk requests, Auth0 events, Better Auth call);
// then the test reads MongoDB to check that each text was accepted by the API, contains its code and was sent, and
// that every request went to /api/v1/sms/send-2fa. Wrongly signed requests must leave no trace.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { runInNewContext } from 'node:vm';
import {
  createSupabaseSendSmsHook,
  createClerkSmsWebhook,
  createAuth0CustomPhoneProvider,
  createAuth0SendPhoneMessage,
  smstunnelSendOTP,
  signWebhook,
  containsCode,
} from '../dist/index.mjs';

const KEY_FILE = process.env.SMSTUNNEL_LOCAL_KEY_FILE ?? '';
const MONGO_URL = process.env.SMSTUNNEL_LOCAL_MONGO ?? 'mongodb://127.0.0.1:27018/smstunnel_app_dev';
const SERVER_DIR = process.env.SMSTUNNEL_SERVER_DIR ?? 'D:/ANDROID/SMSserver';

const haveKey = Boolean(KEY_FILE) && existsSync(KEY_FILE);
const local = haveKey ? JSON.parse(readFileSync(KEY_FILE, 'utf8')) : {};
const skip = haveKey ? false : 'set SMSTUNNEL_LOCAL_KEY_FILE to a local key file';

if (haveKey && !/^http:\/\/(127\.0\.0\.1|localhost|host\.docker\.internal)(:\d+)?$/.test(local.serverUrl)) {
  throw new Error(`Refusing to run end-to-end tests against ${local.serverUrl}: local servers only.`);
}

/** Real fetch that records every path, so we can check the endpoint the adapters used. */
const paths = [];
const recordingFetch = (url, init) => {
  paths.push(`${init.method} ${new URL(url).pathname}`);
  return fetch(url, init);
};

const started = new Date(Date.now() - 1000);
const used = new Set();
const randomCode = () => {
  for (;;) {
    const c = String(100000 + Math.floor(Math.random() * 900000));
    if (!used.has(c)) return used.add(c), c;
  }
};
const randomRecipient = () => `+1415555${String(Math.floor(Math.random() * 10000)).padStart(4, '0')}`;

let client;
let db;
let userId;
let twoFaBefore;
/** What each test sent: checked against MongoDB at the end. */
const expected = [];
/** Codes of the refused (wrongly signed) requests: must not appear in MongoDB. */
const refusedCodes = [];

before(async () => {
  if (skip) return;
  const res = await fetch(`${local.serverUrl}/api/v1/devices`, { headers: { 'X-API-Key': local.apiKey } }).catch((e) => e);
  if (res instanceof Error || !res.ok) {
    throw new Error(`The local SMSTunnel API at ${local.serverUrl} is not answering (${res instanceof Error ? res.message : res.status})`);
  }
  const devices = await res.json();
  const list = [devices, devices?.data, devices?.devices, devices?.data?.devices].find(Array.isArray) ?? [];
  assert.ok(list.some((d) => d.isOnline), 'the simulated phone is not online');

  const { MongoClient, ObjectId } = createRequire(`${SERVER_DIR}/package.json`)('mongodb');
  client = new MongoClient(MONGO_URL, { serverSelectionTimeoutMS: 5000 });
  await client.connect();
  db = client.db();
  const ids = local.deviceId ? [local.deviceId, ...(ObjectId.isValid(local.deviceId) ? [new ObjectId(local.deviceId)] : [])] : [];
  const anyMsg = ids.length ? await db.collection('messages').findOne({ deviceId: { $in: ids } }, { sort: { _id: -1 } }) : null;
  userId = typeof anyMsg?.userId === 'string' && ObjectId.isValid(anyMsg.userId) ? new ObjectId(anyMsg.userId) : anyMsg?.userId;
  if (userId) {
    const user = await db.collection('users').findOne({ _id: userId }, { projection: { usage: 1 } });
    twoFaBefore = user?.usage?.twoFaClean;
  }
});

after(async () => {
  await client?.close();
});

const conn = () => ({ apiKey: local.apiKey, serverUrl: local.serverUrl, fetch: recordingFetch });

test('Supabase Send SMS hook: signed request → 200 {} and the code goes out', { skip }, async () => {
  const hookSecret = `v1,whsec_${btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))}`;
  const hook = createSupabaseSendSmsHook({ ...conn(), hookSecret, template: 'Your SMSTunnel OTP e2e (Supabase) code is {code}' });
  const code = randomCode();
  const to = randomRecipient();
  // Supabase stores numbers without the "+": the hook must add it.
  const body = JSON.stringify({ user: { id: 'u1', phone: to.slice(1), aud: 'authenticated', role: 'authenticated' }, sms: { otp: code } });
  const id = `msg_${crypto.randomUUID()}`;
  const timestamp = Math.floor(Date.now() / 1000);
  const res = await hook(
    new Request('http://localhost/functions/v1/send-sms', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'webhook-id': id, 'webhook-timestamp': String(timestamp), 'webhook-signature': await signWebhook({ secret: hookSecret, id, timestamp, body }) },
      body,
    }),
  );
  assert.equal(res.status, 200, await res.clone().text());
  assert.deepEqual(await res.json(), {});
  expected.push({ adapter: 'supabase', to, code });

  // Same request body, signed with another secret: refused, nothing sent.
  const badCode = randomCode();
  const badBody = JSON.stringify({ user: { phone: to.slice(1) }, sms: { otp: badCode } });
  const bad = await hook(
    new Request('http://localhost/functions/v1/send-sms', {
      method: 'POST',
      headers: {
        'webhook-id': `msg_${crypto.randomUUID()}`,
        'webhook-timestamp': String(timestamp),
        'webhook-signature': await signWebhook({ secret: `whsec_${btoa('x'.repeat(32))}`, id: 'msg_other', timestamp, body: badBody }),
      },
      body: badBody,
    }),
  );
  assert.equal(bad.status, 401);
  refusedCodes.push(badCode);
});

test('Clerk sms.created webhook: Svix-signed request → the code goes out', { skip }, async () => {
  const signingSecret = `whsec_${btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(24))))}`;
  const handler = createClerkSmsWebhook({ ...conn(), signingSecret });
  const code = randomCode();
  const to = randomRecipient();
  const event = {
    object: 'event',
    type: 'sms.created',
    instance_id: 'ins_e2e',
    timestamp: Date.now(),
    data: {
      object: 'sms_message',
      id: `sms_${crypto.randomUUID()}`,
      slug: 'verification_code',
      from_phone_number: '+12345678901',
      to_phone_number: to,
      message: `${code} is your SMSTunnel OTP e2e (Clerk) verification code.`,
      status: 'queued',
      data: { otp_code: code, app: { name: 'SMSTunnel OTP e2e' } },
      delivered_by_clerk: false,
    },
  };
  const body = JSON.stringify(event);
  const id = `msg_${crypto.randomUUID()}`;
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = await signWebhook({ secret: signingSecret, id, timestamp, body });
  const res = await handler(new Request('http://localhost/api/webhooks/clerk-sms', { method: 'POST', headers: { 'svix-id': id, 'svix-timestamp': String(timestamp), 'svix-signature': signature }, body }));
  assert.equal(res.status, 200, await res.clone().text());
  const out = await res.json();
  assert.equal(out.ok, true);
  assert.ok(out.messageId);
  expected.push({ adapter: 'clerk', to, code, messageId: out.messageId });

  // Tampered body (another code) with the original signature: refused, nothing sent.
  const badCode = randomCode();
  const tampered = body.replaceAll(code, badCode);
  const bad = await handler(new Request('http://localhost/api/webhooks/clerk-sms', { method: 'POST', headers: { 'svix-id': id, 'svix-timestamp': String(timestamp), 'svix-signature': signature }, body: tampered }));
  assert.equal(bad.status, 400);
  refusedCodes.push(badCode);
});

test('Auth0 custom-phone-provider: otp_verify → the code goes out, no drop/retry', { skip }, async () => {
  const onExecuteCustomPhoneProvider = createAuth0CustomPhoneProvider({ fetch: recordingFetch });
  const code = randomCode();
  const to = randomRecipient();
  const calls = [];
  await onExecuteCustomPhoneProvider(
    {
      notification: { message_type: 'otp_verify', delivery_method: 'text', recipient: to, code, as_text: `Your SMSTunnel OTP e2e (Auth0) verification code is: ${code}`, locale: 'en_US' },
      secrets: { SMSTUNNEL_API_KEY: local.apiKey, SMSTUNNEL_SERVER_URL: local.serverUrl },
    },
    { notification: { drop: (r) => calls.push(['drop', r]), retry: (r) => calls.push(['retry', r]) } },
  );
  assert.deepEqual(calls, []);
  expected.push({ adapter: 'auth0-custom-phone-provider', to, code });
});

test('Auth0 send-phone-message: MFA code goes out', { skip }, async () => {
  const onExecuteSendPhoneMessage = createAuth0SendPhoneMessage({ fetch: recordingFetch });
  const code = randomCode();
  const to = randomRecipient();
  await onExecuteSendPhoneMessage({
    message_options: { action: 'second-factor-authentication', message_type: 'sms', recipient: to, code, text: `${code} is your SMSTunnel OTP e2e (Auth0 MFA) code` },
    secrets: { SMSTUNNEL_API_KEY: local.apiKey, SMSTUNNEL_SERVER_URL: local.serverUrl },
  });
  expected.push({ adapter: 'auth0-send-phone-message', to, code });
});

test('Auth0 no-dependency example (examples/auth0/custom-phone-provider.no-dependency.js) works as pasted', { skip }, async () => {
  // Run the file as Auth0 would, with its production URL swapped for the local API.
  const source = readFileSync(new URL('../examples/auth0/custom-phone-provider.no-dependency.js', import.meta.url), 'utf8');
  assert.ok(source.includes('https://smstunnel.io'));
  const action = { exports: {} };
  runInNewContext(source.replaceAll('https://smstunnel.io', local.serverUrl), { exports: action.exports, fetch: recordingFetch, JSON, console });
  const code = randomCode();
  const to = randomRecipient();
  const calls = [];
  await action.exports.onExecuteCustomPhoneProvider(
    {
      notification: { message_type: 'otp_enroll', delivery_method: 'text', recipient: to, code, as_text: `Your SMSTunnel OTP e2e (Auth0 no-dependency) enrollment code is ${code}` },
      secrets: { SMSTUNNEL_API_KEY: local.apiKey },
    },
    { notification: { drop: (r) => calls.push(['drop', r]), retry: (r) => calls.push(['retry', r]) } },
  );
  assert.deepEqual(calls, []);
  expected.push({ adapter: 'auth0-no-dependency-example', to, code });
});

test('Better Auth sendOTP: the code goes out', { skip }, async () => {
  const sendOTP = smstunnelSendOTP({ ...conn(), template: 'Your SMSTunnel OTP e2e (Better Auth) code is {code}' });
  const code = randomCode();
  const to = randomRecipient();
  await sendOTP({ phoneNumber: to, code }, undefined);
  expected.push({ adapter: 'better-auth', to, code });
});

test('MongoDB: every code text landed through send-2fa, contains its code and was sent; refused requests left nothing', { skip }, async () => {
  assert.equal(expected.length, 6, 'all six senders ran');
  assert.ok(paths.length >= 6);
  assert.deepEqual([...new Set(paths)], ['POST /api/v1/sms/send-2fa'], `endpoints used: ${paths.join(', ')}`);

  const messages = db.collection('messages');
  const deadline = Date.now() + 20_000;
  for (const item of expected) {
    let doc;
    while (Date.now() < deadline) {
      doc = await messages.findOne({ phoneNumber: item.to, createdAt: { $gte: started }, message: { $regex: item.code } });
      if (doc?.status === 'sent') break;
      await new Promise((r) => setTimeout(r, 300));
    }
    assert.ok(doc, `${item.adapter}: no message for ${item.to} in MongoDB`);
    assert.ok(containsCode(doc.message, item.code), `${item.adapter}: stored text does not contain the code`);
    assert.equal(doc.type, 'outgoing');
    assert.equal(doc.status, 'sent', `${item.adapter}: status ${doc.status}`);
    if (item.messageId) assert.equal(String(doc._id), item.messageId);
    console.log(`  ✓ ${item.adapter}: ${doc._id} to ${item.to} status=${doc.status} text="${doc.message.replace(item.code, '<code>')}"`);
  }

  await new Promise((r) => setTimeout(r, 1500));
  for (const code of refusedCodes) {
    const leaked = await messages.findOne({ createdAt: { $gte: started }, message: { $regex: code } });
    assert.equal(leaked, null, `a wrongly signed request was sent (${code})`);
  }
  console.log(`  ✓ ${refusedCodes.length} wrongly signed requests: nothing in MongoDB`);

  if (userId && typeof twoFaBefore === 'number') {
    const user = await db.collection('users').findOne({ _id: userId }, { projection: { usage: 1 } });
    const delta = (user?.usage?.twoFaClean ?? 0) - twoFaBefore;
    // Other local tests may share this account, so this is a lower bound.
    assert.ok(delta >= expected.length, `2FA counter grew by ${delta}, expected at least ${expected.length}`);
    console.log(`  ✓ 2FA counter (usage.twoFaClean) grew by ${delta}`);
  }
});
