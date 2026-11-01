// Runs examples/supabase/functions/send-sms/index.ts in Deno (as Supabase Edge Functions do), against a LOCAL
// SMSTunnel API, then sends it a correctly signed hook request and a wrongly signed one.
//
//   npm run build
//   DENO_BIN=/path/to/deno node test/deno/supabase-example.e2e.mjs
//
// Uses the same local key file and MongoDB as test/e2e.local.test.mjs. Deno listens on its default port 8000.
import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { signWebhook } from '../../dist/index.mjs';

const DENO = process.env.DENO_BIN ?? 'deno';
const KEY_FILE = process.env.SMSTUNNEL_LOCAL_KEY_FILE ?? '';
const MONGO_URL = process.env.SMSTUNNEL_LOCAL_MONGO ?? 'mongodb://127.0.0.1:27018/smstunnel_app_dev';
const SERVER_DIR = process.env.SMSTUNNEL_SERVER_DIR ?? 'D:/ANDROID/SMSserver';
const PORT = 8000;

if (!KEY_FILE || !existsSync(KEY_FILE)) {
  console.log('skipped: set SMSTUNNEL_LOCAL_KEY_FILE to a local key file');
  process.exit(0);
}
const local = JSON.parse(readFileSync(KEY_FILE, 'utf8'));
if (!/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(local.serverUrl)) throw new Error('local servers only');

const root = fileURLToPath(new URL('../../', import.meta.url));
const secret = `v1,whsec_${btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))}`;
const deno = spawn(
  DENO,
  ['run', '--no-config', '--import-map', 'test/deno/import_map.local.json', '--allow-net', '--allow-env', 'examples/supabase/functions/send-sms/index.ts'],
  {
    cwd: root,
    env: {
      ...process.env,
      SMSTUNNEL_API_KEY: local.apiKey,
      SEND_SMS_HOOK_SECRETS: secret,
      SMSTUNNEL_SERVER_URL: local.serverUrl,
      SMSTUNNEL_TEMPLATE: 'Your SMSTunnel OTP e2e (Supabase in Deno) code is {code}',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  },
);
let output = '';
deno.stdout.on('data', (d) => (output += d));
deno.stderr.on('data', (d) => (output += d));

let failed = false;
const check = (ok, label) => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}`);
  if (!ok) failed = true;
};

try {
  const url = `http://127.0.0.1:${PORT}/`;
  const deadline = Date.now() + 30_000;
  for (;;) {
    const up = await fetch(url, { method: 'GET' }).then(() => true, () => false);
    if (up) break;
    if (Date.now() > deadline || deno.exitCode !== null) throw new Error(`Deno did not start:\n${output}`);
    await new Promise((r) => setTimeout(r, 300));
  }
  check(/Listening on/i.test(output), `Deno started the example (${output.trim().split('\n')[0]})`);

  const code = String(100000 + Math.floor(Math.random() * 900000));
  const to = `+1415555${String(Math.floor(Math.random() * 10000)).padStart(4, '0')}`;
  const send = async (payload, signingSecret) => {
    const body = JSON.stringify(payload);
    const id = `msg_${crypto.randomUUID()}`;
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = await signWebhook({ secret: signingSecret, id, timestamp, body });
    return fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', 'webhook-id': id, 'webhook-timestamp': String(timestamp), 'webhook-signature': signature }, body });
  };

  const res = await send({ user: { id: 'u1', phone: to.slice(1) }, sms: { otp: code } }, secret);
  const text = await res.text();
  check(res.status === 200 && text === '{}' && res.headers.get('content-type') === 'application/json', `signed request → ${res.status} ${text}`);

  const badCode = String(100000 + Math.floor(Math.random() * 900000));
  const bad = await send({ user: { phone: to.slice(1) }, sms: { otp: badCode } }, `whsec_${btoa('y'.repeat(32))}`);
  const badBody = await bad.json();
  check(bad.status === 401 && badBody.error?.http_code === 401, `wrongly signed request → ${bad.status} ${JSON.stringify(badBody)}`);

  const { MongoClient } = createRequire(`${SERVER_DIR}/package.json`)('mongodb');
  const client = new MongoClient(MONGO_URL, { serverSelectionTimeoutMS: 5000 });
  await client.connect();
  try {
    const messages = client.db().collection('messages');
    let doc;
    for (let i = 0; i < 40; i++) {
      doc = await messages.findOne({ phoneNumber: to, message: { $regex: code } });
      if (doc?.status === 'sent') break;
      await new Promise((r) => setTimeout(r, 300));
    }
    check(Boolean(doc) && doc.status === 'sent', `MongoDB: ${doc?._id} to ${to} status=${doc?.status} text="${doc?.message?.replace(code, '<code>')}"`);
    const leaked = await messages.findOne({ message: { $regex: badCode } });
    check(leaked === null, 'MongoDB: nothing from the wrongly signed request');
  } finally {
    await client.close();
  }
} catch (err) {
  check(false, err.message);
} finally {
  deno.kill();
}
process.exit(failed ? 1 : 0);
