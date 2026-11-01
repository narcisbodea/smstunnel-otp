// The CommonJS build, the way an Auth0 Action loads it: `require('@narcisbodea/smstunnel-otp')`.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const otp = require('../dist/index.js');

test('CJS build exports the same API as the ESM build', async () => {
  const esm = await import('../dist/index.mjs');
  assert.deepEqual(Object.keys(otp).sort(), Object.keys(esm).sort());
});

test('CJS: Auth0 custom-phone-provider handler sends through send-2fa', async () => {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, body: JSON.parse(init.body) });
    return new Response(JSON.stringify({ success: true, messageId: 'm', data: { messageId: 'm' } }), { status: 200 });
  };
  const onExecuteCustomPhoneProvider = otp.createAuth0CustomPhoneProvider({ fetch });
  const dropped = [];
  await onExecuteCustomPhoneProvider(
    {
      notification: { message_type: 'otp_verify', delivery_method: 'text', recipient: '+14155550123', as_text: 'Code 102938', code: '102938' },
      secrets: { SMSTUNNEL_API_KEY: 'sk_cjs', SMSTUNNEL_SERVER_URL: 'http://cjs.test' },
    },
    { notification: { drop: (r) => dropped.push(r), retry: (r) => dropped.push(r) } },
  );
  assert.deepEqual(dropped, []);
  assert.equal(calls[0].url, 'http://cjs.test/api/v1/sms/send-2fa');
  assert.deepEqual(calls[0].body, { to: '+14155550123', message: 'Code 102938' });
});

test('CJS: signature check works (WebCrypto from globalThis or node:crypto)', async () => {
  const sig = await otp.signWebhook({ secret: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw', id: 'msg_p5jXN8AQM9LWM0D4loKWxJek', timestamp: 1614265330, body: '{"test": 2432232314}' });
  assert.equal(sig, 'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=');
});
