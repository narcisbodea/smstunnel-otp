// Node 18 has no global `crypto` by default: the signature check must fall back to node:crypto's webcrypto.
import { test } from 'node:test';
import assert from 'node:assert/strict';

Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true, writable: true });

test('signature check works without globalThis.crypto (Node 18)', async () => {
  assert.equal(globalThis.crypto, undefined);
  const { signWebhook, verifyWebhook } = await import('../dist/index.mjs');
  const vector = { secret: 'whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw', id: 'msg_p5jXN8AQM9LWM0D4loKWxJek', timestamp: 1614265330, body: '{"test": 2432232314}' };
  const signature = await signWebhook(vector);
  assert.equal(signature, 'v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=');
  const headers = { 'webhook-id': vector.id, 'webhook-timestamp': String(vector.timestamp), 'webhook-signature': signature };
  await verifyWebhook({ secret: vector.secret, headers, body: vector.body, now: vector.timestamp });
});
