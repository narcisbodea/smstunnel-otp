// Ory check, step 3 (see make-config.mjs): Kratos v26 code login → courier HTTP channel → local SMSTunnel send-2fa → MongoDB.
import { createRequire } from 'node:module';
const PUBLIC = 'http://127.0.0.1:14433', ADMIN = 'http://127.0.0.1:14434';
const phone = `+1415555${String(Math.floor(Math.random() * 10000)).padStart(4, '0')}`;
const started = new Date(Date.now() - 1000);
const j = async (res) => ({ status: res.status, body: await res.json().catch(() => null) });

const ident = await j(await fetch(`${ADMIN}/admin/identities`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ schema_id: 'default', traits: { phone } }) }));
console.log('identity', ident.status, ident.body?.id);
const flow = await j(await fetch(`${PUBLIC}/self-service/login/api`));
console.log('login flow', flow.status, flow.body?.id);
const submit = await j(await fetch(`${PUBLIC}/self-service/login?flow=${flow.body.id}`, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ method: 'code', identifier: phone }) }));
console.log('submit identifier', submit.status, submit.body?.state, (submit.body?.ui?.messages || []).map((m) => m.text).join(' | '));

let courierMsg;
for (let i = 0; i < 40; i++) {
  const list = await j(await fetch(`${ADMIN}/admin/courier/messages?recipient=${encodeURIComponent(phone)}`));
  courierMsg = Array.isArray(list.body) ? list.body[0] : undefined;
  if (courierMsg && ['sent', 'abandoned'].includes(courierMsg.status)) break;
  await new Promise((r) => setTimeout(r, 500));
}
console.log('courier message', courierMsg?.type, courierMsg?.template_type, courierMsg?.status, 'send_count', courierMsg?.send_count);

const { MongoClient } = createRequire(`${process.env.SMSTUNNEL_SERVER_DIR ?? 'D:/ANDROID/SMSserver'}/package.json`)('mongodb');
const client = new MongoClient(process.env.SMSTUNNEL_LOCAL_MONGO ?? 'mongodb://127.0.0.1:27018/smstunnel_app_dev', { serverSelectionTimeoutMS: 5000 });
await client.connect();
let doc;
for (let i = 0; i < 40; i++) {
  doc = await client.db().collection('messages').findOne({ phoneNumber: phone, createdAt: { $gte: started } });
  if (doc?.status === 'sent') break;
  await new Promise((r) => setTimeout(r, 300));
}
await client.close();
const code = doc?.message?.match(/\b\d{6}\b/)?.[0];
console.log('mongo', doc?._id, doc?.status, JSON.stringify(doc?.message?.replace(code, '<code>')));
const ok = courierMsg?.status === 'sent' && doc?.status === 'sent' && Boolean(code) && courierMsg.body === doc.message;
console.log(ok ? 'OK: Kratos login code went out through SMSTunnel send-2fa; text identical to the courier body' : 'FAIL');
process.exit(ok ? 0 : 1);
