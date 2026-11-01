// Ory check, step 1: builds test/ory/kratos.yml (git-ignored: it holds the local key) from the repo's
// examples/ory/kratos.courier.yml, pointed at the LOCAL SMSTunnel API.
//
//   SMSTUNNEL_LOCAL_KEY_FILE=… node test/ory/make-config.mjs
//   docker compose -f test/ory/compose.yml up -d --pull missing
//   node test/ory/run-ory-e2e.mjs
//   docker compose -f test/ory/compose.yml down -v
import { readFileSync, writeFileSync } from 'node:fs';
const keyFile = process.env.SMSTUNNEL_LOCAL_KEY_FILE ?? process.argv[2];
const courierFile = new URL('../../examples/ory/kratos.courier.yml', import.meta.url);
if (!keyFile) throw new Error('Set SMSTUNNEL_LOCAL_KEY_FILE');
const local = JSON.parse(readFileSync(keyFile, 'utf8'));
if (!/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(local.serverUrl)) throw new Error('local servers only');
const port = new URL(local.serverUrl).port;
let courier = readFileSync(courierFile, 'utf8')
  .replace('https://smstunnel.io/api/v1/sms/send-2fa', `http://host.docker.internal:${port}/api/v1/sms/send-2fa`)
  .replace('YOUR_SMSTUNNEL_API_KEY', local.apiKey)
  .split('\n').filter((l) => !l.startsWith('#')).join('\n')
  .replace('courier:\n', 'courier:\n  smtp:\n    connection_uri: smtp://unused:unused@127.0.0.1:1025/\n');
const base = `dsn: memory
serve:
  public:
    base_url: http://127.0.0.1:14433/
  admin:
    base_url: http://127.0.0.1:14434/
selfservice:
  default_browser_return_url: http://127.0.0.1:4455/
  allowed_return_urls: ["http://127.0.0.1:4455"]
  methods:
    password:
      enabled: false
    code:
      enabled: true
      passwordless_enabled: true
  flows:
    error: { ui_url: "http://127.0.0.1:4455/error" }
    login: { ui_url: "http://127.0.0.1:4455/login" }
    registration: { ui_url: "http://127.0.0.1:4455/registration" }
    settings: { ui_url: "http://127.0.0.1:4455/settings" }
    verification: { enabled: false }
    recovery: { enabled: false }
identity:
  default_schema_id: default
  schemas:
    - id: default
      url: file:///etc/config/kratos/identity.schema.json
secrets:
  cookie: ["smst-int-otp-cookie-secret-local-only"]
  cipher: ["32-LONG-SECRET-NOT-SECURE-AT-ALL"]
log:
  level: info
  leak_sensitive_values: false
`;
writeFileSync(new URL('./kratos.yml', import.meta.url), base + courier);
console.log('kratos.yml written');
