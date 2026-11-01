// Ory courier HTTP channel → SMSTunnel POST /api/v1/sms/send-2fa.
// `ctx.body` is the text Ory rendered from its SMS template (login_code, verification_code, recovery_code),
// so it already contains the code.
function(ctx) {
  to: ctx.recipient,
  message: ctx.body,
}
