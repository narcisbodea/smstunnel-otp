/**
 * Auth0 Action, trigger `custom-phone-provider`, WITHOUT any npm dependency: the same thing in a few lines.
 * Secret: SMSTUNNEL_API_KEY. Delivery method: Text.
 */
exports.onExecuteCustomPhoneProvider = async (event, api) => {
  const n = event.notification;
  if (n.delivery_method === 'voice') {
    api.notification.drop('SMSTunnel sends text messages only; set the delivery method to Text.');
    return;
  }
  // Codes (otp_verify, otp_enroll) count against the 2FA allowance; notices without a code are regular texts.
  const path = n.code ? '/api/v1/sms/send-2fa' : '/api/v1/sms/send';
  let message = n.as_text || `Your verification code is ${n.code}`;
  if (n.code && !message.includes(n.code)) message += ` ${n.code}`;
  try {
    const res = await fetch(`https://smstunnel.io${path}`, {
      method: 'POST',
      headers: { 'X-API-Key': event.secrets.SMSTUNNEL_API_KEY, 'Content-Type': 'application/json' },
      body: JSON.stringify({ to: n.recipient, message }),
    });
    if (res.status === 429 || res.status >= 500) api.notification.retry(`SMSTunnel answered ${res.status}`);
    else if (!res.ok) api.notification.drop(`SMSTunnel answered ${res.status}: ${(await res.text()).slice(0, 300)}`);
  } catch (err) {
    api.notification.retry(`SMSTunnel unreachable: ${err.message}`);
  }
};
