/**
 * Auth0 Action, trigger `send-phone-message` (Security → Multi-factor Auth → Phone Message → Custom, when
 * "Use Tenant-Level Messaging Provider" is off). MFA codes go out from your own phone and number through SMSTunnel.
 *
 * Dependency: @narcisbodea/smstunnel-otp
 * Secret:     SMSTUNNEL_API_KEY  (optional: SMSTUNNEL_DEVICE_ID)
 * Delivery method: SMS (SMSTunnel does not place voice calls).
 */
const { createAuth0SendPhoneMessage } = require('@narcisbodea/smstunnel-otp');

const sendWithSmsTunnel = createAuth0SendPhoneMessage();

/**
 * @param {Event} event - Details about the user and the message.
 * @param {SendPhoneMessageAPI} api
 */
exports.onExecuteSendPhoneMessage = async (event, api) => {
  await sendWithSmsTunnel(event, api);
};
