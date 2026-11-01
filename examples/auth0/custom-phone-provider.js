/**
 * Auth0 Action, trigger `custom-phone-provider` (Branding → Phone Provider → Custom).
 * Codes for MFA, passwordless SMS and phone sign-up go out from your own phone and number through SMSTunnel.
 *
 * Dependency: @narcisbodea/smstunnel-otp
 * Secret:     SMSTUNNEL_API_KEY  (optional: SMSTUNNEL_DEVICE_ID)
 * Delivery method: Text (SMSTunnel does not place voice calls).
 */
const { createAuth0CustomPhoneProvider } = require('@narcisbodea/smstunnel-otp');

const sendWithSmsTunnel = createAuth0CustomPhoneProvider();

/**
 * @param {Event} event - Details about the phone notification.
 * @param {CustomPhoneProviderAPI} api - Methods to report a failed delivery.
 */
exports.onExecuteCustomPhoneProvider = async (event, api) => {
  await sendWithSmsTunnel(event, api);
};
