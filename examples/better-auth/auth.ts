// Better Auth with the phoneNumber plugin: codes go out from your own phone and number through SMSTunnel.
import { betterAuth } from 'better-auth';
import { phoneNumber } from 'better-auth/plugins';
import { smstunnelSendOTP } from '@narcisbodea/smstunnel-otp';

const apiKey = process.env.SMSTUNNEL_API_KEY!;

export const auth = betterAuth({
  // ...your database and other options
  plugins: [
    phoneNumber({
      sendOTP: smstunnelSendOTP({ apiKey, template: 'Your Acme code is {code}' }),
      sendPasswordResetOTP: smstunnelSendOTP({ apiKey, template: 'Your Acme password reset code is {code}' }),
    }),
  ],
});
