// The records the activity page signs. Pure functions, no DOM and no network. Python twins:
// countersign.trusted_surface.activity.read_record and revoke_record. Each has its own purpose string,
// so a signature made for one (or for a consent, or a registration) can never serve as another.
import { jcs } from "./device-key.js";

export const PURPOSE_READ = "countersign.activity.read.v1";
export const PURPOSE_REVOKE = "countersign.open-mandate.revoke.v1";
export const CHALLENGE_PURPOSE_READ = "activity_read";
export const CHALLENGE_PURPOSE_REVOKE = "revoke_open_mandate";

const base = ({ challenge, customerId, deviceThumbprint, origin }) => ({
  v: 1,
  challenge_id: challenge.challenge_id,
  challenge: challenge.nonce,
  customer_id: customerId,
  device_thumbprint: deviceThumbprint,
  origin,
});

export const readRecord = (ctx) => ({ ...base(ctx), purpose: PURPOSE_READ });

export const revokeRecord = (ctx, openMandate) => ({
  ...base(ctx),
  purpose: PURPOSE_REVOKE,
  open_mandate: openMandate,
});

export const recordBytes = (record) => new TextEncoder().encode(jcs(record));
