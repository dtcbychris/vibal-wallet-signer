import type { VercelRequest, VercelResponse } from "@vercel/node";

/**
 * GET /api/wallet/health
 *
 * Reports whether all required env vars are present.
 * Never returns the values themselves.
 */
export const config = { runtime: "nodejs" };

const REQUIRED = [
  "WALLET_SIGNING_SERVICE_TOKEN",
  "APPLE_PASS_CERTIFICATE",
  "APPLE_PASS_PRIVATE_KEY",
  "APPLE_PASS_PRIVATE_KEY_PASSPHRASE",
  "APPLE_WWDR_CERTIFICATE",
];

export default function handler(_req: VercelRequest, res: VercelResponse) {
  const status: Record<string, boolean> = {};
  let ok = true;
  for (const name of REQUIRED) {
    const present = !!process.env[name];
    status[name] = present;
    if (!present) ok = false;
  }
  res.status(ok ? 200 : 503).json({
    ok,
    service: "vibal-wallet-signer",
    env: status,
  });
}
