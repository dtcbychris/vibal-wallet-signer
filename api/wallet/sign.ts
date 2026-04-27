import type { VercelRequest, VercelResponse } from "@vercel/node";
import { PKPass } from "passkit-generator";

/**
 * POST /api/wallet/sign
 *
 * Auth: Authorization: Bearer ${WALLET_SIGNING_SERVICE_TOKEN}
 * Body: { passJson: object }   // produced by Vibal's edge function
 * Returns: binary .pkpass (application/vnd.apple.pkpass)
 *
 * This service is intentionally tiny: it does NOT talk to Supabase,
 * does NOT know about tickets, and does NOT persist anything.
 * It only signs.
 */

export const config = {
  runtime: "nodejs",
  maxDuration: 30,
};

function unauthorized(res: VercelResponse, msg = "unauthorized") {
  return res.status(401).json({ error: msg });
}

function badRequest(res: VercelResponse, msg: string) {
  return res.status(400).json({ error: msg });
}

function readEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env var: ${name}`);
  return v;
}

/**
 * PEM env vars often arrive with literal `\n` instead of real newlines
 * (Vercel UI does this). Normalize so node-forge / openssl can parse.
 */
function normalizePem(pem: string): string {
  return pem.replace(/\\n/g, "\n");
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "method_not_allowed" });
  }

  // --- Auth ---
  const expected = process.env.WALLET_SIGNING_SERVICE_TOKEN;
  if (!expected) return res.status(500).json({ error: "service_misconfigured" });

  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
  if (!token || token !== expected) return unauthorized(res);

  // --- Body validation ---
  const body = (req.body ?? {}) as { passJson?: Record<string, unknown> };
  if (!body.passJson || typeof body.passJson !== "object") {
    return badRequest(res, "passJson is required");
  }

  // --- Load Apple credentials ---
  let signerCert: string;
  let signerKey: string;
  let signerKeyPassphrase: string;
  let wwdr: string;
  try {
    signerCert = normalizePem(readEnv("APPLE_PASS_CERTIFICATE"));
    signerKey = normalizePem(readEnv("APPLE_PASS_PRIVATE_KEY"));
    signerKeyPassphrase = readEnv("APPLE_PASS_PRIVATE_KEY_PASSPHRASE");
    wwdr = normalizePem(readEnv("APPLE_WWDR_CERTIFICATE"));
  } catch (err: any) {
    return res.status(500).json({ error: "service_misconfigured", detail: err.message });
  }

  try {
    // passkit-generator builds the pkpass zip + signs the manifest.
    // We pass the prebuilt pass.json from Vibal as the "model".
    const pass = new PKPass(
      {
        // pass.json is the only required model file for a basic event ticket.
        // Icons/logos can be added later by extending this map with PNG buffers.
        "pass.json": Buffer.from(JSON.stringify(body.passJson)),
      },
      {
        signerCert,
        signerKey,
        signerKeyPassphrase,
        wwdr,
      },
    );

    const buffer = pass.getAsBuffer();

    res.setHeader("Content-Type", "application/vnd.apple.pkpass");
    res.setHeader("Content-Disposition", 'attachment; filename="ticket.pkpass"');
    res.setHeader("Cache-Control", "no-store");
    return res.status(200).send(buffer);
  } catch (err: any) {
    // Do NOT leak cert contents in error messages.
    console.error("pkpass signing failed:", err?.message);
    return res.status(500).json({ error: "signing_failed", detail: err?.message ?? "unknown" });
  }
}
