// api/wallet/sign.ts
import type { VercelRequest, VercelResponse } from "@vercel/node";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import forge from "node-forge";
import JSZip from "jszip";

// ---- Auth ----
function isAuthorized(req: VercelRequest): boolean {
  const expected = process.env.SIGNER_SHARED_SECRET ?? "";
  if (!expected) return false;
  const headerSecret = (req.headers["x-signer-secret"] as string | undefined) ?? "";
  const bearer = (req.headers["authorization"] as string | undefined) ?? "";
  const bearerToken = bearer.toLowerCase().startsWith("bearer ")
    ? bearer.slice(7).trim()
    : "";
  return headerSecret === expected || bearerToken === expected;
}

// ---- Asset loader ----
const ASSETS_DIR = path.join(process.cwd(), "assets");
const ASSET_FILES = ["icon.png", "icon@2x.png", "icon@3x.png", "logo.png", "logo@2x.png"];

function loadAssets(): Record<string, Buffer> {
  const out: Record<string, Buffer> = {};
  for (const f of ASSET_FILES) {
    const p = path.join(ASSETS_DIR, f);
    if (fs.existsSync(p)) out[f] = fs.readFileSync(p);
  }
  if (!out["icon.png"] || !out["icon@2x.png"]) {
    throw new Error("Missing required assets: icon.png and icon@2x.png");
  }
  return out;
}

// ---- Manifest (SHA-1 of every file in the pass) ----
function buildManifest(files: Record<string, Buffer>): Buffer {
  const manifest: Record<string, string> = {};
  for (const [name, buf] of Object.entries(files)) {
    manifest[name] = crypto.createHash("sha1").update(buf).digest("hex");
  }
  return Buffer.from(JSON.stringify(manifest), "utf8");
}

// ---- PKCS#7 detached signature over manifest.json ----
function signManifest(manifestBuf: Buffer): Buffer {
  const signerCertPem = process.env.APPLE_PASS_SIGNER_CERT_PEM!;
  const signerKeyPem = process.env.APPLE_PASS_SIGNER_KEY_PEM!;
  const signerKeyPassphrase = process.env.APPLE_PASS_SIGNER_KEY_PASSPHRASE ?? "";
  const wwdrPem = process.env.APPLE_WWDR_CERT_PEM!;

  const cert = forge.pki.certificateFromPem(signerCertPem);
  const key = signerKeyPassphrase
    ? forge.pki.decryptRsaPrivateKey(signerKeyPem, signerKeyPassphrase)
    : forge.pki.privateKeyFromPem(signerKeyPem);
  const wwdr = forge.pki.certificateFromPem(wwdrPem);

  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(manifestBuf.toString("binary"));
  p7.addCertificate(cert);
  p7.addCertificate(wwdr);
  p7.addSigner({
    key,
    certificate: cert,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest },
      { type: forge.pki.oids.signingTime, value: new Date() as any },
    ],
  });
  p7.sign({ detached: true });

  const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
  return Buffer.from(der, "binary");
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }
  if (!isAuthorized(req)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }

  try {
    const body = (req.body ?? {}) as { passJson?: unknown };
    const passJson = body.passJson;
    if (!passJson || typeof passJson !== "object") {
      res.status(400).json({ error: "Missing passJson object in request body" });
      return;
    }

    // Minimal sanity: Apple requires these top-level fields
    const required = ["formatVersion", "passTypeIdentifier", "teamIdentifier", "serialNumber"];
    for (const k of required) {
      if (!(k in (passJson as Record<string, unknown>))) {
        res.status(400).json({ error: `passJson missing required field: ${k}` });
        return;
      }
    }

    const passBuf = Buffer.from(JSON.stringify(passJson), "utf8");
    const assets = loadAssets();

    // Files included in the pass package
    const files: Record<string, Buffer> = {
      "pass.json": passBuf,
      ...assets,
    };

    const manifest = buildManifest(files);
    const signature = signManifest(manifest);

    const zip = new JSZip();
    for (const [name, buf] of Object.entries(files)) zip.file(name, buf);
    zip.file("manifest.json", manifest);
    zip.file("signature", signature);

    const pkpass = await zip.generateAsync({ type: "nodebuffer", compression: "DEFLATE" });

    res.setHeader("Content-Type", "application/vnd.apple.pkpass");
    res.setHeader("Content-Disposition", 'attachment; filename="vibal.pkpass"');
    res.setHeader("Cache-Control", "no-store");
    res.status(200).send(pkpass);
  } catch (err: any) {
    console.error("[wallet/sign] error:", err);
    res.status(500).json({ error: "signing_failed", message: err.message });
  }
}

