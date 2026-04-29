import type { VercelRequest, VercelResponse } from "@vercel/node";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import forge from "node-forge";
import JSZip from "jszip";
import { buildLogoAssets } from "../../lib/walletLogo";

export const config = {
  maxDuration: 15,
};

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

const ASSETS_DIR = path.join(process.cwd(), "assets");
const ASSET_FILES = ["icon.png", "icon@2x.png", "icon@3x.png", "logo.png", "logo@2x.png"];

function loadAssets(): Record<string, Buffer> {
  const out: Record<string, Buffer> = {};

  for (const file of ASSET_FILES) {
    const p = path.join(ASSETS_DIR, file);
    if (fs.existsSync(p)) out[file] = fs.readFileSync(p);
  }

  if (!out["icon.png"] || !out["icon@2x.png"]) {
    throw new Error("Missing required assets: icon.png and icon@2x.png");
  }

  return out;
}

function sha1(buffer: Buffer): string {
  return crypto.createHash("sha1").update(buffer).digest("hex");
}

function buildManifest(files: Record<string, Buffer>): Record<string, string> {
  const manifest: Record<string, string> = {};

  for (const [name, buffer] of Object.entries(files)) {
    manifest[name] = sha1(buffer);
  }

  return manifest;
}

function normalizePem(value: string | undefined): string {
  if (!value) return "";
  return value.replace(/\\n/g, "\n").trim();
}

function signManifest(manifestBuffer: Buffer): Buffer {
  const certPem = normalizePem(process.env.APPLE_PASS_CERTIFICATE);
  const keyPem = normalizePem(process.env.APPLE_PASS_PRIVATE_KEY);
  const wwdrPem = normalizePem(process.env.APPLE_WWDR_CERTIFICATE);
  const passphrase = process.env.APPLE_PASS_PRIVATE_KEY_PASSPHRASE || undefined;

  if (!certPem || !keyPem || !wwdrPem) {
    throw new Error("Missing Apple Wallet certificate environment variables");
  }

  const cert = forge.pki.certificateFromPem(certPem);
  const wwdr = forge.pki.certificateFromPem(wwdrPem);

  let privateKey: forge.pki.PrivateKey | null = null;

  if (keyPem.includes("ENCRYPTED")) {
    if (!passphrase) {
      throw new Error("Encrypted private key requires APPLE_PASS_PRIVATE_KEY_PASSPHRASE");
    }
    privateKey = forge.pki.decryptRsaPrivateKey(keyPem, passphrase);
  } else {
    privateKey = forge.pki.privateKeyFromPem(keyPem);
  }

  if (!privateKey) {
    throw new Error("Unable to parse Apple Wallet private key");
  }

  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(manifestBuffer.toString("latin1"));
  p7.addCertificate(cert);
  p7.addCertificate(wwdr);
  p7.addSigner({
    key: privateKey,
    certificate: cert,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      {
        type: forge.pki.oids.contentType,
        value: forge.pki.oids.data,
      },
      {
        type: forge.pki.oids.messageDigest,
      },
      {
        type: forge.pki.oids.signingTime,
        value: new Date().toISOString(),
      },
    ],
  });

  p7.sign({ detached: true });

  const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
  return Buffer.from(der, "latin1");
}

async function zipFiles(files: Record<string, Buffer>): Promise<Buffer> {
  const zip = new JSZip();

  for (const [name, buffer] of Object.entries(files)) {
    zip.file(name, buffer);
  }

  return zip.generateAsync({
    type: "nodebuffer",
    compression: "DEFLATE",
    compressionOptions: { level: 9 },
  });
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  if (!isAuthorized(req)) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;

    const passJson = body?.passJson;
    const logoUrl = body?.assets?.logoUrl as string | undefined;

    if (!passJson || typeof passJson !== "object") {
      return res.status(400).json({ error: "Missing passJson" });
    }

    const defaultAssets = loadAssets();
    const passAssets: Record<string, Buffer> = { ...defaultAssets };

    let customLogoUsed = false;
    let logoFetchStatus: "ok" | "skipped" | "failed" = "skipped";
    let logoBytes = { x1: 0, x2: 0 };

    if (logoUrl) {
      try {
        const built = await buildLogoAssets(logoUrl);
        passAssets["logo.png"] = built["logo.png"];
        passAssets["logo@2x.png"] = built["logo@2x.png"];

        customLogoUsed = true;
        logoFetchStatus = "ok";
        logoBytes = {
          x1: built["logo.png"].byteLength,
          x2: built["logo@2x.png"].byteLength,
        };
      } catch (err) {
        logoFetchStatus = "failed";
        console.warn("[wallet-signer] custom logo failed, falling back to default", {
          error: err instanceof Error ? err.message : String(err),
        });
      }
    }

    console.log("[wallet-signer] logo decision", {
      customLogoUsed,
      logoFetchStatus,
      logoBytes,
      serial: passJson.serialNumber,
    });

    passAssets["pass.json"] = Buffer.from(JSON.stringify(passJson), "utf8");

    const manifest = buildManifest(passAssets);
    const manifestBuffer = Buffer.from(JSON.stringify(manifest), "utf8");
    passAssets["manifest.json"] = manifestBuffer;

    passAssets["signature"] = signManifest(manifestBuffer);

    const pkpass = await zipFiles(passAssets);

    res.setHeader("Content-Type", "application/vnd.apple.pkpass");
    res.setHeader("Content-Disposition", 'attachment; filename="vibal-ticket.pkpass"');
    res.setHeader("Cache-Control", "no-store");
    res.status(200).send(pkpass);
  } catch (err) {
    console.error("[wallet-signer] error", err);
    res.status(500).json({
      error: err instanceof Error ? err.message : "Signing failed",
    });
  }
}
