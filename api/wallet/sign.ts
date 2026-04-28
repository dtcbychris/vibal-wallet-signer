// api/wallet/sign.ts
// Vercel Node serverless function — signs an Apple Wallet .pkpass package.
//
// Required env vars (set in Vercel project settings):
//   PASS_TYPE_ID            e.g. pass.io.getvibal.ticket
//   TEAM_ID                 your Apple Developer Team ID (10 chars)
//   PASS_CERT_PEM           PEM-encoded Pass Type ID certificate
//   PASS_CERT_KEY_PEM       PEM-encoded private key
//   PASS_CERT_KEY_PASSPHRASE optional passphrase for the key
//   WWDR_PEM                Apple WWDR intermediate cert (G4) in PEM
//   SIGNER_SHARED_SECRET    shared secret expected in `x-signer-secret`
//
// POST body (JSON):
//   {
//     "serialNumber": "vibal-ord-123",
//     "organizationName": "Vibal",
//     "description": "Vibal Event Ticket",
//     "eventName": "Sunset Run Club",
//     "attendeeName": "Jane Doe",
//     "ticketTier": "General",
//     "venue": "Echo Park",
//     "startsAt": "2026-05-01T18:00:00-07:00",
//     "qrPayload": "https://getvibal.io/t/abc123",
//     "backgroundColor": "rgb(15,17,26)",
//     "foregroundColor": "rgb(255,255,255)",
//     "labelColor": "rgb(0,102,255)"
//   }

import type { VercelRequest, VercelResponse } from '@vercel/node';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import forge from 'node-forge';
import JSZip from 'jszip';

// ---- Asset loading ----------------------------------------------------------
// process.cwd() is the project root on Vercel. Assets live at /assets at the
// repo root and are bundled via vercel.json `includeFiles` (see README).
const ASSET_DIR = join(process.cwd(), 'assets');
const ASSETS = {
  'icon.png':       readFileSync(join(ASSET_DIR, 'icon.png')),
  'icon@2x.png':    readFileSync(join(ASSET_DIR, 'icon@2x.png')),
  'icon@3x.png':    readFileSync(join(ASSET_DIR, 'icon@3x.png')),
  'logo.png':       readFileSync(join(ASSET_DIR, 'logo.png')),
  'logo@2x.png':    readFileSync(join(ASSET_DIR, 'logo@2x.png')),
} as const;

// ---- Cert loading -----------------------------------------------------------
function loadCerts() {
  const certPem = process.env.PASS_CERT_PEM!;
  const keyPem  = process.env.PASS_CERT_KEY_PEM!;
  const wwdrPem = process.env.WWDR_PEM!;
  const passphrase = process.env.PASS_CERT_KEY_PASSPHRASE || undefined;

  const cert = forge.pki.certificateFromPem(certPem);
  const wwdr = forge.pki.certificateFromPem(wwdrPem);
  const key  = passphrase
    ? forge.pki.decryptRsaPrivateKey(keyPem, passphrase)
    : forge.pki.privateKeyFromPem(keyPem);

  if (!key) throw new Error('Unable to load private key (wrong passphrase?)');
  return { cert, wwdr, key };
}

// ---- Signing ----------------------------------------------------------------
function signManifest(manifestJson: string): Buffer {
  const { cert, wwdr, key } = loadCerts();
  const p7 = forge.pkcs7.createSignedData();
  p7.content = forge.util.createBuffer(manifestJson, 'utf8');
  p7.addCertificate(cert);
  p7.addCertificate(wwdr);
  p7.addSigner({
    key,
    certificate: cert,
    digestAlgorithm: forge.pki.oids.sha256,
    authenticatedAttributes: [
      { type: forge.pki.oids.contentType, value: forge.pki.oids.data },
      { type: forge.pki.oids.messageDigest /* auto */ },
      { type: forge.pki.oids.signingTime,  value: new Date() as any },
    ],
  });
  // detached: true — signature is over the manifest, not embedded
  p7.sign({ detached: true });
  const der = forge.asn1.toDer(p7.toAsn1()).getBytes();
  return Buffer.from(der, 'binary');
}

// ---- pass.json builder ------------------------------------------------------
function buildPassJson(input: any) {
  return {
    formatVersion: 1,
    passTypeIdentifier: process.env.PASS_TYPE_ID!,
    teamIdentifier: process.env.TEAM_ID!,
    organizationName: input.organizationName ?? 'Vibal',
    description: input.description ?? 'Vibal Event Ticket',
    serialNumber: String(input.serialNumber),
    backgroundColor: input.backgroundColor ?? 'rgb(15,17,26)',
    foregroundColor: input.foregroundColor ?? 'rgb(255,255,255)',
    labelColor:      input.labelColor      ?? 'rgb(0,102,255)',
    barcodes: [{
      message: String(input.qrPayload),
      format: 'PKBarcodeFormatQR',
      messageEncoding: 'iso-8859-1',
    }],
    eventTicket: {
      primaryFields:   [{ key: 'event',    label: 'EVENT',    value: input.eventName }],
      secondaryFields: [
        { key: 'attendee', label: 'ATTENDEE', value: input.attendeeName ?? '' },
        { key: 'tier',     label: 'TIER',     value: input.ticketTier   ?? 'General' },
      ],
      auxiliaryFields: [
        { key: 'venue', label: 'VENUE', value: input.venue ?? '' },
        { key: 'starts', label: 'STARTS',
          value: input.startsAt,
          dateStyle: 'PKDateStyleMedium',
          timeStyle: 'PKDateStyleShort' },
      ],
    },
  };
}

// ---- Manifest ---------------------------------------------------------------
function buildManifest(files: Record<string, Buffer>): string {
  const manifest: Record<string, string> = {};
  for (const [name, buf] of Object.entries(files)) {
    manifest[name] = createHash('sha1').update(buf).digest('hex');
  }
  return JSON.stringify(manifest);
}

// ---- Handler ----------------------------------------------------------------
export default async function handler(req: VercelRequest, res: VercelResponse) {
  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }
  if (req.headers['x-signer-secret'] !== process.env.SIGNER_SHARED_SECRET) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  try {
    const input = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    if (!input?.serialNumber || !input?.eventName || !input?.qrPayload) {
      res.status(400).json({ error: 'Missing serialNumber / eventName / qrPayload' });
      return;
    }

    // 1. Build pass.json
    const passJson = Buffer.from(JSON.stringify(buildPassJson(input)), 'utf8');

    // 2. Bundle every file that goes into the pass (icons MUST be present)
    const files: Record<string, Buffer> = {
      'pass.json':     passJson,
      'icon.png':      ASSETS['icon.png'],
      'icon@2x.png':   ASSETS['icon@2x.png'],
      'icon@3x.png':   ASSETS['icon@3x.png'],
      'logo.png':      ASSETS['logo.png'],
      'logo@2x.png':   ASSETS['logo@2x.png'],
    };

    // 3. Build manifest.json (SHA-1 of every file above)
    const manifestJson = buildManifest(files);
    const manifestBuf = Buffer.from(manifestJson, 'utf8');

    // 4. Sign manifest (PKCS#7 detached)
    const signature = signManifest(manifestJson);

    // 5. Zip everything flat
    const zip = new JSZip();
    for (const [name, buf] of Object.entries(files)) zip.file(name, buf);
    zip.file('manifest.json', manifestBuf);
    zip.file('signature', signature);
    const pkpass = await zip.generateAsync({
      type: 'nodebuffer',
      compression: 'DEFLATE',
      compressionOptions: { level: 9 },
    });

    res.setHeader('Content-Type', 'application/vnd.apple.pkpass');
    res.setHeader('Content-Disposition', 'attachment; filename="vibal-ticket.pkpass"');
    res.setHeader('Cache-Control', 'no-store');
    res.status(200).send(pkpass);
  } catch (err: any) {
    console.error('[wallet/sign] error', err);
    res.status(500).json({ error: err?.message ?? 'Signing failed' });
  }
}
