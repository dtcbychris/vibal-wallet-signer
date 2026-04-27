# Vibal Wallet Signer

Tiny Node/Vercel service that signs Apple Wallet `.pkpass` files for Vibal.

**Architecture**

```
Vibal (Supabase edge fn)        This service (Vercel Node)
  builds passJson  ───POST───►  signs with Apple certs
                                returns binary .pkpass
```

This repo is **deliberately separate** from the Vibal Lovable project so the
Apple certificates never touch the main app and signing happens on a real
Node runtime (Deno can't reliably do PKCS#7 signing).

---

## Endpoints

### `POST /api/wallet/sign`

Headers:
- `Authorization: Bearer <WALLET_SIGNING_SERVICE_TOKEN>`
- `Content-Type: application/json`

Body:
```json
{ "passJson": { "...": "output of Vibal's buildEventTicketPassJson" } }
```

Response: `200` with `Content-Type: application/vnd.apple.pkpass` (binary).

### `GET /api/wallet/health`

Public. Returns `200` if all required env vars are set, `503` otherwise.
Never reveals values, only presence.

---

## Setup

### 1. Create a GitHub repo

```bash
cd vibal-wallet-signer
git init
git add .
git commit -m "Initial Vibal wallet signer"
# Create an empty repo on GitHub (e.g. vibal-wallet-signer), then:
git branch -M main
git remote add origin git@github.com:<your-org>/vibal-wallet-signer.git
git push -u origin main
```

### 2. Import to Vercel

1. Go to <https://vercel.com/new>.
2. Import the GitHub repo.
3. Framework preset: **Other**. Build command: leave empty. Output dir: leave empty.
4. Click **Deploy**. The first deploy will succeed but `/api/wallet/health`
   will return 503 until you add env vars.

### 3. Add Apple cert env vars in Vercel

In the Vercel project → **Settings → Environment Variables**, add (Production + Preview):

| Name | Value |
|---|---|
| `WALLET_SIGNING_SERVICE_TOKEN` | `openssl rand -hex 32` (long random string) |
| `APPLE_PASS_CERTIFICATE` | Full PEM of Pass Type ID cert |
| `APPLE_PASS_PRIVATE_KEY` | Full PEM of the private key |
| `APPLE_PASS_PRIVATE_KEY_PASSPHRASE` | Passphrase used when exporting the key |
| `APPLE_WWDR_CERTIFICATE` | Full PEM of Apple WWDR intermediate cert |

**Paste the full PEM blocks including the `-----BEGIN ...-----` and
`-----END ...-----` lines.** Vercel preserves real newlines, so paste as-is.
If you script env vars via CLI and end up with literal `\n`, the service
normalizes them at runtime.

#### Getting the certs

1. In the Apple Developer portal, create a **Pass Type ID** (e.g. `pass.com.vibal.ticket`).
2. Generate a CSR in Keychain Access, upload it, download the resulting `.cer`.
3. Import the `.cer` into Keychain. Right-click → Export both the certificate
   and its private key as a `.p12`. Pick a passphrase — that's `APPLE_PASS_PRIVATE_KEY_PASSPHRASE`.
4. Convert to PEM:
   ```bash
   openssl pkcs12 -in pass.p12 -clcerts -nokeys -out pass-cert.pem -legacy
   openssl pkcs12 -in pass.p12 -nocerts -out pass-key.pem -legacy
   ```
5. Download the WWDR intermediate from <https://www.apple.com/certificateauthority/>
   and convert to PEM:
   ```bash
   openssl x509 -inform DER -in AppleWWDRCAG3.cer -out wwdr.pem
   ```

After saving env vars, **redeploy** the project (Deployments → Redeploy).

### 4. Wire the URL back into Vibal

Your endpoint URL is:

```
https://<your-vercel-project>.vercel.app/api/wallet/sign
```

In Vibal (Lovable Cloud), add these secrets so the
`generate-apple-wallet-pass` edge function can call this service:

- `WALLET_SIGNING_SERVICE_URL` → the full URL above
- `WALLET_SIGNING_SERVICE_TOKEN` → the **same** token you set on Vercel
- `APPLE_PASS_TYPE_IDENTIFIER` → e.g. `pass.com.vibal.ticket`
- `APPLE_TEAM_IDENTIFIER` → your Apple Developer team ID

Once those are set, `useWalletAvailability` flips to `true` and the
"Add to Apple Wallet" button appears on guest tickets.

---

## Verify it's working

```bash
# Health (no auth)
curl https://<your-vercel-project>.vercel.app/api/wallet/health

# Sign (replace TOKEN; passJson is whatever Vibal builds)
curl -X POST https://<your-vercel-project>.vercel.app/api/wallet/sign \
  -H "Authorization: Bearer $WALLET_SIGNING_SERVICE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"passJson":{"formatVersion":1,"passTypeIdentifier":"pass.com.vibal.ticket","teamIdentifier":"XXXXXXXXXX","serialNumber":"test","organizationName":"Vibal","description":"Test"}}' \
  --output test.pkpass

file test.pkpass   # → Zip archive data
```

Open `test.pkpass` on a Mac to confirm it loads in Wallet preview.

---

## Security notes

- This service holds the **only** copy of Apple cert env vars. They are
  never sent to Vibal/Supabase or to the browser.
- Every signing request requires the bearer token. Rotate it by updating
  both Vercel and the Vibal `WALLET_SIGNING_SERVICE_TOKEN` secret.
- Health endpoint reveals **presence** of env vars only, never values.
- No request bodies are logged.
