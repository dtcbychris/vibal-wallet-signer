import sharp from "sharp";

const MAX_BYTES = 5 * 1024 * 1024; // 5MB cap
const FETCH_TIMEOUT_MS = 6000;

export type LogoAssets = {
  "logo.png": Buffer;
  "logo@2x.png": Buffer;
};

async function fetchImage(url: string): Promise<Buffer> {
  if (!/^https:\/\//i.test(url)) throw new Error("logoUrl must be https");

  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: ctrl.signal });
    if (!res.ok) throw new Error(`fetch ${res.status}`);
    const ct = res.headers.get("content-type") ?? "";
    if (!ct.startsWith("image/")) throw new Error(`bad content-type ${ct}`);

    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.byteLength > MAX_BYTES) throw new Error("image too large");
    return buf;
  } finally {
    clearTimeout(t);
  }
}

async function resizeContain(src: Buffer, w: number, h: number): Promise<Buffer> {
  return sharp(src, { failOn: "none" })
    .ensureAlpha()
    .resize(w, h, {
      fit: "contain",
      background: { r: 0, g: 0, b: 0, alpha: 0 }, // transparent padding
      withoutEnlargement: false,
    })
    .png({ compressionLevel: 9, adaptiveFiltering: true })
    .toBuffer();
}

export async function buildLogoAssets(logoUrl: string): Promise<LogoAssets> {
  const src = await fetchImage(logoUrl);
  const [logo1x, logo2x] = await Promise.all([
    resizeContain(src, 160, 50),
    resizeContain(src, 320, 100),
  ]);
  return { "logo.png": logo1x, "logo@2x.png": logo2x };
}

