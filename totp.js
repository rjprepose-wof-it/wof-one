// Rotating-code logic (TOTP-style), 6 digits. Period set in TOTP_PERIOD_SECONDS below.
// NOTE: This runs entirely client-side. The secret below is visible to
// anyone who views this file's source. It deters casual/accidental access
// to an unlisted link; it is not real cryptographic security.

const TOTP_SECRET_B32 = "4EO7HGNWJP74I53CSLB37PQDUDXFMYHX";
const TOTP_PERIOD_SECONDS = 86400; // 24 hours
const TOTP_DIGITS = 6;

function base32Decode(b32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const char of b32.replace(/=+$/, "").toUpperCase()) {
    const val = alphabet.indexOf(char);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

async function hmacSha1(keyBytes, msgBytes) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, msgBytes);
  return new Uint8Array(sig);
}

function counterToBytes(counter) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  // JS numbers are safe up to 2^53; counter fits easily for a long time.
  view.setUint32(4, counter, false);
  return new Uint8Array(buf);
}

async function totpForCounter(counter) {
  const keyBytes = base32Decode(TOTP_SECRET_B32);
  const msgBytes = counterToBytes(counter);
  const hmac = await hmacSha1(keyBytes, msgBytes);
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const code = (binCode % Math.pow(10, TOTP_DIGITS)).toString().padStart(TOTP_DIGITS, "0");
  return code;
}

function currentCounter() {
  return Math.floor(Date.now() / 1000 / TOTP_PERIOD_SECONDS);
}

function secondsRemainingInWindow() {
  const nowSec = Math.floor(Date.now() / 1000);
  return TOTP_PERIOD_SECONDS - (nowSec % TOTP_PERIOD_SECONDS);
}

async function getCurrentCode() {
  return totpForCounter(currentCounter());
}

// Only the code currently on screen is accepted — no next-code lookahead,
// no previous-window grace. Using it grants no extra time either way.
async function isCodeValid(inputCode) {
  const cleaned = (inputCode || "").trim();
  const current = await totpForCounter(currentCounter());
  return cleaned === current;
}
