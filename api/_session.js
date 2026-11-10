import crypto from "node:crypto";

export const COOKIE_NAME = "sr1_admin";
export const SESSION_TTL_SECONDS = 60 * 60 * 12;

export function sign(payload, secret) {
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

export function createToken(username, secret) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
  const payload = `${Buffer.from(username).toString("base64url")}.${exp}`;
  return `${payload}.${sign(payload, secret)}`;
}

export function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}
