import { createRemoteJWKSet, jwtVerify } from "jose";
import { COOKIE_NAME, SESSION_TTL_SECONDS, createToken, safeEqual } from "./_session.js";

const FIREBASE_JWKS = createRemoteJWKSet(
  new URL("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com")
);

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  const { ADMIN_USERNAME = "admin", ADMIN_PASSWORD, ADMIN_SESSION_SECRET, FIREBASE_PROJECT_ID, ADMIN_EMAILS = "" } = process.env;
  if (!ADMIN_SESSION_SECRET) {
    return res.status(500).json({ ok: false, error: "Admin login is not configured" });
  }

  const body = typeof req.body === "string" ? safeParse(req.body) : req.body || {};
  let username = null;

  if (body.idToken) {
    const admins = ADMIN_EMAILS.split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
    if (!FIREBASE_PROJECT_ID || !admins.length) {
      return res.status(400).json({ ok: false, error: "Email sign-in is not enabled for admins" });
    }
    try {
      const { payload } = await jwtVerify(String(body.idToken), FIREBASE_JWKS, {
        issuer: `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`,
        audience: FIREBASE_PROJECT_ID,
      });
      const email = String(payload.email || "").toLowerCase();
      if (admins.includes(email)) username = email;
    } catch {
      username = null;
    }
  } else if (ADMIN_PASSWORD) {
    const name = String(body.username || "").trim();
    const password = String(body.password || "");
    if (safeEqual(name, ADMIN_USERNAME) & safeEqual(password, ADMIN_PASSWORD)) username = name;
  }

  if (!username) {
    await new Promise((r) => setTimeout(r, 600));
    return res.status(401).json({ ok: false, error: "Invalid username or password" });
  }

  const token = createToken(username, ADMIN_SESSION_SECRET);
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_TTL_SECONDS}`
  );
  return res.status(200).json({ ok: true });
}

function safeParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    return Object.fromEntries(new URLSearchParams(text));
  }
}
