import { COOKIE_NAME, SESSION_TTL_SECONDS, createToken, safeEqual } from "./_session.js";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  const { ADMIN_USERNAME = "admin", ADMIN_PASSWORD, ADMIN_SESSION_SECRET } = process.env;
  if (!ADMIN_PASSWORD || !ADMIN_SESSION_SECRET) {
    return res.status(500).json({ ok: false, error: "Admin login is not configured" });
  }

  const body = typeof req.body === "string" ? safeParse(req.body) : req.body || {};
  const username = String(body.username || "").trim();
  const password = String(body.password || "");

  const valid = safeEqual(username, ADMIN_USERNAME) & safeEqual(password, ADMIN_PASSWORD);
  if (!valid) {
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
