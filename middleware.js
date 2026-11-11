import { next } from "@vercel/functions";

export const config = {
  matcher: ["/admin", "/admin/:path*"],
};

const COOKIE_NAME = "sr1_admin";

export default async function middleware(request) {
  const secret = process.env.ADMIN_SESSION_SECRET;
  const cookies = request.headers.get("cookie") || "";
  const match = cookies.match(new RegExp(`(?:^|;\\s*)${COOKIE_NAME}=([^;]+)`));

  if (secret && match && (await isValidToken(match[1], secret))) {
    return next();
  }

  const url = new URL(request.url);
  const loginUrl = new URL("/login", url.origin);
  loginUrl.searchParams.set("next", url.pathname);
  return Response.redirect(loginUrl, 302);
}

async function isValidToken(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [user, exp, signature] = parts;
  if (!/^\d+$/.test(exp) || Number(exp) < Date.now() / 1000) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${user}.${exp}`));
  const expected = [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
  if (expected.length !== signature.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  return diff === 0;
}
