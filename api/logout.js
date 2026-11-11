import { COOKIE_NAME } from "./_session.js";

export default function handler(req, res) {
  res.setHeader("Set-Cookie", `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`);
  res.setHeader("Location", "/login?logged_out=1");
  return res.status(303).end();
}
