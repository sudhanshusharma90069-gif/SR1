(function () {
  const FIREBASE_VERSION = "10.12.2";
  const cfg = window.SR1_FIREBASE_CONFIG;
  const listeners = new Set();
  let current = null;
  let fb = null;

  const emit = () => listeners.forEach((cb) => cb(current));
  const loadScript = (src) =>
    new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = src;
      s.onload = resolve;
      s.onerror = () => reject(new Error("Could not load " + src));
      document.head.appendChild(s);
    });
  const toUser = (u) => (u ? { uid: u.uid, email: u.email, name: u.displayName || (u.email || "").split("@")[0], createdAt: u.metadata && u.metadata.creationTime } : null);

  // ---------- Demo mode (browser-only accounts) ----------
  const DEMO_USERS = "sr1_demo_users";
  const DEMO_SESSION = "sr1_demo_session";
  const DEMO_RESETS = "sr1_demo_resets";
  const read = (k, d) => { try { return JSON.parse(localStorage.getItem(k)) ?? d; } catch { return d; } };
  const write = (k, v) => localStorage.setItem(k, JSON.stringify(v));
  async function hash(text) {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("sr1-demo:" + text));
    return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  const fail = (code, message) => { const e = new Error(message); e.code = code; throw e; };
  const demoPublic = (u) => (u ? { uid: u.uid, email: u.email, name: u.name, createdAt: u.createdAt } : null);
  function demoLoad() {
    const email = localStorage.getItem(DEMO_SESSION);
    current = email ? demoPublic(read(DEMO_USERS, {})[email]) : null;
  }

  const demo = {
    async signUp(name, email, password) {
      email = email.trim().toLowerCase();
      if (password.length < 6) fail("auth/weak-password", "Password must be at least 6 characters.");
      const users = read(DEMO_USERS, {});
      if (users[email]) fail("auth/email-already-in-use", "An account with this email already exists.");
      users[email] = { uid: "u_" + Math.random().toString(36).slice(2, 10), name: name.trim(), email, pw: await hash(password), createdAt: new Date().toISOString() };
      write(DEMO_USERS, users);
      localStorage.setItem(DEMO_SESSION, email);
      demoLoad(); emit();
      return current;
    },
    async signIn(email, password) {
      email = email.trim().toLowerCase();
      const u = read(DEMO_USERS, {})[email];
      if (!u || u.pw !== (await hash(password))) fail("auth/invalid-credential", "Incorrect email or password.");
      localStorage.setItem(DEMO_SESSION, email);
      demoLoad(); emit();
      return current;
    },
    async signOut() { localStorage.removeItem(DEMO_SESSION); current = null; emit(); },
    async sendReset(email) {
      email = email.trim().toLowerCase();
      const token = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
      if (read(DEMO_USERS, {})[email]) {
        const resets = read(DEMO_RESETS, {});
        resets[token] = { email, exp: Date.now() + 30 * 60 * 1000 };
        write(DEMO_RESETS, resets);
        return { demoLink: `${location.origin}/signin?mode=resetPassword&oobCode=${token}` };
      }
      return {};
    },
    async verifyReset(code) {
      const r = read(DEMO_RESETS, {})[code];
      if (!r || r.exp < Date.now()) fail("auth/expired-action-code", "This reset link is invalid or has expired.");
      return r.email;
    },
    async confirmReset(code, password) {
      const email = await demo.verifyReset(code);
      if (password.length < 6) fail("auth/weak-password", "Password must be at least 6 characters.");
      const users = read(DEMO_USERS, {});
      users[email].pw = await hash(password);
      write(DEMO_USERS, users);
      const resets = read(DEMO_RESETS, {}); delete resets[code]; write(DEMO_RESETS, resets);
    },
    async updateName(name) {
      const users = read(DEMO_USERS, {});
      users[current.email].name = name.trim();
      write(DEMO_USERS, users); demoLoad(); emit();
    },
    async changePassword(oldPw, newPw) {
      const users = read(DEMO_USERS, {});
      const u = users[current.email];
      if (u.pw !== (await hash(oldPw))) fail("auth/wrong-password", "Current password is incorrect.");
      if (newPw.length < 6) fail("auth/weak-password", "Password must be at least 6 characters.");
      u.pw = await hash(newPw); write(DEMO_USERS, users);
    },
  };

  // ---------- Firebase mode ----------
  const firebaseImpl = {
    async signUp(name, email, password) {
      const cred = await fb.auth().createUserWithEmailAndPassword(email.trim(), password);
      await cred.user.updateProfile({ displayName: name.trim() });
      current = toUser(fb.auth().currentUser); emit();
      return current;
    },
    async signIn(email, password) {
      const cred = await fb.auth().signInWithEmailAndPassword(email.trim(), password);
      return toUser(cred.user);
    },
    async signOut() { await fb.auth().signOut(); },
    async sendReset(email) {
      try {
        await fb.auth().sendPasswordResetEmail(email.trim(), { url: location.origin + "/signin?reset=done" });
      } catch (e) {
        if (e.code === "auth/user-not-found") return {};
        if (e.code !== "auth/unauthorized-continue-uri" && e.code !== "auth/invalid-continue-uri") throw e;
        await fb.auth().sendPasswordResetEmail(email.trim());
      }
      return {};
    },
    async verifyReset(code) { return fb.auth().verifyPasswordResetCode(code); },
    async confirmReset(code, password) { await fb.auth().confirmPasswordReset(code, password); },
    async updateName(name) { await fb.auth().currentUser.updateProfile({ displayName: name.trim() }); current = toUser(fb.auth().currentUser); emit(); },
    async changePassword(oldPw, newPw) {
      const u = fb.auth().currentUser;
      try {
        await u.reauthenticateWithCredential(fb.auth.EmailAuthProvider.credential(u.email, oldPw));
      } catch (e) {
        if (e.code === "auth/invalid-credential" || e.code === "auth/wrong-password") fail("auth/wrong-password", "Current password is incorrect.");
        throw e;
      }
      await u.updatePassword(newPw);
    },
    async idToken() { return fb.auth().currentUser ? fb.auth().currentUser.getIdToken() : null; },
  };

  const ready = (async () => {
    if (!cfg) { demoLoad(); return "demo"; }
    await loadScript(`https://www.gstatic.com/firebasejs/${FIREBASE_VERSION}/firebase-app-compat.js`);
    await loadScript(`https://www.gstatic.com/firebasejs/${FIREBASE_VERSION}/firebase-auth-compat.js`);
    fb = window.firebase;
    if (!fb.apps.length) fb.initializeApp(cfg);
    await new Promise((resolve) => {
      let first = true;
      fb.auth().onAuthStateChanged((u) => { current = toUser(u); emit(); if (first) { first = false; resolve(); } });
    });
    return "firebase";
  })();

  const impl = () => (cfg ? firebaseImpl : demo);
  const ERRORS = {
    "auth/invalid-credential": "Incorrect email or password.",
    "auth/wrong-password": "Current password is incorrect.",
    "auth/user-not-found": "Incorrect email or password.",
    "auth/email-already-in-use": "An account with this email already exists.",
    "auth/weak-password": "Password must be at least 6 characters.",
    "auth/invalid-email": "Please enter a valid email address.",
    "auth/too-many-requests": "Too many attempts. Please try again in a few minutes.",
    "auth/expired-action-code": "This reset link is invalid or has expired.",
    "auth/invalid-action-code": "This reset link is invalid or has expired.",
    "auth/network-request-failed": "Network error. Please check your connection.",
    "auth/operation-not-allowed": "Email sign-in is not enabled yet. Please try again later.",
    "auth/configuration-not-found": "Email sign-in is not enabled yet. Please try again later.",
  };

  window.SR1Auth = {
    mode: cfg ? "firebase" : "demo",
    ready,
    current: () => current,
    onChange(cb) { listeners.add(cb); return () => listeners.delete(cb); },
    message: (e) => ERRORS[e && e.code] || (e && e.message) || "Something went wrong.",
    signUp: (...a) => ready.then(() => impl().signUp(...a)),
    signIn: (...a) => ready.then(() => impl().signIn(...a)),
    signOut: () => ready.then(() => impl().signOut()),
    sendReset: (e) => ready.then(() => impl().sendReset(e)),
    verifyReset: (c) => ready.then(() => impl().verifyReset(c)),
    confirmReset: (c, p) => ready.then(() => impl().confirmReset(c, p)),
    updateName: (n) => ready.then(() => impl().updateName(n)),
    changePassword: (o, n) => ready.then(() => impl().changePassword(o, n)),
    idToken: () => ready.then(() => (cfg ? firebaseImpl.idToken() : null)),
    userKey: (suffix) => (current ? `sr1_u_${current.uid}_${suffix}` : null),
  };
})();
