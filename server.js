// Porchlight — standalone server with real accounts
//
// What changed from v1:
//  - No more trust-the-browser identity. People sign up with a real email,
//    verify a code, and log in with a password. The server derives who
//    you are from a signed session cookie, never from the request body.
//  - Blocking and reporting, plus a tiny admin page to review reports and
//    ban accounts. The first person to sign up becomes the admin.
//  - Optional invite-code gate on signup (set SIGNUP_INVITE_CODE).
//  - Basic rate limiting on auth and posting endpoints.
//
// See README.md for environment variables and setup.

const express = require("express");
const http = require("http");
const { WebSocketServer, WebSocket } = require("ws");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const PORT = process.env.PORT || 3000;
const SIGNUP_INVITE_CODE = process.env.SIGNUP_INVITE_CODE || null;
const RESEND_API_KEY = process.env.RESEND_API_KEY || null;
const EMAIL_FROM = process.env.EMAIL_FROM || "Porchlight <onboarding@resend.dev>";
const IS_PROD = process.env.NODE_ENV === "production";

const POSTS_FILE = path.join(__dirname, "data.json");
const USERS_FILE = path.join(__dirname, "users.json");
const REPORTS_FILE = path.join(__dirname, "reports.json");
const SECRET_FILE = path.join(__dirname, ".jwt-secret");

// ---------- tiny JSON-file store helpers ----------
function loadJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")); }
  catch (e) { return fallback; }
}
function saveJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}
function loadPosts() { return loadJson(POSTS_FILE, []); }
function savePosts(p) { saveJson(POSTS_FILE, p); }
function loadUsers() { return loadJson(USERS_FILE, []); }
function saveUsers(u) { saveJson(USERS_FILE, u); }
function loadReports() { return loadJson(REPORTS_FILE, []); }
function saveReports(r) { saveJson(REPORTS_FILE, r); }

function getOrCreateSecret() {
  try { return fs.readFileSync(SECRET_FILE, "utf8").trim(); }
  catch (e) {
    const secret = crypto.randomBytes(32).toString("hex");
    fs.writeFileSync(SECRET_FILE, secret);
    return secret;
  }
}
const JWT_SECRET = process.env.JWT_SECRET || getOrCreateSecret();

let posts = loadPosts();

// ---------- email ----------
async function sendVerificationEmail(toEmail, code) {
  if (!RESEND_API_KEY) {
    console.log(`[dev — no RESEND_API_KEY set] Verification code for ${toEmail}: ${code}`);
    return;
  }
  try {
    const { Resend } = require("resend");
    const resend = new Resend(RESEND_API_KEY);
    await resend.emails.send({
      from: EMAIL_FROM,
      to: toEmail,
      subject: "Your Porchlight verification code",
      text: `Your verification code is ${code}. It expires in 15 minutes.`,
    });
  } catch (e) {
    console.error("Email send failed, falling back to console:", e.message);
    console.log(`[dev fallback] Verification code for ${toEmail}: ${code}`);
  }
}

// ---------- rate limiting (in-memory, per IP) ----------
function makeLimiter(max, windowMs) {
  const hits = {};
  return function (req, res, next) {
    const key = req.ip || "unknown";
    const now = Date.now();
    hits[key] = (hits[key] || []).filter((t) => now - t < windowMs);
    if (hits[key].length >= max) return res.status(429).json({ error: "rate_limited" });
    hits[key].push(now);
    next();
  };
}
const authLimiter = makeLimiter(10, 10 * 60 * 1000); // 10 requests / 10 min / IP
const postLimiter = makeLimiter(20, 10 * 60 * 1000);

// ---------- auth helpers ----------
function issueSession(res, user) {
  const token = jwt.sign({ uid: user.id }, JWT_SECRET, { expiresIn: "30d" });
  res.cookie("session", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: IS_PROD,
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}
function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, isAdmin: !!u.isAdmin };
}
function authMiddleware(req, res, next) {
  const token = req.cookies && req.cookies.session;
  if (!token) return res.status(401).json({ error: "not_authenticated" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const users = loadUsers();
    const user = users.find((u) => u.id === payload.uid);
    if (!user || user.banned) return res.status(401).json({ error: "not_authenticated" });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: "not_authenticated" });
  }
}
function requireAdmin(req, res, next) {
  if (!req.user.isAdmin) return res.status(403).json({ error: "forbidden" });
  next();
}
function parseCookies(str) {
  const out = {};
  (str || "").split(";").forEach((pair) => {
    const idx = pair.indexOf("=");
    if (idx > -1) out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

function broadcast() {
  const payload = JSON.stringify({ type: "posts", posts });
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) client.send(payload);
  });
}

// ===================== AUTH =====================

app.post("/api/auth/signup", authLimiter, async (req, res) => {
  const { name, email, password, inviteCode } = req.body || {};
  if (SIGNUP_INVITE_CODE && inviteCode !== SIGNUP_INVITE_CODE) {
    return res.status(403).json({ error: "invalid_invite_code" });
  }
  if (!name || !email || !password) return res.status(400).json({ error: "missing_fields" });
  const cleanEmail = String(email).trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) return res.status(400).json({ error: "invalid_email" });
  if (String(password).length < 8) return res.status(400).json({ error: "weak_password" });

  const users = loadUsers();
  if (users.find((u) => u.email === cleanEmail)) return res.status(409).json({ error: "email_in_use" });

  const passwordHash = bcrypt.hashSync(password, 10);
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const user = {
    id: crypto.randomUUID(),
    name: String(name).trim().slice(0, 40),
    email: cleanEmail,
    passwordHash,
    verified: false,
    verifyCode: code,
    verifyExpires: Date.now() + 15 * 60 * 1000,
    banned: false,
    isAdmin: users.length === 0, // first account on a fresh install is the admin
    blockedUserIds: [],
    createdAt: new Date().toISOString(),
  };
  users.push(user);
  saveUsers(users);
  await sendVerificationEmail(cleanEmail, code);
  res.json({ ok: true, needsVerification: true });
});

app.post("/api/auth/verify", authLimiter, (req, res) => {
  const { email, code } = req.body || {};
  const users = loadUsers();
  const user = users.find((u) => u.email === String(email || "").trim().toLowerCase());
  if (!user) return res.status(404).json({ error: "not_found" });
  if (user.verified) return res.status(400).json({ error: "already_verified" });
  if (!user.verifyCode || user.verifyCode !== String(code || "").trim() || Date.now() > user.verifyExpires) {
    return res.status(400).json({ error: "invalid_or_expired" });
  }
  user.verified = true;
  user.verifyCode = null;
  user.verifyExpires = null;
  saveUsers(users);
  issueSession(res, user);
  res.json({ ok: true, user: publicUser(user) });
});

app.post("/api/auth/resend-code", authLimiter, async (req, res) => {
  const { email } = req.body || {};
  const users = loadUsers();
  const user = users.find((u) => u.email === String(email || "").trim().toLowerCase());
  if (!user) return res.status(404).json({ error: "not_found" });
  if (user.verified) return res.status(400).json({ error: "already_verified" });
  user.verifyCode = String(Math.floor(100000 + Math.random() * 900000));
  user.verifyExpires = Date.now() + 15 * 60 * 1000;
  saveUsers(users);
  await sendVerificationEmail(user.email, user.verifyCode);
  res.json({ ok: true });
});

app.post("/api/auth/login", authLimiter, (req, res) => {
  const { email, password } = req.body || {};
  const users = loadUsers();
  const user = users.find((u) => u.email === String(email || "").trim().toLowerCase());
  if (!user || !bcrypt.compareSync(password || "", user.passwordHash)) {
    return res.status(401).json({ error: "invalid_credentials" });
  }
  if (user.banned) return res.status(403).json({ error: "banned" });
  if (!user.verified) return res.status(403).json({ error: "not_verified" });
  issueSession(res, user);
  res.json({ ok: true, user: publicUser(user) });
});

app.post("/api/auth/logout", (req, res) => {
  res.clearCookie("session");
  res.json({ ok: true });
});

app.get("/api/auth/me", authMiddleware, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// ===================== POSTS (all require a verified session) =====================

app.get("/api/posts", authMiddleware, (req, res) => {
  res.json(posts);
});

app.post("/api/posts", authMiddleware, postLimiter, (req, res) => {
  const body = req.body || {};
  if (!body.title || !body.type) return res.status(400).json({ error: "missing_fields" });
  const post = {
    id: crypto.randomUUID(),
    type: body.type,
    category: body.category || "Other",
    title: String(body.title).slice(0, 90),
    description: String(body.description || "").slice(0, 400),
    timing: String(body.timing || "").slice(0, 60),
    authorId: req.user.id,
    authorName: req.user.name,
    status: "open",
    matchedWith: null,
    matchedWithName: null,
    scheduleNote: null,
    hours: null,
    createdAt: new Date().toISOString(),
    completedAt: null,
  };
  posts.unshift(post);
  savePosts(posts);
  broadcast();
  res.json(post);
});

app.post("/api/posts/:id/claim", authMiddleware, postLimiter, (req, res) => {
  const idx = posts.findIndex((p) => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "not_found" });
  if (posts[idx].status !== "open") return res.status(409).json({ error: "not_open" });
  if (posts[idx].authorId === req.user.id) return res.status(400).json({ error: "cant_claim_own_post" });
  posts[idx] = Object.assign({}, posts[idx], {
    status: "matched",
    matchedWith: req.user.id,
    matchedWithName: req.user.name,
  });
  savePosts(posts);
  broadcast();
  res.json(posts[idx]);
});

app.patch("/api/posts/:id", authMiddleware, (req, res) => {
  const idx = posts.findIndex((p) => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "not_found" });
  const post = posts[idx];
  const body = Object.assign({}, req.body || {});
  delete body.requesterId; // identity always comes from the session now, never the client
  const requesterId = req.user.id;

  if (body.status === "cancelled" && requesterId !== post.authorId) {
    return res.status(403).json({ error: "forbidden" });
  }
  const touchesParticipantOnlyFields = body.scheduleNote !== undefined || body.status === "completed";
  if (touchesParticipantOnlyFields && requesterId !== post.authorId && requesterId !== post.matchedWith) {
    return res.status(403).json({ error: "forbidden" });
  }

  posts[idx] = Object.assign({}, post, body);
  savePosts(posts);
  broadcast();
  res.json(posts[idx]);
});

// ===================== BLOCKING =====================

app.get("/api/users/me/blocked", authMiddleware, (req, res) => {
  res.json({ blockedUserIds: req.user.blockedUserIds || [] });
});
app.post("/api/users/:id/block", authMiddleware, (req, res) => {
  const users = loadUsers();
  const me = users.find((u) => u.id === req.user.id);
  if (!me.blockedUserIds.includes(req.params.id)) me.blockedUserIds.push(req.params.id);
  saveUsers(users);
  res.json({ ok: true });
});
app.post("/api/users/:id/unblock", authMiddleware, (req, res) => {
  const users = loadUsers();
  const me = users.find((u) => u.id === req.user.id);
  me.blockedUserIds = (me.blockedUserIds || []).filter((id) => id !== req.params.id);
  saveUsers(users);
  res.json({ ok: true });
});

// ===================== REPORTING =====================

app.post("/api/reports", authMiddleware, postLimiter, (req, res) => {
  const { reportedUserId, postId, reason } = req.body || {};
  if (!reportedUserId || !reason) return res.status(400).json({ error: "missing_fields" });
  const reports = loadReports();
  reports.unshift({
    id: crypto.randomUUID(),
    reporterId: req.user.id,
    reporterName: req.user.name,
    reportedUserId,
    postId: postId || null,
    reason: String(reason).slice(0, 500),
    status: "open",
    createdAt: new Date().toISOString(),
  });
  saveReports(reports);
  res.json({ ok: true });
});

// ===================== ADMIN =====================
// The first account created on a fresh install is the admin. Open
// /admin.html while logged in as that account.

app.get("/api/admin/reports", authMiddleware, requireAdmin, (req, res) => {
  const reports = loadReports();
  const users = loadUsers();
  const withNames = reports.map((r) => {
    const reported = users.find((u) => u.id === r.reportedUserId);
    return Object.assign({}, r, {
      reportedUserName: reported ? reported.name : "Unknown",
      reportedUserEmail: reported ? reported.email : "",
      reportedUserBanned: reported ? !!reported.banned : false,
    });
  });
  res.json(withNames);
});
app.post("/api/admin/ban/:userId", authMiddleware, requireAdmin, (req, res) => {
  const users = loadUsers();
  const u = users.find((x) => x.id === req.params.userId);
  if (!u) return res.status(404).json({ error: "not_found" });
  u.banned = true;
  saveUsers(users);
  res.json({ ok: true });
});
app.post("/api/admin/unban/:userId", authMiddleware, requireAdmin, (req, res) => {
  const users = loadUsers();
  const u = users.find((x) => x.id === req.params.userId);
  if (!u) return res.status(404).json({ error: "not_found" });
  u.banned = false;
  saveUsers(users);
  res.json({ ok: true });
});
app.post("/api/admin/reports/:id/resolve", authMiddleware, requireAdmin, (req, res) => {
  const reports = loadReports();
  const r = reports.find((x) => x.id === req.params.id);
  if (!r) return res.status(404).json({ error: "not_found" });
  r.status = "resolved";
  saveReports(reports);
  res.json({ ok: true });
});

// ===================== WEBSOCKET (requires a valid session cookie) =====================

wss.on("connection", (ws, req) => {
  const cookies = parseCookies(req.headers.cookie);
  const token = cookies.session;
  let authed = false;
  if (token) {
    try { jwt.verify(token, JWT_SECRET); authed = true; } catch (e) { /* not authed */ }
  }
  if (!authed) { ws.close(4001, "unauthenticated"); return; }
  ws.send(JSON.stringify({ type: "posts", posts }));
});

server.listen(PORT, () => {
  console.log(`Porchlight running at http://localhost:${PORT}`);
  if (!RESEND_API_KEY) {
    console.log("No RESEND_API_KEY set — verification codes will print to this console instead of emailing.");
  }
  if (SIGNUP_INVITE_CODE) {
    console.log("Signup is gated behind an invite code.");
  }
});
