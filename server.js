import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import morgan from "morgan";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

// ---- DB ----
const dbPath = process.env.DB_PATH || path.join(__dirname, "data.sqlite");
const db = new Database(dbPath);

db.pragma("journal_mode = WAL");
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  pass_hash TEXT NOT NULL,
  balance INTEGER NOT NULL DEFAULT 1000,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  type TEXT NOT NULL,            -- topup | withdraw | bet_lock | bet_payout | withdraw_lock | withdraw_paid | withdraw_refund
  amount INTEGER NOT NULL,       -- positive integer
  meta TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_user_id INTEGER,
  actor_username TEXT,
  action TEXT NOT NULL,          -- e.g. auth_login, request_topup, admin_approve_topup
  target_user_id INTEGER,
  ip TEXT,
  user_agent TEXT,
  meta TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS topup_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  source_game TEXT,              -- where TC/item came from
  source_sender TEXT,            -- sender IGN/ID from other game
  reference TEXT,                -- any ref / note
  proof_name TEXT,
  proof_mime TEXT,
  proof_base64 TEXT,
  status TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
  admin_note TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  reviewed_at TEXT,
  reviewed_by INTEGER,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(reviewed_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS withdraw_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  amount INTEGER NOT NULL,
  payout_method TEXT NOT NULL,   -- gcash | maya | bank | other
  payout_details TEXT NOT NULL,  -- JSON string
  status TEXT NOT NULL DEFAULT 'pending', -- pending | paid | rejected
  admin_note TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  reviewed_at TEXT,
  reviewed_by INTEGER,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(reviewed_by) REFERENCES users(id)
);
`);

function jsonError(res, status, msg) {
  return res.status(status).json({ ok: false, error: msg });
}

function isValidUsername(u) {
  return typeof u === "string" && /^[A-Za-z0-9]{5,12}$/.test(u);
}

function isValidPassword(p) {
  return typeof p === "string" && p.length >= 5 && p.length <= 12;
}

function signToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authRequired(req, res, next) {
  const auth = req.headers.authorization || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!token) return jsonError(res, 401, "Missing token");
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return jsonError(res, 401, "Invalid/expired token");
  }
}

function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") return jsonError(res, 403, "Admin only");
  next();
}

function getIp(req) {
  // trust proxy enabled
  return (req.headers["x-forwarded-for"] || "").toString().split(",")[0].trim() || req.ip || "";
}

function auditLog({ actor_user_id=null, actor_username=null, action, target_user_id=null, req=null, meta=null }) {
  try {
    const ip = req ? getIp(req) : null;
    const ua = req ? (req.headers["user-agent"] || "").toString().slice(0, 300) : null;
    db.prepare(`
      INSERT INTO audit_logs (actor_user_id, actor_username, action, target_user_id, ip, user_agent, meta)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      actor_user_id,
      actor_username,
      action,
      target_user_id,
      ip,
      ua,
      meta ? JSON.stringify(meta).slice(0, 8000) : null
    );
  } catch {}
}

// ---- Middleware ----
app.use(helmet({ contentSecurityPolicy: false })); // CSP off for CDN fonts/icons in your mockup
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(morgan("tiny"));

// ---- API ----
app.get("/api/health", (req, res) => res.json({ ok: true }));

app.post("/api/auth/signup", async (req, res) => {
  const { username, password } = req.body ?? {};
  if (!isValidUsername(username)) return jsonError(res, 400, "Username must be 5-12 chars, letters+numbers only.");
  if (!isValidPassword(password)) return jsonError(res, 400, "Password must be 5-12 chars.");

  const exists = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
  if (exists) return jsonError(res, 409, "Username already exists");

  const pass_hash = await bcrypt.hash(password, 10);

  // first user becomes admin (house)
  const count = db.prepare("SELECT COUNT(*) AS c FROM users").get().c;
  const role = count === 0 ? "admin" : "user";

  const info = db
    .prepare("INSERT INTO users (username, pass_hash, balance, role) VALUES (?, ?, ?, ?)")
    .run(username, pass_hash, 1000, role);

  const user = db.prepare("SELECT id, username, role, balance FROM users WHERE id = ?").get(info.lastInsertRowid);
  const token = signToken(user);
  auditLog({ actor_user_id: user.id, actor_username: user.username, action: "auth_signup", target_user_id: user.id, req, meta: { role: user.role } });
  return res.json({ ok: true, token, user });
});

app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body ?? {};
  if (!isValidUsername(username)) return jsonError(res, 400, "Invalid username format");
  if (!isValidPassword(password)) return jsonError(res, 400, "Invalid password format");

  const user = db.prepare("SELECT id, username, role, balance, pass_hash FROM users WHERE username = ?").get(username);
  if (!user) return jsonError(res, 401, "Wrong username/password");

  const ok = await bcrypt.compare(password, user.pass_hash);
  if (!ok) return jsonError(res, 401, "Wrong username/password");

  const token = signToken(user);
  auditLog({ actor_user_id: user.id, actor_username: user.username, action: "auth_login", target_user_id: user.id, req });
  return res.json({ ok: true, token, user: { id: user.id, username: user.username, role: user.role, balance: user.balance } });
});

app.get("/api/me", authRequired, (req, res) => {
  const user = db.prepare("SELECT id, username, role, balance, created_at FROM users WHERE id = ?").get(req.user.sub);
  if (!user) return jsonError(res, 404, "User not found");
  return res.json({ ok: true, user });
});

app.get("/api/wallet", authRequired, (req, res) => {
  const row = db.prepare("SELECT balance FROM users WHERE id = ?").get(req.user.sub);
  if (!row) return jsonError(res, 404, "User not found");
  res.json({ ok: true, balance: row.balance });
});

app.post("/api/wallet/topup", authRequired, adminOnly, (req, res) => {
  const { user_id, amount } = req.body ?? {};
  const uid = Number(user_id);
  const amt = Number(amount);
  if (!Number.isInteger(uid) || uid <= 0) return jsonError(res, 400, "Invalid user_id");
  if (!Number.isInteger(amt) || amt <= 0) return jsonError(res, 400, "Invalid amount");

  const tx = db.transaction(() => {
    const u = db.prepare("SELECT id FROM users WHERE id = ?").get(uid);
    if (!u) throw new Error("User not found");

    db.prepare("UPDATE users SET balance = balance + ? WHERE id = ?").run(amt, uid);
    db.prepare("INSERT INTO transactions (user_id, type, amount, meta) VALUES (?, 'topup', ?, ?)").run(
      uid, amt, JSON.stringify({ by: "admin", admin: req.user.username })
    );
    return db.prepare("SELECT balance FROM users WHERE id = ?").get(uid).balance;
  });

  try {
    const balance = tx();
    res.json({ ok: true, balance });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || "Topup failed" });
  }
});

app.post("/api/wallet/withdraw", authRequired, adminOnly, (req, res) => {
  const { user_id, amount } = req.body ?? {};
  const uid = Number(user_id);
  const amt = Number(amount);
  if (!Number.isInteger(uid) || uid <= 0) return jsonError(res, 400, "Invalid user_id");
  if (!Number.isInteger(amt) || amt <= 0) return jsonError(res, 400, "Invalid amount");

  const tx = db.transaction(() => {
    const row = db.prepare("SELECT balance FROM users WHERE id = ?").get(uid);
    if (!row) throw new Error("User not found");
    if (amt > row.balance) throw new Error("Insufficient funds");

    db.prepare("UPDATE users SET balance = balance - ? WHERE id = ?").run(amt, uid);
    db.prepare("INSERT INTO transactions (user_id, type, amount, meta) VALUES (?, 'withdraw', ?, ?)").run(
      uid, amt, JSON.stringify({ by: "admin", admin: req.user.username })
    );
    return db.prepare("SELECT balance FROM users WHERE id = ?").get(uid).balance;
  });

  try {
    const balance = tx();
    res.json({ ok: true, balance });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || "Withdraw failed" });
  }
});

// Optional: admin can adjust any user balance (house panel helper)
// ---- BET WALLET HELPERS (used by home page) ----
app.post("/api/bet/lock", authRequired, (req, res) => {
  const amt = Number(req.body?.amount);
  if (!Number.isInteger(amt) || amt <= 0) return jsonError(res, 400, "Invalid amount");

  const tx = db.transaction(() => {
    const row = db.prepare("SELECT balance FROM users WHERE id = ?").get(req.user.sub);
    if (!row) throw new Error("User not found");
    if (amt > row.balance) throw new Error("Insufficient funds");

    db.prepare("UPDATE users SET balance = balance - ? WHERE id = ?").run(amt, req.user.sub);
    db.prepare("INSERT INTO transactions (user_id, type, amount, meta) VALUES (?, 'bet_lock', ?, ?)").run(
      req.user.sub, amt, JSON.stringify({ status: "locked" })
    );
    return db.prepare("SELECT balance FROM users WHERE id = ?").get(req.user.sub).balance;
  });

  try {
    const balance = tx();
    auditLog({ actor_user_id: req.user.sub, actor_username: req.user.username, action: "bet_lock", target_user_id: req.user.sub, req, meta: { amount: amt } });
  res.json({ ok: true, balance });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || "Bet lock failed" });
  }
});

app.post("/api/bet/payout", authRequired, (req, res) => {
  const amt = Number(req.body?.amount);
  if (!Number.isInteger(amt) || amt <= 0) return jsonError(res, 400, "Invalid amount");

  const tx = db.transaction(() => {
    db.prepare("UPDATE users SET balance = balance + ? WHERE id = ?").run(amt, req.user.sub);
    db.prepare("INSERT INTO transactions (user_id, type, amount, meta) VALUES (?, 'bet_payout', ?, ?)").run(
      req.user.sub, amt, JSON.stringify({ status: "paid" })
    );
    return db.prepare("SELECT balance FROM users WHERE id = ?").get(req.user.sub).balance;
  });

  const balance = tx();
  auditLog({ actor_user_id: req.user.sub, actor_username: req.user.username, action: "bet_payout", target_user_id: req.user.sub, req, meta: { amount: amt } });
  res.json({ ok: true, balance });
});

// ---- TOPUP / WITHDRAW REQUESTS (player flow) ----

// Create topup request (player)
app.post("/api/requests/topup", authRequired, (req, res) => {
  const { amount, source_game, source_sender, reference, proof_name, proof_mime, proof_base64 } = req.body ?? {};
  const amt = Number(amount);

  if (!Number.isInteger(amt) || amt <= 0) return jsonError(res, 400, "Invalid amount");
  if (amt > 1_000_000_000) return jsonError(res, 400, "Amount too large");

  const game = (source_game || "").toString().trim().slice(0, 80);
  const sender = (source_sender || "").toString().trim().slice(0, 80);
  const ref = (reference || "").toString().trim().slice(0, 160);

  if (!game) return jsonError(res, 400, "Source game is required");
  if (!sender) return jsonError(res, 400, "Source sender is required");

  let p64 = null;
  let pname = null;
  let pmime = null;
  if (proof_base64) {
    p64 = proof_base64.toString();
    pname = (proof_name || "proof").toString().slice(0, 120);
    pmime = (proof_mime || "application/octet-stream").toString().slice(0, 80);
    if (p64.length > 2_800_000) return jsonError(res, 400, "Proof image too large (max ~2MB)");
    if (!p64.startsWith("data:")) return jsonError(res, 400, "Invalid proof format");
  }

  const info = db.prepare(`
    INSERT INTO topup_requests (user_id, amount, source_game, source_sender, reference, proof_name, proof_mime, proof_base64, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
  `).run(req.user.sub, amt, game, sender, ref || null, pname, pmime, p64);

  auditLog({
    actor_user_id: req.user.sub,
    actor_username: req.user.username,
    action: "request_topup",
    target_user_id: req.user.sub,
    req,
    meta: { amount: amt, source_game: game, source_sender: sender, reference: ref }
  });

  res.json({ ok: true, request_id: info.lastInsertRowid });
});

// Create withdraw request (player) — locks funds immediately
app.post("/api/requests/withdraw", authRequired, (req, res) => {
  const { amount, payout_method, payout_details } = req.body ?? {};
  const amt = Number(amount);
  if (!Number.isInteger(amt) || amt <= 0) return jsonError(res, 400, "Invalid amount");

  const method = (payout_method || "").toString().trim().toLowerCase();
  if (!["gcash","maya","bank","other"].includes(method)) return jsonError(res, 400, "Invalid payout method");

  let detailsStr = "";
  try {
    detailsStr = JSON.stringify(payout_details ?? {});
  } catch {
    return jsonError(res, 400, "Invalid payout details");
  }
  if (detailsStr.length > 4000) return jsonError(res, 400, "Payout details too long");

  const tx = db.transaction(() => {
    const row = db.prepare("SELECT balance FROM users WHERE id = ?").get(req.user.sub);
    if (!row) throw new Error("User not found");
    if (amt > row.balance) throw new Error("Insufficient funds");

    // lock funds
    db.prepare("UPDATE users SET balance = balance - ? WHERE id = ?").run(amt, req.user.sub);
    db.prepare("INSERT INTO transactions (user_id, type, amount, meta) VALUES (?, 'withdraw_lock', ?, ?)").run(
      req.user.sub, amt, JSON.stringify({ status: "pending" })
    );

    const info = db.prepare(`
      INSERT INTO withdraw_requests (user_id, amount, payout_method, payout_details, status)
      VALUES (?, ?, ?, ?, 'pending')
    `).run(req.user.sub, amt, method, detailsStr);

    const balance = db.prepare("SELECT balance FROM users WHERE id = ?").get(req.user.sub).balance;
    return { request_id: info.lastInsertRowid, balance };
  });

  try {
    const out = tx();
    auditLog({
    actor_user_id: req.user.sub,
    actor_username: req.user.username,
    action: "request_withdraw",
    target_user_id: req.user.sub,
    req,
    meta: { amount: amt, payout_method: method }
  });
  res.json({ ok: true, ...out });

auditLog({ actor_user_id: req.user.sub, actor_username: req.user.username, action: "admin_action", req, meta: { note } });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || "Withdraw request failed" });
  }
});

// List my requests (player)
app.get("/api/requests/mine", authRequired, (req, res) => {
  const topups = db.prepare(`
    SELECT id, amount, method, reference, status, admin_note, created_at, reviewed_at
    FROM topup_requests
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT 50
  `).all(req.user.sub);

  const withdrawals = db.prepare(`
    SELECT id, amount, payout_method, payout_details, status, admin_note, created_at, reviewed_at
    FROM withdraw_requests
    WHERE user_id = ?
    ORDER BY id DESC
    LIMIT 50
  `).all(req.user.sub);

  res.json({ ok: true, topups, withdrawals });
});

// ---- ADMIN: review requests ----
app.get("/api/admin/requests/topups", authRequired, adminOnly, (req, res) => {
  const status = (req.query.status || "pending").toString();
  const rows = db.prepare(`
    SELECT tr.id, tr.amount, tr.method, tr.reference, tr.status, tr.created_at,
           u.username
    FROM topup_requests tr
    JOIN users u ON u.id = tr.user_id
    WHERE tr.status = ?
    ORDER BY tr.id ASC
    LIMIT 200
  `).all(status);
  res.json({ ok: true, rows });
});

app.get("/api/admin/requests/withdrawals", authRequired, adminOnly, (req, res) => {
  const status = (req.query.status || "pending").toString();
  const rows = db.prepare(`
    SELECT wr.id, wr.amount, wr.payout_method, wr.payout_details, wr.status, wr.created_at,
           u.username
    FROM withdraw_requests wr
    JOIN users u ON u.id = wr.user_id
    WHERE wr.status = ?
    ORDER BY wr.id ASC
    LIMIT 200
  `).all(status);
  res.json({ ok: true, rows });
});

app.get("/api/admin/requests/topups/:id/proof", authRequired, adminOnly, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return jsonError(res, 400, "Invalid id");
  const row = db.prepare("SELECT proof_base64 FROM topup_requests WHERE id = ?").get(id);
  if (!row || !row.proof_base64) return jsonError(res, 404, "No proof");
  res.json({ ok: true, proof_base64: row.proof_base64 });
});

app.post("/api/admin/requests/topups/:id/approve", authRequired, adminOnly, (req, res) => {
  const id = Number(req.params.id);
  const note = (req.body?.admin_note || "").toString().slice(0, 500);
  if (!Number.isInteger(id) || id <= 0) return jsonError(res, 400, "Invalid id");

  const tx = db.transaction(() => {
    const tr = db.prepare("SELECT * FROM topup_requests WHERE id = ?").get(id);
    if (!tr) throw new Error("Request not found");
    if (tr.status !== "pending") throw new Error("Already reviewed");

    db.prepare("UPDATE users SET balance = balance + ? WHERE id = ?").run(tr.amount, tr.user_id);
    db.prepare("INSERT INTO transactions (user_id, type, amount, meta) VALUES (?, 'topup', ?, ?)").run(
      tr.user_id, tr.amount, JSON.stringify({ by: "admin", admin: req.user.username, request_id: id })
    );

    db.prepare(`
      UPDATE topup_requests
      SET status='approved', admin_note=?, reviewed_at=datetime('now'), reviewed_by=?
      WHERE id=?
    `).run(note || null, req.user.sub, id);

    const balance = db.prepare("SELECT balance FROM users WHERE id = ?").get(tr.user_id).balance;
    return { user_id: tr.user_id, balance };
  });

  try {
    const out = tx();
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || "Approve failed" });
  }
});

app.post("/api/admin/requests/topups/:id/reject", authRequired, adminOnly, (req, res) => {
  const id = Number(req.params.id);
  const note = (req.body?.admin_note || "").toString().slice(0, 500);
  if (!Number.isInteger(id) || id <= 0) return jsonError(res, 400, "Invalid id");

  const tr = db.prepare("SELECT status FROM topup_requests WHERE id = ?").get(id);
  if (!tr) return jsonError(res, 404, "Request not found");
  if (tr.status !== "pending") return jsonError(res, 400, "Already reviewed");

  db.prepare(`
    UPDATE topup_requests
    SET status='rejected', admin_note=?, reviewed_at=datetime('now'), reviewed_by=?
    WHERE id=?
  `).run(note || null, req.user.sub, id);

  res.json({ ok: true });
});

app.post("/api/admin/requests/withdrawals/:id/paid", authRequired, adminOnly, (req, res) => {
  const id = Number(req.params.id);
  const note = (req.body?.admin_note || "").toString().slice(0, 500);
  if (!Number.isInteger(id) || id <= 0) return jsonError(res, 400, "Invalid id");

  const tx = db.transaction(() => {
    const wr = db.prepare("SELECT * FROM withdraw_requests WHERE id = ?").get(id);
    if (!wr) throw new Error("Request not found");
    if (wr.status !== "pending") throw new Error("Already reviewed");

    db.prepare(`
      UPDATE withdraw_requests
      SET status='paid', admin_note=?, reviewed_at=datetime('now'), reviewed_by=?
      WHERE id=?
    `).run(note || null, req.user.sub, id);

    db.prepare("INSERT INTO transactions (user_id, type, amount, meta) VALUES (?, 'withdraw_paid', ?, ?)").run(
      wr.user_id, wr.amount, JSON.stringify({ by: "admin", admin: req.user.username, request_id: id })
    );
    return true;
  });

  try {
    tx();
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || "Mark paid failed" });
  }
});

app.post("/api/admin/requests/withdrawals/:id/reject", authRequired, adminOnly, (req, res) => {
  const id = Number(req.params.id);
  const note = (req.body?.admin_note || "").toString().slice(0, 500);
  if (!Number.isInteger(id) || id <= 0) return jsonError(res, 400, "Invalid id");

  const tx = db.transaction(() => {
    const wr = db.prepare("SELECT * FROM withdraw_requests WHERE id = ?").get(id);
    if (!wr) throw new Error("Request not found");
    if (wr.status !== "pending") throw new Error("Already reviewed");

    db.prepare("UPDATE users SET balance = balance + ? WHERE id = ?").run(wr.amount, wr.user_id);
    db.prepare("INSERT INTO transactions (user_id, type, amount, meta) VALUES (?, 'withdraw_refund', ?, ?)").run(
      wr.user_id, wr.amount, JSON.stringify({ by: "admin", admin: req.user.username, request_id: id })
    );

    db.prepare(`
      UPDATE withdraw_requests
      SET status='rejected', admin_note=?, reviewed_at=datetime('now'), reviewed_by=?
      WHERE id=?
    `).run(note || null, req.user.sub, id);

    const balance = db.prepare("SELECT balance FROM users WHERE id = ?").get(wr.user_id).balance;
    return { user_id: wr.user_id, balance };
  });

  try {
    const out = tx();
    res.json({ ok: true, ...out });
  } catch (e) {
    res.status(400).json({ ok: false, error: e.message || "Reject failed" });
  }
});

// Admin: view audit logs (system/player logs)
app.get("/api/admin/logs", authRequired, adminOnly, (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 200, 500);
  const rows = db.prepare(`
    SELECT id, actor_username, action, target_user_id, ip, user_agent, meta, created_at
    FROM audit_logs
    ORDER BY id DESC
    LIMIT ?
  `).all(limit);
  res.json({ ok: true, rows });
});

// Admin: list players
app.get("/api/admin/players", authRequired, adminOnly, (req, res) => {
  const rows = db.prepare(`
    SELECT id, username, role, balance, created_at
    FROM users
    ORDER BY id ASC
    LIMIT 500
  `).all();
  res.json({ ok: true, rows });
});

app.post("/api/admin/adjust-balance", authRequired, adminOnly, (req, res) => {
  const { username, delta } = req.body ?? {};
  if (!isValidUsername(username)) return jsonError(res, 400, "Invalid username");
  const d = Number(delta);
  if (!Number.isInteger(d) || d === 0) return jsonError(res, 400, "Invalid delta");

  const u = db.prepare("SELECT id, balance FROM users WHERE username = ?").get(username);
  if (!u) return jsonError(res, 404, "User not found");
  if (u.balance + d < 0) return jsonError(res, 400, "Would go negative");

  const tx = db.transaction(() => {
    db.prepare("UPDATE users SET balance = balance + ? WHERE id = ?").run(d, u.id);
    db.prepare("INSERT INTO transactions (user_id, type, amount, meta) VALUES (?, ?, ?, ?)").run(
      u.id, d > 0 ? "topup" : "withdraw", Math.abs(d), JSON.stringify({ by: "admin", admin: req.user.username })
    );
    return db.prepare("SELECT balance FROM users WHERE id = ?").get(u.id).balance;
  });

  const balance = tx();
  res.json({ ok: true, balance });
});

// ---- Static ----
const publicDir = path.join(__dirname, "public");
app.use(express.static(publicDir, { extensions: ["html"] }));

// SPA-ish fallback for "/" (serve index.html)
app.get("/", (req, res) => res.sendFile(path.join(publicDir, "index.html")));

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
