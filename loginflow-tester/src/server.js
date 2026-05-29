import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import Database from "better-sqlite3";
import * as OTPAuth from "otpauth";
import QRCode from "qrcode";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();

const port = Number(process.env.PORT || 8080);
const databasePath = process.env.DATABASE_PATH || path.join(__dirname, "..", "data", "loginflow.db");
const rpID = process.env.RP_ID || "localhost";
const publicOrigin = process.env.PUBLIC_ORIGIN || `http://localhost:${port}`;
const rpName = process.env.RP_NAME || "Login Flow Tester";
const idleShutdownSeconds = Number(process.env.IDLE_SHUTDOWN_SECONDS || 0);

fs.mkdirSync(path.dirname(databasePath), { recursive: true });

const db = new Database(databasePath);
db.pragma("journal_mode = WAL");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    username TEXT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_plain TEXT,
    password_hash TEXT,
    second_factor TEXT NOT NULL DEFAULT 'none',
    totp_secret TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS passkeys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    transports TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);
ensureColumn("users", "username", "TEXT");
ensureColumn("users", "password_plain", "TEXT");
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS users_username_unique ON users(username COLLATE NOCASE) WHERE username IS NOT NULL AND username != ''");

const challenges = new Map();
const logHistory = [];
let lastRequestAt = Date.now();
let server;

app.use(express.json({ limit: "1mb" }));
app.use((req, _res, next) => {
  if (req.path !== "/healthz") lastRequestAt = Date.now();
  next();
});
app.use(express.static(path.join(__dirname, "..", "public")));

function addServerLog(event, details = {}) {
  const entry = {
    ts: new Date().toISOString(),
    source: "server",
    event,
    details: redact(details),
  };
  logHistory.unshift(entry);
  logHistory.splice(200);
  console.log(JSON.stringify(entry));
  return entry;
}

function clearServerLogs() {
  logHistory.length = 0;
}

function redact(value) {
  if (Array.isArray(value)) return value.map(redact);
  if (!value || typeof value !== "object") return value;
  const out = {};
  for (const [key, val] of Object.entries(value)) {
    if (/password/i.test(key)) out[key] = "[redacted]";
    else out[key] = redact(val);
  }
  return out;
}

function createSession(res, userId) {
  const sessionId = crypto.randomUUID();
  challenges.set(`session:${sessionId}`, { userId, createdAt: Date.now() });
  res.cookie("loginflow_session", sessionId, {
    httpOnly: true,
    sameSite: "lax",
    secure: publicOrigin.startsWith("https://"),
    maxAge: 1000 * 60 * 60 * 2,
  });
}

function getSessionUser(req) {
  const sessionId = parseCookie(req.headers.cookie || "").loginflow_session;
  if (!sessionId) return null;
  const session = challenges.get(`session:${sessionId}`);
  if (!session) return null;
  return getUserById(session.userId);
}

function parseCookie(header) {
  return Object.fromEntries(
    header
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean)
      .map((part) => {
        const index = part.indexOf("=");
        return index === -1 ? [part, ""] : [part.slice(0, index), decodeURIComponent(part.slice(index + 1))];
      }),
  );
}

function ensureColumn(table, column, definition) {
  const columns = db.prepare(`PRAGMA table_info(${table})`).all().map((info) => info.name);
  if (!columns.includes(column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
  }
}

function verifyPassword(password, user) {
  if (user.password_plain !== null && user.password_plain !== undefined) {
    return password === user.password_plain;
  }
  if (!user.password_hash) return false;
  const stored = user.password_hash;
  const [scheme, salt, hash] = stored.split("$");
  if (scheme !== "scrypt" || !salt || !hash) return false;
  const candidate = crypto.scryptSync(password, salt, 64).toString("base64url");
  return crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(hash));
}

function getUserByEmail(email) {
  return db.prepare("SELECT * FROM users WHERE email = ? COLLATE NOCASE").get(email.trim());
}

function getUserByUsername(username) {
  return db.prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE").get(username.trim());
}

function getUserById(id) {
  return db.prepare("SELECT * FROM users WHERE id = ?").get(id);
}

function publicUser(user) {
  const passkeyCount = db.prepare("SELECT COUNT(*) AS count FROM passkeys WHERE user_id = ?").get(user.id).count;
  return {
    id: user.id,
    name: user.name,
    username: user.username || "",
    email: user.email,
    secondFactor: user.second_factor,
    hasTotp: Boolean(user.totp_secret),
    passkeyCount,
  };
}

function deleteUserArtifacts(userId) {
  const keysToDelete = [];
  for (const [key, value] of challenges.entries()) {
    if (value?.userId === userId || key === `totp-setup:${userId}` || key === `passkey-register:${userId}`) {
      keysToDelete.push(key);
    }
  }

  const removeUser = db.transaction((id) => {
    db.prepare("DELETE FROM passkeys WHERE user_id = ?").run(id);
    db.prepare("DELETE FROM users WHERE id = ?").run(id);
  });
  removeUser(userId);

  for (const key of keysToDelete) challenges.delete(key);
}

function normalizeSecondFactor(value) {
  return ["none", "totp", "passkey", "passkey-only"].includes(value) ? value : "none";
}

function randomBase32(length = 32) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let out = "";
  const bytes = crypto.randomBytes(length);
  for (const byte of bytes) out += alphabet[byte % alphabet.length];
  return out;
}

function base64urlToBytes(value) {
  return Buffer.from(value, "base64url");
}

function bytesToBase64url(value) {
  return Buffer.from(value).toString("base64url");
}

function makeTotp(secret, user) {
  return new OTPAuth.TOTP({
    issuer: "LoginFlowTester",
    label: user.email,
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secret),
  });
}

function requireFields(body, fields) {
  for (const field of fields) {
    if (typeof body[field] !== "string" || body[field].trim() === "") {
      const error = new Error(`Missing ${field}`);
      error.statusCode = 400;
      throw error;
    }
  }
}

app.get("/api/logs", (_req, res) => {
  res.json({ logs: logHistory });
});

app.post("/api/logs/clear", (_req, res) => {
  clearServerLogs();
  res.json({ cleared: true });
});

app.get("/api/debug/users", (_req, res) => {
  const users = db.prepare("SELECT * FROM users ORDER BY created_at DESC").all();
  const passkeys = db.prepare("SELECT * FROM passkeys ORDER BY created_at DESC").all();
  res.json({
    users: users.map((user) => ({
      id: user.id,
      name: user.name,
      username: user.username || "",
      email: user.email,
      password: user.password_plain ?? "[legacy hashed password unavailable as clear text]",
      secondFactor: user.second_factor,
      totpSecret: user.totp_secret || "",
      hasTotp: Boolean(user.totp_secret),
      passkeys: passkeys
        .filter((passkey) => passkey.user_id === user.id)
        .map((passkey) => ({
          credentialId: passkey.credential_id,
          publicKey: passkey.public_key,
          counter: passkey.counter,
          transports: JSON.parse(passkey.transports || "[]"),
          createdAt: passkey.created_at,
        })),
      createdAt: user.created_at,
    })),
  });
});

app.delete("/api/debug/users/:id", (req, res) => {
  const user = getUserById(req.params.id);
  if (!user) return res.status(404).json({ error: "User not found." });

  const passkeyCount = db.prepare("SELECT COUNT(*) AS count FROM passkeys WHERE user_id = ?").get(user.id).count;
  deleteUserArtifacts(user.id);
  addServerLog("debug user deleted", {
    user: publicUser(user),
    passkeyCount,
  });
  res.json({ deleted: true, user: publicUser(user) });
});

app.post("/api/register", async (req, res, next) => {
  try {
    requireFields(req.body, ["name", "username", "email", "password"]);
    const username = req.body.username.trim();
    const email = req.body.email.trim().toLowerCase();
    const existing = getUserByEmail(email);
    if (existing) {
      addServerLog("registration rejected", { email, reason: "email already exists" });
      return res.status(409).json({ error: "A user with that email already exists." });
    }
    if (getUserByUsername(username)) {
      addServerLog("registration rejected", { username, reason: "username already exists" });
      return res.status(409).json({ error: "A user with that username already exists." });
    }

    const id = crypto.randomUUID();
    const secondFactor = normalizeSecondFactor(req.body.secondFactor);
    db.prepare(
      "INSERT INTO users (id, name, username, email, password_plain, password_hash, second_factor) VALUES (?, ?, ?, ?, ?, ?, ?)",
    ).run(id, req.body.name.trim(), username, email, req.body.password, "[cleartext-debug]", secondFactor);

    const user = getUserById(id);
    createSession(res, id);
    addServerLog("registration created", {
      user: publicUser(user),
      passwordStorage: "clear-text",
      autocomplete: Boolean(req.body.autocomplete),
    });
    res.json({ user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/passkey-only/register/options", async (req, res, next) => {
  try {
    requireFields(req.body, ["name", "username", "email"]);
    const username = req.body.username.trim();
    const email = req.body.email.trim().toLowerCase();
    if (getUserByEmail(email)) {
      addServerLog("passkey-only registration rejected", { email, reason: "email already exists" });
      return res.status(409).json({ error: "A user with that email already exists." });
    }
    if (getUserByUsername(username)) {
      addServerLog("passkey-only registration rejected", { username, reason: "username already exists" });
      return res.status(409).json({ error: "A user with that username already exists." });
    }

    const userId = crypto.randomUUID();
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: Buffer.from(userId),
      userName: email,
      userDisplayName: req.body.name.trim(),
      attestationType: "none",
      authenticatorSelection: {
        residentKey: "required",
        requireResidentKey: true,
        userVerification: "preferred",
      },
    });

    const registrationToken = crypto.randomUUID();
    challenges.set(`passkey-only-register:${registrationToken}`, {
      userId,
      name: req.body.name.trim(),
      username,
      email,
      challenge: options.challenge,
      createdAt: Date.now(),
    });
    addServerLog("passkey-only registration options generated", {
      username,
      email,
      rpID,
      origin: publicOrigin,
      challenge: options.challenge,
    });
    res.json({ registrationToken, options });
  } catch (error) {
    next(error);
  }
});

app.post("/api/passkey-only/register/verify", async (req, res, next) => {
  try {
    requireFields(req.body, ["registrationToken"]);
    const pending = challenges.get(`passkey-only-register:${req.body.registrationToken}`);
    if (!pending) return res.status(400).json({ error: "Passkey-only registration challenge expired." });

    if (getUserByEmail(pending.email) || getUserByUsername(pending.username)) {
      challenges.delete(`passkey-only-register:${req.body.registrationToken}`);
      return res.status(409).json({ error: "That user was registered while this passkey prompt was open." });
    }

    const verification = await verifyRegistrationResponse({
      response: req.body.response,
      expectedChallenge: pending.challenge,
      expectedOrigin: publicOrigin,
      expectedRPID: rpID,
      requireUserVerification: false,
    });

    if (!verification.verified || !verification.registrationInfo?.credential) {
      addServerLog("passkey-only registration failed", { email: pending.email });
      return res.status(400).json({ error: "Passkey registration was not verified." });
    }

    db.prepare(
      "INSERT INTO users (id, name, username, email, password_plain, password_hash, second_factor) VALUES (?, ?, ?, ?, ?, ?, ?)",
    ).run(pending.userId, pending.name, pending.username, pending.email, "", "[passkey-only]", "passkey-only");

    const { credential } = verification.registrationInfo;
    db.prepare(
      "INSERT INTO passkeys (id, user_id, credential_id, public_key, counter, transports) VALUES (?, ?, ?, ?, ?, ?)",
    ).run(
      crypto.randomUUID(),
      pending.userId,
      credential.id,
      bytesToBase64url(credential.publicKey),
      credential.counter || 0,
      JSON.stringify(req.body.response?.response?.transports || credential.transports || []),
    );
    challenges.delete(`passkey-only-register:${req.body.registrationToken}`);

    const user = getUserById(pending.userId);
    createSession(res, user.id);
    addServerLog("passkey-only registration verified", {
      user: publicUser(user),
      credentialId: credential.id,
      transports: req.body.response?.response?.transports || credential.transports || [],
      counter: credential.counter || 0,
    });
    res.json({ verified: true, user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/login/password", (req, res, next) => {
  try {
    requireFields(req.body, ["identifier", "identifierType", "password"]);
    const identifierType = req.body.identifierType === "username" ? "username" : "email";
    const user = identifierType === "username"
      ? getUserByUsername(req.body.identifier)
      : getUserByEmail(req.body.identifier);
    if (!user || !verifyPassword(req.body.password, user)) {
      addServerLog("password login failed", { identifier: req.body.identifier, identifierType, reason: "invalid credentials" });
      return res.status(401).json({ error: "Invalid login or password." });
    }

    addServerLog("password verified", { user: publicUser(user), identifierType, autocomplete: Boolean(req.body.autocomplete) });
    if (user.second_factor === "none") {
      createSession(res, user.id);
      return res.json({ status: "complete", user: publicUser(user) });
    }

    const loginToken = crypto.randomUUID();
    challenges.set(`login:${loginToken}`, { userId: user.id, createdAt: Date.now() });
    res.json({
      status: "second_factor_required",
      loginToken,
      secondFactor: user.second_factor,
      user: publicUser(user),
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/totp/setup", async (req, res, next) => {
  try {
    const user = getSessionUser(req);
    if (!user) return res.status(401).json({ error: "Register or log in before setting up TOTP." });

    const secret = randomBase32();
    const totp = makeTotp(secret, user);
    const uri = totp.toString();
    const qrDataUrl = await QRCode.toDataURL(uri, { margin: 1, width: 240 });

    challenges.set(`totp-setup:${user.id}`, { secret, createdAt: Date.now() });
    addServerLog("totp setup generated", {
      email: user.email,
      secretPreview: `${secret.slice(0, 6)}...${secret.slice(-4)}`,
      uri,
    });
    res.json({
      secret,
      uri,
      qrDataUrl,
      issuer: "LoginFlowTester",
      account: user.email,
      digits: 6,
      period: 30,
      algorithm: "SHA1",
    });
  } catch (error) {
    next(error);
  }
});

app.post("/api/totp/confirm", (req, res, next) => {
  try {
    requireFields(req.body, ["code"]);
    const user = getSessionUser(req);
    if (!user) return res.status(401).json({ error: "Register or log in before confirming TOTP." });

    const pending = challenges.get(`totp-setup:${user.id}`);
    if (!pending) return res.status(400).json({ error: "No pending TOTP setup." });

    const totp = makeTotp(pending.secret, user);
    const delta = totp.validate({ token: req.body.code.replace(/\s+/g, ""), window: 1 });
    if (delta === null) {
      addServerLog("totp setup failed", { email: user.email, drift: null });
      return res.status(400).json({ error: "Invalid TOTP code." });
    }

    db.prepare("UPDATE users SET totp_secret = ?, second_factor = 'totp' WHERE id = ?").run(pending.secret, user.id);
    challenges.delete(`totp-setup:${user.id}`);
    const updated = getUserById(user.id);
    addServerLog("totp setup confirmed", { user: publicUser(updated), drift: delta });
    res.json({ verified: true, drift: delta, user: publicUser(updated) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/totp/login", (req, res, next) => {
  try {
    requireFields(req.body, ["loginToken", "code"]);
    const pending = challenges.get(`login:${req.body.loginToken}`);
    if (!pending) return res.status(400).json({ error: "Login challenge expired." });
    const user = getUserById(pending.userId);
    if (!user || !user.totp_secret) return res.status(400).json({ error: "User has no TOTP configured." });

    const delta = makeTotp(user.totp_secret, user).validate({
      token: req.body.code.replace(/\s+/g, ""),
      window: 1,
    });
    if (delta === null) {
      addServerLog("totp login failed", { email: user.email, drift: null });
      return res.status(401).json({ error: "Invalid TOTP code." });
    }

    challenges.delete(`login:${req.body.loginToken}`);
    createSession(res, user.id);
    addServerLog("totp login verified", { user: publicUser(user), drift: delta });
    res.json({ status: "complete", drift: delta, user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/passkey/register/options", async (req, res, next) => {
  try {
    const user = getSessionUser(req);
    if (!user) return res.status(401).json({ error: "Register or log in before adding a passkey." });
    const existing = db.prepare("SELECT * FROM passkeys WHERE user_id = ?").all(user.id);
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: Buffer.from(user.id),
      userName: user.email,
      userDisplayName: user.name,
      attestationType: "none",
      excludeCredentials: existing.map((credential) => ({
        id: credential.credential_id,
        transports: JSON.parse(credential.transports || "[]"),
      })),
      authenticatorSelection: {
        residentKey: "preferred",
        userVerification: "preferred",
      },
    });

    challenges.set(`passkey-register:${user.id}`, { challenge: options.challenge, createdAt: Date.now() });
    addServerLog("passkey registration options generated", {
      email: user.email,
      rpID,
      origin: publicOrigin,
      challenge: options.challenge,
    });
    res.json(options);
  } catch (error) {
    next(error);
  }
});

app.post("/api/passkey/register/verify", async (req, res, next) => {
  try {
    const user = getSessionUser(req);
    if (!user) return res.status(401).json({ error: "Register or log in before adding a passkey." });
    const pending = challenges.get(`passkey-register:${user.id}`);
    if (!pending) return res.status(400).json({ error: "Passkey registration challenge expired." });

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: pending.challenge,
      expectedOrigin: publicOrigin,
      expectedRPID: rpID,
      requireUserVerification: false,
    });

    if (!verification.verified || !verification.registrationInfo?.credential) {
      addServerLog("passkey registration failed", { email: user.email });
      return res.status(400).json({ error: "Passkey registration was not verified." });
    }

    const { credential } = verification.registrationInfo;
    db.prepare(
      "INSERT INTO passkeys (id, user_id, credential_id, public_key, counter, transports) VALUES (?, ?, ?, ?, ?, ?)",
    ).run(
      crypto.randomUUID(),
      user.id,
      credential.id,
      bytesToBase64url(credential.publicKey),
      credential.counter || 0,
      JSON.stringify(req.body.response?.transports || credential.transports || []),
    );
    db.prepare("UPDATE users SET second_factor = 'passkey' WHERE id = ?").run(user.id);
    challenges.delete(`passkey-register:${user.id}`);

    const updated = getUserById(user.id);
    addServerLog("passkey registration verified", {
      user: publicUser(updated),
      credentialId: credential.id,
      transports: req.body.response?.transports || credential.transports || [],
      counter: credential.counter || 0,
    });
    res.json({ verified: true, user: publicUser(updated) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/passkey/login/options", async (req, res, next) => {
  try {
    requireFields(req.body, ["loginToken"]);
    const pendingLogin = challenges.get(`login:${req.body.loginToken}`);
    if (!pendingLogin) return res.status(400).json({ error: "Login challenge expired." });
    const user = getUserById(pendingLogin.userId);
    const passkeys = db.prepare("SELECT * FROM passkeys WHERE user_id = ?").all(user.id);
    if (passkeys.length === 0) return res.status(400).json({ error: "User has no passkeys configured." });

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: passkeys.map((credential) => ({
        id: credential.credential_id,
        transports: JSON.parse(credential.transports || "[]"),
      })),
      userVerification: "preferred",
    });

    challenges.set(`passkey-login:${req.body.loginToken}`, {
      userId: user.id,
      challenge: options.challenge,
      createdAt: Date.now(),
    });
    addServerLog("passkey login options generated", {
      email: user.email,
      rpID,
      origin: publicOrigin,
      challenge: options.challenge,
      credentialIds: passkeys.map((credential) => credential.credential_id),
    });
    res.json(options);
  } catch (error) {
    next(error);
  }
});

app.post("/api/passkey-only/login/options", async (_req, res, next) => {
  try {
    const options = await generateAuthenticationOptions({
      rpID,
      userVerification: "preferred",
    });
    const loginToken = crypto.randomUUID();
    challenges.set(`passkey-only-login:${loginToken}`, {
      challenge: options.challenge,
      createdAt: Date.now(),
    });
    addServerLog("passkey-only login options generated", {
      rpID,
      origin: publicOrigin,
      challenge: options.challenge,
    });
    res.json({ loginToken, options });
  } catch (error) {
    next(error);
  }
});

app.post("/api/passkey-only/login/verify", async (req, res, next) => {
  try {
    requireFields(req.body, ["loginToken"]);
    const pending = challenges.get(`passkey-only-login:${req.body.loginToken}`);
    if (!pending) return res.status(400).json({ error: "Passkey-only login challenge expired." });

    const credentialId = req.body.response?.id || req.body.id;
    const credential = db.prepare("SELECT * FROM passkeys WHERE credential_id = ?").get(credentialId);
    if (!credential) {
      addServerLog("passkey-only login failed", { reason: "credential not found", credentialId });
      return res.status(401).json({ error: "Unknown passkey credential." });
    }

    const verification = await verifyAuthenticationResponse({
      response: req.body.response,
      expectedChallenge: pending.challenge,
      expectedOrigin: publicOrigin,
      expectedRPID: rpID,
      credential: {
        id: credential.credential_id,
        publicKey: base64urlToBytes(credential.public_key),
        counter: credential.counter,
        transports: JSON.parse(credential.transports || "[]"),
      },
      requireUserVerification: false,
    });

    if (!verification.verified) {
      addServerLog("passkey-only login failed", { credentialId, reason: "not verified" });
      return res.status(401).json({ error: "Passkey assertion was not verified." });
    }

    db.prepare("UPDATE passkeys SET counter = ? WHERE id = ?").run(
      verification.authenticationInfo?.newCounter ?? credential.counter,
      credential.id,
    );
    challenges.delete(`passkey-only-login:${req.body.loginToken}`);

    const user = getUserById(credential.user_id);
    createSession(res, user.id);
    addServerLog("passkey-only login verified", {
      user: publicUser(user),
      credentialId,
      previousCounter: credential.counter,
      newCounter: verification.authenticationInfo?.newCounter ?? credential.counter,
    });
    res.json({ status: "complete", user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.post("/api/passkey/login/verify", async (req, res, next) => {
  try {
    requireFields(req.body, ["loginToken"]);
    const pending = challenges.get(`passkey-login:${req.body.loginToken}`);
    if (!pending) return res.status(400).json({ error: "Passkey login challenge expired." });

    const credential = db.prepare("SELECT * FROM passkeys WHERE credential_id = ?").get(req.body.response?.id || req.body.id);
    if (!credential || credential.user_id !== pending.userId) {
      addServerLog("passkey login failed", { reason: "credential not found", credentialId: req.body.response?.id || req.body.id });
      return res.status(401).json({ error: "Unknown passkey credential." });
    }

    const verification = await verifyAuthenticationResponse({
      response: req.body.response || req.body,
      expectedChallenge: pending.challenge,
      expectedOrigin: publicOrigin,
      expectedRPID: rpID,
      credential: {
        id: credential.credential_id,
        publicKey: base64urlToBytes(credential.public_key),
        counter: credential.counter,
        transports: JSON.parse(credential.transports || "[]"),
      },
      requireUserVerification: false,
    });

    if (!verification.verified) {
      addServerLog("passkey login failed", { credentialId: credential.credential_id, reason: "not verified" });
      return res.status(401).json({ error: "Passkey assertion was not verified." });
    }

    db.prepare("UPDATE passkeys SET counter = ? WHERE id = ?").run(
      verification.authenticationInfo?.newCounter ?? credential.counter,
      credential.id,
    );
    challenges.delete(`passkey-login:${req.body.loginToken}`);
    challenges.delete(`login:${req.body.loginToken}`);

    const user = getUserById(pending.userId);
    createSession(res, user.id);
    addServerLog("passkey login verified", {
      user: publicUser(user),
      credentialId: credential.credential_id,
      previousCounter: credential.counter,
      newCounter: verification.authenticationInfo?.newCounter ?? credential.counter,
    });
    res.json({ status: "complete", user: publicUser(user) });
  } catch (error) {
    next(error);
  }
});

app.get("/api/me", (req, res) => {
  const user = getSessionUser(req);
  res.json({ user: user ? publicUser(user) : null });
});

app.get("/healthz", (_req, res) => {
  res.json({
    ok: true,
    idleShutdownSeconds,
    idleSeconds: Math.round((Date.now() - lastRequestAt) / 1000),
  });
});

app.get([
  "/",
  "/login",
  "/login-username",
  "/login-autocomplete",
  "/login-username-autocomplete",
  "/login-passkey",
  "/register",
  "/register-autocomplete",
  "/register-passkey",
], (_req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "index.html"));
});

app.use((error, _req, res, _next) => {
  const status = error.statusCode || 500;
  addServerLog("request error", { status, message: error.message, stack: process.env.NODE_ENV === "development" ? error.stack : undefined });
  res.status(status).json({ error: error.message || "Unexpected error." });
});

server = app.listen(port, () => {
  addServerLog("server started", { port, databasePath, rpID, publicOrigin });
});

if (idleShutdownSeconds > 0) {
  setInterval(() => {
    const idleSeconds = (Date.now() - lastRequestAt) / 1000;
    if (idleSeconds < idleShutdownSeconds) return;

    addServerLog("idle shutdown", { idleSeconds: Math.round(idleSeconds), idleShutdownSeconds });
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  }, Math.min(60, Math.max(5, Math.floor(idleShutdownSeconds / 6))) * 1000).unref();
}
