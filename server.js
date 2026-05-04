require("dotenv").config();
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const QRCode = require("qrcode");

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "database.json");
const UPLOADS_DIR = path.join(__dirname, "uploads");
const STAFF_PASSWORD = process.env.STAFF_PASSWORD || "sklad2026";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin2026";
const COOKIE_NAME = "eventkg_session";
const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

function ensureDb() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  if (!fs.existsSync(DB_PATH)) {
    const initial = {
      products: [],
      movements: [],
    };
    fs.writeFileSync(DB_PATH, JSON.stringify(initial, null, 2), "utf8");
  }
}

function readDb() {
  ensureDb();
  return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
}

function writeDb(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), "utf8");
}

function signSession(payload) {
  const secret = ADMIN_PASSWORD + STAFF_PASSWORD;
  const body = Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
  const sig = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  return `${body}.${sig}`;
}

function parseSession(cookieVal) {
  if (!cookieVal || typeof cookieVal !== "string") return null;
  const parts = cookieVal.split(".");
  if (parts.length !== 2) return null;
  const [body, sig] = parts;
  const secret = ADMIN_PASSWORD + STAFF_PASSWORD;
  const expected = crypto.createHmac("sha256", secret).update(body).digest("base64url");
  const a = Buffer.from(sig, "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (!payload.exp || payload.exp < Date.now()) return null;
    return payload;
  } catch {
    return null;
  }
}

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(UPLOADS_DIR, { fallthrough: false }));

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, UPLOADS_DIR),
    filename: (_req, file, cb) => {
      const ext = path.extname(file.originalname || "").toLowerCase();
      cb(null, `${crypto.randomUUID()}${ext || ""}`);
    },
  }),
  limits: { fileSize: 6 * 1024 * 1024, files: 6 },
  fileFilter: (_req, file, cb) => {
    const ok = ["image/jpeg", "image/png", "image/webp", "image/gif"].includes(file.mimetype);
    cb(ok ? null : new Error("Разрешены только изображения (jpg/png/webp/gif)"), ok);
  },
});

function authStaff(req, res, next) {
  const s = parseSession(req.cookies[COOKIE_NAME]);
  if (!s || (s.role !== "staff" && s.role !== "admin")) {
    return res.status(401).json({ error: "Требуется вход" });
  }
  req.session = s;
  next();
}

function authAdmin(req, res, next) {
  const s = parseSession(req.cookies[COOKIE_NAME]);
  if (!s || s.role !== "admin") {
    return res.status(401).json({ error: "Нужны права администратора" });
  }
  req.session = s;
  next();
}

app.post("/api/auth/login", (req, res) => {
  const { password, asAdmin } = req.body || {};
  if (typeof password !== "string") {
    return res.status(400).json({ error: "Укажите пароль" });
  }
  if (asAdmin) {
    if (password !== ADMIN_PASSWORD) {
      return res.status(401).json({ error: "Неверный пароль администратора" });
    }
    const token = signSession({
      role: "admin",
      exp: Date.now() + SESSION_MAX_AGE_MS,
    });
    res.cookie(COOKIE_NAME, token, {
      httpOnly: true,
      sameSite: "lax",
      maxAge: SESSION_MAX_AGE_MS,
    });
    return res.json({ ok: true, role: "admin" });
  }
  if (password !== STAFF_PASSWORD) {
    return res.status(401).json({ error: "Неверный пароль" });
  }
  const token = signSession({
    role: "staff",
    exp: Date.now() + SESSION_MAX_AGE_MS,
  });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: "lax",
    maxAge: SESSION_MAX_AGE_MS,
  });
  return res.json({ ok: true, role: "staff" });
});

app.post("/api/auth/logout", (_req, res) => {
  res.clearCookie(COOKIE_NAME);
  res.json({ ok: true });
});

app.get("/api/auth/me", (req, res) => {
  const s = parseSession(req.cookies[COOKIE_NAME]);
  if (!s) return res.json({ role: null });
  return res.json({ role: s.role });
});

app.get("/api/products", authStaff, (_req, res) => {
  const db = readDb();
  res.json(db.products);
});

app.get("/api/products/:id", authStaff, (req, res) => {
  const db = readDb();
  const p = db.products.find((x) => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: "Товар не найден" });
  res.json(p);
});

app.post("/api/products", authAdmin, (req, res) => {
  const { name, sku, unit, quantity, category, note } = req.body || {};
  if (!name || typeof name !== "string" || !name.trim()) {
    return res.status(400).json({ error: "Укажите название товара" });
  }
  const db = readDb();
  const id = crypto.randomUUID();
  const qty = Math.max(0, Math.floor(Number(quantity) || 0));
  const product = {
    id,
    name: name.trim(),
    sku: typeof sku === "string" ? sku.trim() : "",
    unit: typeof unit === "string" && unit.trim() ? unit.trim() : "шт",
    category: typeof category === "string" ? category.trim() : "",
    note: typeof note === "string" ? note.trim() : "",
    quantity: qty,
    photos: [],
    createdAt: new Date().toISOString(),
  };
  db.products.push(product);
  writeDb(db);
  res.status(201).json(product);
});

app.patch("/api/products/:id", authAdmin, (req, res) => {
  const db = readDb();
  const idx = db.products.findIndex((x) => x.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Товар не найден" });
  const { name, sku, unit, category, note } = req.body || {};
  const p = db.products[idx];
  if (name !== undefined) p.name = String(name).trim() || p.name;
  if (sku !== undefined) p.sku = String(sku).trim();
  if (unit !== undefined) p.unit = String(unit).trim() || p.unit;
  if (category !== undefined) p.category = String(category).trim();
  if (note !== undefined) p.note = String(note).trim();
  p.updatedAt = new Date().toISOString();
  db.products[idx] = p;
  writeDb(db);
  res.json(p);
});

app.delete("/api/products/:id", authAdmin, (req, res) => {
  const db = readDb();
  const idx = db.products.findIndex((x) => x.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: "Товар не найден" });
  const p = db.products[idx];
  if (Array.isArray(p.photos)) {
    for (const rel of p.photos) {
      const safe = String(rel || "");
      const full = path.join(__dirname, safe.startsWith("/") ? safe.slice(1) : safe);
      if (full.startsWith(UPLOADS_DIR) && fs.existsSync(full)) {
        try {
          fs.unlinkSync(full);
        } catch {}
      }
    }
  }
  db.products.splice(idx, 1);
  writeDb(db);
  res.json({ ok: true });
});

app.post("/api/products/:id/photos", authAdmin, upload.array("photos", 6), (req, res) => {
  const db = readDb();
  const p = db.products.find((x) => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: "Товар не найден" });
  if (!Array.isArray(p.photos)) p.photos = [];
  const files = Array.isArray(req.files) ? req.files : [];
  const added = files.map((f) => `/uploads/${f.filename}`);
  p.photos.unshift(...added);
  p.photos = p.photos.slice(0, 10);
  p.updatedAt = new Date().toISOString();
  writeDb(db);
  res.json({ ok: true, photos: p.photos });
});

app.delete("/api/products/:id/photos", authAdmin, (req, res) => {
  const { url } = req.body || {};
  if (!url || typeof url !== "string") return res.status(400).json({ error: "Укажите url" });
  const db = readDb();
  const p = db.products.find((x) => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: "Товар не найден" });
  if (!Array.isArray(p.photos)) p.photos = [];
  const before = p.photos.length;
  p.photos = p.photos.filter((x) => x !== url);
  if (p.photos.length === before) return res.status(404).json({ error: "Фото не найдено" });
  const safe = String(url);
  const full = path.join(__dirname, safe.startsWith("/") ? safe.slice(1) : safe);
  if (full.startsWith(UPLOADS_DIR) && fs.existsSync(full)) {
    try {
      fs.unlinkSync(full);
    } catch {}
  }
  p.updatedAt = new Date().toISOString();
  writeDb(db);
  res.json({ ok: true, photos: p.photos });
});

function recordMovement(db, { productId, type, amount, userRole, note }) {
  db.movements.unshift({
    id: crypto.randomUUID(),
    productId,
    type,
    amount,
    userRole,
    note: note || "",
    at: new Date().toISOString(),
  });
  db.movements = db.movements.slice(0, 2000);
}

app.post("/api/stock/receive", authStaff, (req, res) => {
  const { productId, amount, note } = req.body || {};
  if (!productId || typeof productId !== "string") {
    return res.status(400).json({ error: "Укажите товар" });
  }
  const n = Math.max(1, Math.floor(Number(amount) || 0));
  if (!n) return res.status(400).json({ error: "Укажите количество" });
  const db = readDb();
  const p = db.products.find((x) => x.id === productId);
  if (!p) return res.status(404).json({ error: "Товар не найден" });
  p.quantity += n;
  p.updatedAt = new Date().toISOString();
  recordMovement(db, {
    productId,
    type: "receive",
    amount: n,
    userRole: req.session.role,
    note,
  });
  writeDb(db);
  res.json({ product: p });
});

app.post("/api/stock/ship", authStaff, (req, res) => {
  const { productId, amount, note } = req.body || {};
  if (!productId || typeof productId !== "string") {
    return res.status(400).json({ error: "Укажите товар" });
  }
  const n = Math.max(1, Math.floor(Number(amount) || 0));
  if (!n) return res.status(400).json({ error: "Укажите количество" });
  const db = readDb();
  const p = db.products.find((x) => x.id === productId);
  if (!p) return res.status(404).json({ error: "Товар не найден" });
  if (p.quantity < n) {
    return res.status(400).json({ error: "Недостаточно на складе", quantity: p.quantity });
  }
  p.quantity -= n;
  p.updatedAt = new Date().toISOString();
  recordMovement(db, {
    productId,
    type: "ship",
    amount: n,
    userRole: req.session.role,
    note,
  });
  writeDb(db);
  res.json({ product: p });
});

app.get("/api/movements", authAdmin, (_req, res) => {
  const db = readDb();
  const list = db.movements.slice(0, 200).map((m) => {
    const p = db.products.find((x) => x.id === m.productId);
    return { ...m, productName: p ? p.name : "(удалён)" };
  });
  res.json(list);
});

app.get("/api/products/:id/qr.svg", authStaff, async (req, res) => {
  const db = readDb();
  const p = db.products.find((x) => x.id === req.params.id);
  if (!p) return res.status(404).send("Not found");
  const payload = JSON.stringify({ v: 1, id: p.id });
  try {
    const svg = await QRCode.toString(payload, { type: "svg", margin: 1, width: 256 });
    res.type("image/svg+xml").send(svg);
  } catch (e) {
    res.status(500).send(String(e.message));
  }
});

ensureDb();
app.listen(PORT, () => {
  console.log(`event.kg inventory → http://localhost:${PORT}`);
});
