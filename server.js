require("dotenv").config();
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const QRCode = require("qrcode");
const { createClient } = require("@supabase/supabase-js");

const PORT = Number(process.env.PORT) || 3000;
const UPLOADS_DIR = path.join(__dirname, "uploads");
const STAFF_PASSWORD = process.env.STAFF_PASSWORD || "sklad2026";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin2026";
const COOKIE_NAME = "eventkg_session";
const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const BUCKET = "product-photos";

const SUPABASE_URL = process.env.SUPABASE_URL || "";
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("Задайте SUPABASE_URL и SUPABASE_SERVICE_ROLE_KEY в .env (см. .env.example).");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

function mapProduct(row) {
  let photos = row.photo_urls;
  if (!Array.isArray(photos)) {
    try {
      photos = typeof photos === "string" ? JSON.parse(photos || "[]") : [];
    } catch {
      photos = [];
    }
  }
  const cat = row.categories;
  const categoryName = cat && typeof cat === "object" && !Array.isArray(cat) && cat.name ? cat.name : "";
  return {
    id: row.id,
    name: row.name,
    sku: row.sku || "",
    unit: row.unit || "шт",
    category: categoryName,
    category_id: row.category_id,
    note: row.note || "",
    quantity: row.quantity,
    photos,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
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
  storage: multer.memoryStorage(),
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

function sanitizeSearch(q) {
  return String(q || "")
    .trim()
    .replace(/%/g, "")
    .replace(/,/g, " ")
    .slice(0, 100);
}

app.get("/api/categories", authStaff, async (_req, res) => {
  try {
    const { data, error } = await supabase.from("categories").select("id,name,created_at").order("name");
    if (error) throw error;
    res.json(data || []);
  } catch (e) {
    res.status(500).json({ error: e.message || "Ошибка БД" });
  }
});

app.post("/api/categories", authAdmin, async (req, res) => {
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  if (!name) return res.status(400).json({ error: "Укажите название категории" });
  try {
    const { data, error } = await supabase.from("categories").insert({ name }).select("id,name,created_at").single();
    if (error) {
      if (error.code === "23505") return res.status(409).json({ error: "Категория с таким именем уже есть" });
      throw error;
    }
    res.status(201).json(data);
  } catch (e) {
    res.status(500).json({ error: e.message || "Ошибка БД" });
  }
});

app.patch("/api/categories/:id", authAdmin, async (req, res) => {
  const id = req.params.id;
  const name = typeof req.body?.name === "string" ? req.body.name.trim() : "";
  if (!name) return res.status(400).json({ error: "Укажите название" });
  try {
    const { data, error } = await supabase
      .from("categories")
      .update({ name })
      .eq("id", id)
      .select("id,name,created_at")
      .single();
    if (error) {
      if (error.code === "23505") return res.status(409).json({ error: "Имя занято" });
      throw error;
    }
    if (!data) return res.status(404).json({ error: "Категория не найдена" });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message || "Ошибка БД" });
  }
});

app.delete("/api/categories/:id", authAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    await supabase.from("products").update({ category_id: null }).eq("category_id", id);
    const { error } = await supabase.from("categories").delete().eq("id", id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message || "Ошибка БД" });
  }
});

async function listProducts(searchRaw) {
  const q = sanitizeSearch(searchRaw);
  const select = "*, categories(name)";
  if (!q) {
    const { data, error } = await supabase.from("products").select(select).order("name");
    if (error) throw error;
    return (data || []).map(mapProduct);
  }
  const pattern = `%${q}%`;
  const { data: catRows, error: catErr } = await supabase.from("categories").select("id").ilike("name", pattern);
  if (catErr) throw catErr;
  const catIds = (catRows || []).map((c) => c.id);
  const orParts = [`name.ilike.${pattern}`, `sku.ilike.${pattern}`];
  if (catIds.length) orParts.push(`category_id.in.(${catIds.join(",")})`);
  const { data, error } = await supabase.from("products").select(select).or(orParts.join(",")).order("name");
  if (error) throw error;
  return (data || []).map(mapProduct);
}

app.get("/api/products", authStaff, async (req, res) => {
  try {
    const list = await listProducts(req.query.q);
    res.json(list);
  } catch (e) {
    res.status(500).json({ error: e.message || "Ошибка БД" });
  }
});

app.get("/api/products/:id", authStaff, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("products")
      .select("*, categories(name)")
      .eq("id", req.params.id)
      .maybeSingle();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: "Товар не найден" });
    res.json(mapProduct(data));
  } catch (e) {
    res.status(500).json({ error: e.message || "Ошибка БД" });
  }
});

app.post("/api/products", authAdmin, async (req, res) => {
  const { name, sku, unit, quantity, category_id, note } = req.body || {};
  if (!name || typeof name !== "string" || !name.trim()) {
    return res.status(400).json({ error: "Укажите название товара" });
  }
  const qty = Math.max(0, Math.floor(Number(quantity) || 0));
  const row = {
    name: name.trim(),
    sku: typeof sku === "string" ? sku.trim() : "",
    unit: typeof unit === "string" && unit.trim() ? unit.trim() : "шт",
    category_id: typeof category_id === "string" && category_id ? category_id : null,
    note: typeof note === "string" ? note.trim() : "",
    quantity: qty,
    photo_urls: [],
  };
  try {
    const { data, error } = await supabase.from("products").insert(row).select("*, categories(name)").single();
    if (error) throw error;
    res.status(201).json(mapProduct(data));
  } catch (e) {
    res.status(500).json({ error: e.message || "Ошибка БД" });
  }
});

app.patch("/api/products/:id", authAdmin, async (req, res) => {
  const id = req.params.id;
  const { name, sku, unit, category_id, note, quantity } = req.body || {};
  const patch = { updated_at: new Date().toISOString() };
  if (name !== undefined) {
    const t = String(name).trim();
    if (!t) return res.status(400).json({ error: "Название не может быть пустым" });
    patch.name = t;
  }
  if (sku !== undefined) patch.sku = String(sku).trim();
  if (unit !== undefined) patch.unit = String(unit).trim() || "шт";
  if (note !== undefined) patch.note = String(note).trim();
  if (category_id !== undefined) patch.category_id = category_id === null || category_id === "" ? null : String(category_id);
  if (quantity !== undefined) {
    const q = Math.max(0, Math.floor(Number(quantity)));
    if (Number.isNaN(q)) return res.status(400).json({ error: "Некорректное количество" });
    patch.quantity = q;
  }
  try {
    const { data, error } = await supabase
      .from("products")
      .update(patch)
      .eq("id", id)
      .select("*, categories(name)")
      .single();
    if (error) throw error;
    if (!data) return res.status(404).json({ error: "Товар не найден" });
    res.json(mapProduct(data));
  } catch (e) {
    res.status(500).json({ error: e.message || "Ошибка БД" });
  }
});

function publicObjectUrl(objectPath) {
  const base = SUPABASE_URL.replace(/\/$/, "");
  return `${base}/storage/v1/object/public/${BUCKET}/${objectPath}`;
}

function pathFromPublicPhotoUrl(url) {
  const marker = `/object/public/${BUCKET}/`;
  const i = String(url).indexOf(marker);
  if (i === -1) return null;
  return decodeURIComponent(String(url).slice(i + marker.length));
}

app.delete("/api/products/:id", authAdmin, async (req, res) => {
  const id = req.params.id;
  try {
    const { data: p, error: fe } = await supabase.from("products").select("photo_urls").eq("id", id).maybeSingle();
    if (fe) throw fe;
    if (!p) return res.status(404).json({ error: "Товар не найден" });
    const urls = Array.isArray(p.photo_urls) ? p.photo_urls : [];
    for (const u of urls) {
      const objectPath = pathFromPublicPhotoUrl(u);
      if (objectPath) await supabase.storage.from(BUCKET).remove([objectPath]);
    }
    const { error } = await supabase.from("products").delete().eq("id", id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message || "Ошибка БД" });
  }
});

app.post("/api/products/:id/photos", authAdmin, upload.array("photos", 6), async (req, res) => {
  const id = req.params.id;
  const files = Array.isArray(req.files) ? req.files : [];
  if (!files.length) return res.status(400).json({ error: "Нет файлов" });
  try {
    const { data: p, error: pe } = await supabase.from("products").select("photo_urls").eq("id", id).maybeSingle();
    if (pe) throw pe;
    if (!p) return res.status(404).json({ error: "Товар не найден" });
    let photos = Array.isArray(p.photo_urls) ? [...p.photo_urls] : [];
    const added = [];
    for (const f of files) {
      const ext = path.extname(f.originalname || "").toLowerCase() || ".jpg";
      const objectPath = `${id}/${crypto.randomUUID()}${ext}`;
      const { error: upErr } = await supabase.storage.from(BUCKET).upload(objectPath, f.buffer, {
        contentType: f.mimetype,
        upsert: false,
      });
      if (upErr) throw upErr;
      added.push(publicObjectUrl(objectPath));
    }
    photos = [...added, ...photos].slice(0, 10);
    const { data: updated, error: ue } = await supabase
      .from("products")
      .update({ photo_urls: photos, updated_at: new Date().toISOString() })
      .eq("id", id)
      .select("photo_urls")
      .single();
    if (ue) throw ue;
    res.json({ ok: true, photos: updated.photo_urls });
  } catch (e) {
    res.status(500).json({ error: e.message || "Ошибка загрузки" });
  }
});

app.delete("/api/products/:id/photos", authAdmin, async (req, res) => {
  const { url } = req.body || {};
  if (!url || typeof url !== "string") return res.status(400).json({ error: "Укажите url" });
  const id = req.params.id;
  try {
    const { data: p, error: pe } = await supabase.from("products").select("photo_urls").eq("id", id).maybeSingle();
    if (pe) throw pe;
    if (!p) return res.status(404).json({ error: "Товар не найден" });
    let photos = Array.isArray(p.photo_urls) ? p.photo_urls : [];
    const before = photos.length;
    photos = photos.filter((x) => x !== url);
    if (photos.length === before) return res.status(404).json({ error: "Фото не найдено" });
    const objectPath = pathFromPublicPhotoUrl(url);
    if (objectPath) await supabase.storage.from(BUCKET).remove([objectPath]);
    const { error: ue } = await supabase
      .from("products")
      .update({ photo_urls: photos, updated_at: new Date().toISOString() })
      .eq("id", id);
    if (ue) throw ue;
    res.json({ ok: true, photos });
  } catch (e) {
    res.status(500).json({ error: e.message || "Ошибка БД" });
  }
});

async function recordMovement({ productId, type, amount, userRole, note }) {
  const { error } = await supabase.from("stock_movements").insert({
    product_id: productId,
    type,
    amount,
    user_role: userRole,
    note: note || "",
  });
  if (error) throw error;
}

app.post("/api/stock/receive", authStaff, async (req, res) => {
  const { productId, amount, note } = req.body || {};
  if (!productId || typeof productId !== "string") return res.status(400).json({ error: "Укажите товар" });
  const n = Math.max(1, Math.floor(Number(amount) || 0));
  if (!n) return res.status(400).json({ error: "Укажите количество" });
  try {
    const { data: p, error: fe } = await supabase.from("products").select("quantity").eq("id", productId).maybeSingle();
    if (fe) throw fe;
    if (!p) return res.status(404).json({ error: "Товар не найден" });
    const newQty = p.quantity + n;
    const { data: updated, error: ue } = await supabase
      .from("products")
      .update({ quantity: newQty, updated_at: new Date().toISOString() })
      .eq("id", productId)
      .select("*, categories(name)")
      .single();
    if (ue) throw ue;
    await recordMovement({ productId, type: "receive", amount: n, userRole: req.session.role, note });
    res.json({ product: mapProduct(updated) });
  } catch (e) {
    res.status(500).json({ error: e.message || "Ошибка БД" });
  }
});

app.post("/api/stock/ship", authStaff, async (req, res) => {
  const { productId, amount, note } = req.body || {};
  if (!productId || typeof productId !== "string") return res.status(400).json({ error: "Укажите товар" });
  const n = Math.max(1, Math.floor(Number(amount) || 0));
  if (!n) return res.status(400).json({ error: "Укажите количество" });
  try {
    const { data: p, error: fe } = await supabase.from("products").select("quantity").eq("id", productId).maybeSingle();
    if (fe) throw fe;
    if (!p) return res.status(404).json({ error: "Товар не найден" });
    if (p.quantity < n) return res.status(400).json({ error: "Недостаточно на складе", quantity: p.quantity });
    const newQty = p.quantity - n;
    const { data: updated, error: ue } = await supabase
      .from("products")
      .update({ quantity: newQty, updated_at: new Date().toISOString() })
      .eq("id", productId)
      .select("*, categories(name)")
      .single();
    if (ue) throw ue;
    await recordMovement({ productId, type: "ship", amount: n, userRole: req.session.role, note });
    res.json({ product: mapProduct(updated) });
  } catch (e) {
    res.status(500).json({ error: e.message || "Ошибка БД" });
  }
});

app.get("/api/movements", authAdmin, async (_req, res) => {
  try {
    const { data: movements, error: me } = await supabase
      .from("stock_movements")
      .select("id,product_id,type,amount,user_role,note,at")
      .order("at", { ascending: false })
      .limit(200);
    if (me) throw me;
    const ids = [...new Set((movements || []).map((m) => m.product_id))];
    let nameById = {};
    if (ids.length) {
      const { data: prods, error: pe } = await supabase.from("products").select("id,name").in("id", ids);
      if (pe) throw pe;
      nameById = Object.fromEntries((prods || []).map((p) => [p.id, p.name]));
    }
    const list = (movements || []).map((m) => ({
      id: m.id,
      productId: m.product_id,
      type: m.type,
      amount: m.amount,
      userRole: m.user_role,
      note: m.note,
      at: m.at,
      productName: nameById[m.product_id] || "(удалён)",
    }));
    res.json(list);
  } catch (e) {
    res.status(500).json({ error: e.message || "Ошибка БД" });
  }
});

app.get("/api/products/:id/qr.svg", authStaff, async (req, res) => {
  try {
    const { data: p, error } = await supabase.from("products").select("id").eq("id", req.params.id).maybeSingle();
    if (error) throw error;
    if (!p) return res.status(404).send("Not found");
    const payload = JSON.stringify({ v: 1, id: p.id });
    const svg = await QRCode.toString(payload, { type: "svg", margin: 1, width: 256 });
    res.type("image/svg+xml").send(svg);
  } catch (e) {
    res.status(500).send(String(e.message));
  }
});

app.listen(PORT, () => {
  console.log(`Склад → http://localhost:${PORT} (Supabase)`);
});
