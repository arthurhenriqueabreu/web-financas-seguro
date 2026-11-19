import express from "express";
import helmet from "helmet";
import bcrypt from "bcryptjs";
import multer from "multer";
import { rateLimit } from "express-rate-limit";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { resolve } from "node:path";
import { db, ownerId, seedCategories } from "./db.js";

const app = express();
const production = process.env.NODE_ENV === "production";
if (process.env.TRUST_PROXY === "1") app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(
  helmet({
    strictTransportSecurity: production,
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        objectSrc: ["'none'"],
        baseUri: ["'none'"],
        formAction: ["'self'"],
        upgradeInsecureRequests: production ? [] : null,
      },
    },
  }),
);
app.use(express.json({ limit: "32kb" }));
app.use(express.urlencoded({ extended: false, limit: "32kb" }));

const cookieName = production ? "__Host-financas" : "financas_session";
const hash = (value) => createHash("sha256").update(value).digest("hex");
const token = () => randomBytes(32).toString("base64url");
const fail = (res, status, message) =>
  res.status(status).json({ error: message });
const text = (value, max) =>
  typeof value === "string" ? value.trim().slice(0, max + 1) : "";
const emailValid = (value) =>
  /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length <= 254;
const dateValid = (value) =>
  typeof value === "string" &&
  /^\d{4}-\d{2}-\d{2}$/.test(value) &&
  !Number.isNaN(Date.parse(`${value}T00:00:00Z`)) &&
  new Date(`${value}T00:00:00Z`).toISOString().slice(0, 10) === value;
const safeEqual = (a, b) =>
  typeof a === "string" &&
  typeof b === "string" &&
  a.length === b.length &&
  timingSafeEqual(Buffer.from(a), Buffer.from(b));

function readCookie(req) {
  const match = (req.headers.cookie || "")
    .split(";")
    .map((s) => s.trim())
    .find((s) => s.startsWith(`${cookieName}=`));
  return match ? match.slice(cookieName.length + 1) : null;
}
function setCookie(res, value, maxAge) {
  const parts = [
    `${cookieName}=${value}`,
    "HttpOnly",
    "SameSite=Strict",
    "Path=/",
    `Max-Age=${maxAge}`,
  ];
  if (production) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}
function createSession(res, userId) {
  const raw = token();
  const csrf = token();
  db.prepare(
    "INSERT INTO sessions (token_hash, user_id, csrf_token, expires_at) VALUES (?, ?, ?, ?)",
  ).run(hash(raw), userId, csrf, Date.now() + 7 * 86400000);
  setCookie(res, raw, 7 * 86400);
  return csrf;
}
function authenticate(req, res, next) {
  const raw = readCookie(req);
  if (!raw) return fail(res, 401, "Faça login para continuar.");
  const session = db
    .prepare(
      `SELECT s.csrf_token, s.expires_at, u.id, u.parent_id, u.name, u.email, u.can_view, u.can_add
    FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?`,
    )
    .get(hash(raw));
  if (!session || session.expires_at < Date.now())
    return fail(res, 401, "Sessão expirada. Faça login novamente.");
  req.user = session;
  next();
}
function csrf(req, res, next) {
  if (!safeEqual(req.get("x-csrf-token"), req.user.csrf_token))
    return fail(res, 403, "Token CSRF inválido. Atualize a página.");
  next();
}
function parentOnly(req, res, next) {
  if (req.user.parent_id !== null)
    return fail(res, 403, "Apenas o responsável pode fazer isso.");
  next();
}
function canView(req, res, next) {
  if (!req.user.can_view)
    return fail(res, 403, "Acesso ao histórico desativado pelo responsável.");
  next();
}
function canAdd(req, res, next) {
  if (!req.user.can_add)
    return fail(
      res,
      403,
      "Registro de lançamentos desativado pelo responsável.",
    );
  next();
}
// Confere a origem inclusive no login/cadastro, antes da sessão existir.
app.use("/api", (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  const origin = req.get("origin");
  const host = req.get("host");
  const expected = `${req.protocol}://${host}`;
  if (origin && origin !== expected) return fail(res, 403, "Origem inválida.");
  if (!origin && req.get("sec-fetch-site") === "cross-site")
    return fail(res, 403, "Origem inválida.");
  next();
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15,
  standardHeaders: "draft-8",
  legacyHeaders: false,
  message: { error: "Muitas tentativas. Aguarde 15 minutos." },
});
app.post("/api/register", authLimiter, (req, res) => {
  const name = text(req.body.name, 80);
  const email = text(req.body.email, 254).toLowerCase();
  const password = req.body.password;
  if (
    !name ||
    name.length > 80 ||
    !emailValid(email) ||
    typeof password !== "string" ||
    password.length < 12 ||
    password.length > 128
  )
    return fail(
      res,
      400,
      "Informe nome, e-mail válido e senha de 12 a 128 caracteres.",
    );
  if (db.prepare("SELECT id FROM users WHERE email = ?").get(email))
    return fail(res, 409, "E-mail já cadastrado.");
  const result = db
    .prepare("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)")
    .run(name, email, bcrypt.hashSync(password, 12));
  seedCategories(result.lastInsertRowid);
  const csrfToken = createSession(res, result.lastInsertRowid);
  res.status(201).json({ csrfToken });
});
app.post("/api/login", authLimiter, (req, res) => {
  const email = text(req.body.email, 254).toLowerCase();
  const password = req.body.password;
  const user = emailValid(email)
    ? db
        .prepare("SELECT id, password_hash FROM users WHERE email = ?")
        .get(email)
    : null;
  if (
    !user ||
    typeof password !== "string" ||
    !bcrypt.compareSync(password, user.password_hash)
  )
    return fail(res, 401, "Credenciais inválidas.");
  const old = readCookie(req);
  if (old)
    db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(hash(old));
  const csrfToken = createSession(res, user.id);
  res.json({ csrfToken });
});
app.get("/api/me", authenticate, (req, res) => {
  const { id, parent_id, name, email, can_view, can_add, csrf_token } =
    req.user;
  res.json({
    id,
    parentId: parent_id,
    name,
    email,
    canView: !!can_view,
    canAdd: !!can_add,
    csrfToken: csrf_token,
  });
});
app.post("/api/logout", authenticate, csrf, (req, res) => {
  db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(
    hash(readCookie(req)),
  );
  setCookie(res, "", 0);
  res.status(204).end();
});

app.get("/api/categories", authenticate, (req, res) => {
  res.json(
    db
      .prepare(
        "SELECT id, name, type FROM categories WHERE owner_id = ? ORDER BY type, name",
      )
      .all(ownerId(req.user)),
  );
});
app.post("/api/categories", authenticate, csrf, parentOnly, (req, res) => {
  const name = text(req.body.name, 40);
  const type = req.body.type;
  if (!name || name.length > 40 || !["income", "expense"].includes(type))
    return fail(res, 400, "Categoria inválida.");
  try {
    const result = db
      .prepare("INSERT INTO categories (owner_id, name, type) VALUES (?, ?, ?)")
      .run(req.user.id, name, type);
    res.status(201).json({ id: Number(result.lastInsertRowid), name, type });
  } catch (error) {
    if (error.code?.startsWith("SQLITE_CONSTRAINT"))
      return fail(res, 409, "Categoria já existe.");
    throw error;
  }
});

app.get("/api/transactions", authenticate, canView, (req, res) => {
  const type = req.query.type;
  const month = req.query.month;
  if (type && !["income", "expense"].includes(type))
    return fail(res, 400, "Filtro inválido.");
  if (month && !/^\d{4}-(0[1-9]|1[0-2])$/.test(month))
    return fail(res, 400, "Mês inválido.");
  const where = ["t.owner_id = ?"];
  const args = [ownerId(req.user)];
  if (type) {
    where.push("t.type = ?");
    args.push(type);
  }
  if (month) {
    where.push("substr(t.occurred_on, 1, 7) = ?");
    args.push(month);
  }
  const rows = db
    .prepare(
      `SELECT t.id, t.type, t.amount_cents, t.description, t.occurred_on, t.created_by,
    c.name AS category, u.name AS author, r.transaction_id IS NOT NULL AS has_receipt
    FROM transactions t JOIN categories c ON c.id = t.category_id JOIN users u ON u.id = t.created_by
    LEFT JOIN receipts r ON r.transaction_id = t.id WHERE ${where.join(" AND ")}
    ORDER BY t.occurred_on DESC, t.id DESC LIMIT 500`,
    )
    .all(...args);
  const summary = db
    .prepare(
      `SELECT
    COALESCE(SUM(CASE WHEN type = 'income' THEN amount_cents ELSE 0 END), 0) AS income,
    COALESCE(SUM(CASE WHEN type = 'expense' THEN amount_cents ELSE 0 END), 0) AS expense
    FROM transactions WHERE owner_id = ?`,
    )
    .get(ownerId(req.user));
  res.json({
    rows,
    summary: { ...summary, balance: summary.income - summary.expense },
  });
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 1, fields: 6 },
});
function detectedMime(buffer) {
  if (!buffer) return null;
  if (buffer.subarray(0, 5).toString() === "%PDF-") return "application/pdf";
  if (
    buffer.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))
  )
    return "image/png";
  if (buffer.subarray(0, 3).equals(Buffer.from([255, 216, 255])))
    return "image/jpeg";
  if (
    buffer.subarray(0, 4).toString() === "RIFF" &&
    buffer.subarray(8, 12).toString() === "WEBP"
  )
    return "image/webp";
  return null;
}
app.post(
  "/api/transactions",
  authenticate,
  csrf,
  canAdd,
  upload.single("receipt"),
  (req, res) => {
    const type = req.body.type;
    const amount = Number(req.body.amountCents);
    const categoryId = Number(req.body.categoryId);
    const description = text(req.body.description, 160);
    const occurredOn = req.body.occurredOn;
    if (
      !["income", "expense"].includes(type) ||
      !Number.isSafeInteger(amount) ||
      amount < 1 ||
      amount > 1e11 ||
      !Number.isSafeInteger(categoryId) ||
      !description ||
      description.length > 160 ||
      !dateValid(occurredOn)
    )
      return fail(res, 400, "Confira os dados do lançamento.");
    const owner = ownerId(req.user);
    const category = db
      .prepare(
        "SELECT id FROM categories WHERE id = ? AND owner_id = ? AND type = ?",
      )
      .get(categoryId, owner, type);
    if (!category) return fail(res, 400, "Categoria inválida.");
    const file = req.file;
    const mime = file ? detectedMime(file.buffer) : null;
    if (file && (!mime || mime !== file.mimetype))
      return fail(res, 400, "Anexe PDF, PNG, JPEG ou WebP válido.");
    db.exec("BEGIN");
    try {
      const result = db
        .prepare(
          `INSERT INTO transactions (owner_id, created_by, category_id, type, amount_cents, description, occurred_on)
      VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          owner,
          req.user.id,
          categoryId,
          type,
          amount,
          description,
          occurredOn,
        );
      if (file)
        db.prepare(
          "INSERT INTO receipts (transaction_id, mime, original_name, content) VALUES (?, ?, ?, ?)",
        ).run(
          result.lastInsertRowid,
          mime,
          text(file.originalname, 120) || "comprovante",
          file.buffer,
        );
      db.exec("COMMIT");
      res.status(201).json({ id: Number(result.lastInsertRowid) });
    } catch (error) {
      db.exec("ROLLBACK");
      throw error;
    }
  },
);
app.get("/api/transactions/:id/receipt", authenticate, canView, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id))
    return fail(res, 404, "Comprovante não encontrado.");
  const receipt = db
    .prepare(
      `SELECT r.mime, r.content FROM receipts r JOIN transactions t ON t.id = r.transaction_id
    WHERE t.id = ? AND t.owner_id = ?`,
    )
    .get(id, ownerId(req.user));
  if (!receipt) return fail(res, 404, "Comprovante não encontrado.");
  res.set({
    "Content-Type": receipt.mime,
    "Content-Disposition": `attachment; filename="comprovante-${id}.${receipt.mime === "application/pdf" ? "pdf" : receipt.mime.split("/")[1]}"`,
    "Cache-Control": "private, no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.send(Buffer.from(receipt.content));
});
app.delete(
  "/api/transactions/:id",
  authenticate,
  csrf,
  parentOnly,
  (req, res) => {
    const id = Number(req.params.id);
    if (!Number.isSafeInteger(id))
      return fail(res, 404, "Lançamento não encontrado.");
    const result = db
      .prepare("DELETE FROM transactions WHERE id = ? AND owner_id = ?")
      .run(id, req.user.id);
    if (!result.changes) return fail(res, 404, "Lançamento não encontrado.");
    res.status(204).end();
  },
);

app.get("/api/children", authenticate, parentOnly, (req, res) => {
  res.json(
    db
      .prepare(
        "SELECT id, name, email, can_view, can_add FROM users WHERE parent_id = ? ORDER BY name",
      )
      .all(req.user.id),
  );
});
app.post("/api/children", authenticate, csrf, parentOnly, (req, res) => {
  const name = text(req.body.name, 80);
  const email = text(req.body.email, 254).toLowerCase();
  const password = req.body.password;
  const canViewValue = req.body.canView === true ? 1 : 0;
  const canAddValue = req.body.canAdd === true ? 1 : 0;
  if (
    !name ||
    name.length > 80 ||
    !emailValid(email) ||
    typeof password !== "string" ||
    password.length < 12 ||
    password.length > 128
  )
    return fail(
      res,
      400,
      "Informe nome, e-mail válido e senha de 12 a 128 caracteres.",
    );
  if (db.prepare("SELECT id FROM users WHERE email = ?").get(email))
    return fail(res, 409, "E-mail já cadastrado.");
  const result = db
    .prepare(
      `INSERT INTO users (parent_id, name, email, password_hash, can_view, can_add)
    VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .run(
      req.user.id,
      name,
      email,
      bcrypt.hashSync(password, 12),
      canViewValue,
      canAddValue,
    );
  res.status(201).json({ id: Number(result.lastInsertRowid) });
});
app.patch("/api/children/:id", authenticate, csrf, parentOnly, (req, res) => {
  const id = Number(req.params.id);
  if (
    !Number.isSafeInteger(id) ||
    typeof req.body.canView !== "boolean" ||
    typeof req.body.canAdd !== "boolean"
  )
    return fail(res, 400, "Permissões inválidas.");
  const result = db
    .prepare(
      "UPDATE users SET can_view = ?, can_add = ? WHERE id = ? AND parent_id = ?",
    )
    .run(Number(req.body.canView), Number(req.body.canAdd), id, req.user.id);
  if (!result.changes) return fail(res, 404, "Conta não encontrada.");
  res.json({ ok: true });
});

app.use("/api", (req, res) => fail(res, 404, "Rota não encontrada."));
app.use(
  express.static(resolve("public"), {
    extensions: ["html"],
    maxAge: production ? "1h" : 0,
  }),
);
app.use((error, req, res, next) => {
  if (error instanceof multer.MulterError)
    return fail(
      res,
      400,
      error.code === "LIMIT_FILE_SIZE"
        ? "Arquivo acima de 5 MB."
        : "Envio inválido.",
    );
  console.error(error);
  if (res.headersSent) return next(error);
  fail(res, 500, "Erro interno. Tente novamente.");
});

const port = Number(process.env.PORT || 3000);
if (process.env.NODE_ENV !== "test")
  app.listen(port, () =>
    console.log(`Finanças Seguras: http://localhost:${port}`),
  );
export { app };
