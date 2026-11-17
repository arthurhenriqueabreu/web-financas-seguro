import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";

const filename = resolve(process.env.DB_PATH || "data/financas.sqlite");
mkdirSync(dirname(filename), { recursive: true });
export const db = new DatabaseSync(filename);
db.exec(`
  PRAGMA foreign_keys = ON;
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    can_view INTEGER NOT NULL DEFAULT 1,
    can_add INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('income', 'expense')),
    UNIQUE(owner_id, name, type)
  );
  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_by INTEGER NOT NULL REFERENCES users(id),
    category_id INTEGER NOT NULL REFERENCES categories(id),
    type TEXT NOT NULL CHECK(type IN ('income', 'expense')),
    amount_cents INTEGER NOT NULL CHECK(amount_cents > 0),
    description TEXT NOT NULL,
    occurred_on TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS receipts (
    transaction_id INTEGER PRIMARY KEY REFERENCES transactions(id) ON DELETE CASCADE,
    mime TEXT NOT NULL,
    original_name TEXT NOT NULL,
    content BLOB NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_transactions_owner_date ON transactions(owner_id, occurred_on DESC, id DESC);
`);

export function ownerId(user) {
  return user.parent_id ?? user.id;
}

export function seedCategories(owner) {
  const insert = db.prepare(
    "INSERT OR IGNORE INTO categories (owner_id, name, type) VALUES (?, ?, ?)",
  );
  for (const name of ["Salário", "Freelance", "Outros"])
    insert.run(owner, name, "income");
  for (const name of [
    "Alimentação",
    "Moradia",
    "Transporte",
    "Saúde",
    "Educação",
    "Lazer",
    "Outros",
  ])
    insert.run(owner, name, "expense");
}
