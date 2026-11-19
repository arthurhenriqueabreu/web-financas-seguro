import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = mkdtempSync(join(tmpdir(), "financas-test-"));
process.env.DB_PATH = join(dir, "test.sqlite");
process.env.NODE_ENV = "test";
const { app } = await import("../src/server.js");
const { db } = await import("../src/db.js");
const server = app.listen(0);
await new Promise((resolve) => server.once("listening", resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const PASSWORD = "senha-muito-forte-123";

async function request(path, { method = "GET", body, session } = {}) {
  const response = await fetch(`${base}/api${path}`, {
    method,
    headers: {
      ...(session ? { Cookie: session.cookie, "x-csrf-token": session.csrf } : {}),
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return {
    status: response.status,
    data: response.status === 204 ? null : await response.json().catch(() => null),
    cookie: response.headers.get("set-cookie")?.split(";")[0],
  };
}
async function register(name, email) {
  const r = await request("/register", {
    method: "POST",
    body: { name, email, password: PASSWORD },
  });
  assert.equal(r.status, 201);
  return { cookie: r.cookie, csrf: r.data.csrfToken };
}
const entry = (type, categoryId, amountCents, description) => ({
  type,
  categoryId,
  amountCents,
  description,
  occurredOn: "2026-11-10",
});

test("filtro e total por categoria", async () => {
  try {
    const parent = await register("Pai", "pai@example.com");
    const cats = (await request("/categories", { session: parent })).data;
    const food = cats.find((c) => c.type === "expense" && c.name === "Alimentação");
    const home = cats.find((c) => c.type === "expense" && c.name === "Moradia");
    for (const [cat, value] of [[food, 1000], [food, 500], [home, 3000]]) {
      const r = await request("/transactions", {
        method: "POST",
        session: parent,
        body: entry("expense", cat.id, value, "Teste"),
      });
      assert.equal(r.status, 201);
    }
    const filtered = await request(`/transactions?categoryId=${food.id}`, {
      session: parent,
    });
    assert.equal(filtered.data.rows.length, 2);
    const totals = Object.fromEntries(
      (await request("/transactions", { session: parent })).data.byCategory.map(
        (c) => [c.category, c.total],
      ),
    );
    assert.equal(totals["Alimentação"], 1500);
    assert.equal(totals["Moradia"], 3000);
    assert.equal(
      (await request("/transactions?categoryId=abc", { session: parent })).status,
      400,
    );
    // A categoria de outra família não retorna lançamentos.
    const other = await register("Outro", "outro@example.com");
    const leak = await request(`/transactions?categoryId=${food.id}`, {
      session: other,
    });
    assert.equal(leak.data.rows.length, 0);

    // Gestão de contas de filhos: senha, remoção e isolamento.
    const created = await request("/children", {
      method: "POST",
      session: parent,
      body: { name: "Filho", email: "filho@example.com", password: PASSWORD, canView: true, canAdd: true },
    });
    assert.equal(created.status, 201);
    const childId = created.data.id;
    const login = await request("/login", {
      method: "POST",
      body: { email: "filho@example.com", password: PASSWORD },
    });
    const child = { cookie: login.cookie, csrf: login.data.csrfToken };
    const childTx = await request("/transactions", {
      method: "POST",
      session: child,
      body: entry("expense", food.id, 700, "Do filho"),
    });
    assert.equal(childTx.status, 201);
    // Filho não gerencia contas.
    assert.equal(
      (await request(`/children/${childId}`, { method: "DELETE", session: child })).status,
      403,
    );
    // Outro responsável não mexe na conta do filho (IDOR).
    assert.equal(
      (await request(`/children/${childId}`, { method: "DELETE", session: other })).status,
      404,
    );
    assert.equal(
      (await request(`/children/${childId}/password`, { method: "POST", session: other, body: { password: PASSWORD } })).status,
      404,
    );
    // Troca de senha derruba as sessões do filho.
    const reset = await request(`/children/${childId}/password`, {
      method: "POST",
      session: parent,
      body: { password: "outra-senha-forte-456" },
    });
    assert.equal(reset.status, 200);
    assert.equal((await request("/me", { session: child })).status, 401);
    // Remoção preserva os lançamentos da família.
    assert.equal(
      (await request(`/children/${childId}`, { method: "DELETE", session: parent })).status,
      204,
    );
    const after = await request("/transactions", { session: parent });
    assert.equal(after.data.rows.length, 4);
    assert.equal((await request("/children", { session: parent })).data.length, 0);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
