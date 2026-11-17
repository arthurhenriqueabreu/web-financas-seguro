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

async function request(
  path,
  { method = "GET", body, session, headers = {} } = {},
) {
  const response = await fetch(`${base}/api${path}`, {
    method,
    headers: {
      ...(session
        ? { Cookie: session.cookie, "x-csrf-token": session.csrf }
        : {}),
      ...(body && !(body instanceof FormData)
        ? { "Content-Type": "application/json" }
        : {}),
      ...headers,
    },
    body:
      body instanceof FormData
        ? body
        : body === undefined
          ? undefined
          : JSON.stringify(body),
    redirect: "manual",
  });
  const data =
    response.status === 204 ? null : await response.json().catch(() => null);
  return {
    status: response.status,
    data,
    cookie: response.headers.get("set-cookie")?.split(";")[0],
  };
}
async function register(name, email) {
  const result = await request("/register", {
    method: "POST",
    body: { name, email, password: "senha-muito-forte-123" },
  });
  assert.equal(result.status, 201);
  return { cookie: result.cookie, csrf: result.data.csrfToken };
}

test("fluxos e proteções de segurança", async () => {
  try {
    const parent = await register("Responsável", "parent@example.com");
    const other = await register("Outra pessoa", "other@example.com");
    const categories = await request("/categories", { session: parent });
    const category = categories.data.find((c) => c.type === "expense");
    assert.ok(category);

    const noCsrf = await request("/categories", {
      method: "POST",
      session: parent,
      headers: { "x-csrf-token": "" },
      body: { name: "Teste", type: "expense" },
    });
    assert.equal(noCsrf.status, 403);
    const wrongOrigin = await request("/login", {
      method: "POST",
      headers: { Origin: "https://attacker.test" },
      body: { email: "parent@example.com", password: "senha-muito-forte-123" },
    });
    assert.equal(wrongOrigin.status, 403);

    const create = await request("/transactions", {
      method: "POST",
      session: parent,
      body: {
        type: "expense",
        categoryId: category.id,
        amountCents: 2590,
        description: "<img src=x onerror=alert(1)>",
        occurredOn: "2026-11-16",
        owner_id: 999,
      },
    });
    assert.equal(create.status, 201);
    const history = await request("/transactions", { session: parent });
    assert.equal(history.data.summary.expense, 2590);
    assert.equal(
      history.data.rows[0].description,
      "<img src=x onerror=alert(1)>",
    );
    assert.equal(
      (await request("/transactions", { session: other })).data.rows.length,
      0,
    );
    assert.equal(
      (
        await request(`/transactions/${create.data.id}`, {
          method: "DELETE",
          session: other,
        })
      ).status,
      404,
    );

    const badFile = new FormData();
    badFile.set("type", "expense");
    badFile.set("categoryId", String(category.id));
    badFile.set("amountCents", "100");
    badFile.set("description", "Arquivo inválido");
    badFile.set("occurredOn", "2026-11-16");
    badFile.set(
      "receipt",
      new Blob(["<script>alert(1)</script>"], { type: "image/png" }),
      "evil.png",
    );
    assert.equal(
      (
        await request("/transactions", {
          method: "POST",
          session: parent,
          body: badFile,
        })
      ).status,
      400,
    );

    const child = await request("/children", {
      method: "POST",
      session: parent,
      body: {
        name: "Filho",
        email: "child@example.com",
        password: "senha-muito-forte-123",
        canView: false,
        canAdd: true,
        parent_id: 999,
      },
    });
    assert.equal(child.status, 201);
    const login = await request("/login", {
      method: "POST",
      body: { email: "child@example.com", password: "senha-muito-forte-123" },
    });
    const childSession = { cookie: login.cookie, csrf: login.data.csrfToken };
    assert.equal(
      (await request("/transactions", { session: childSession })).status,
      403,
    );
    assert.equal(
      (
        await request("/categories", {
          method: "POST",
          session: childSession,
          body: { name: "Hack", type: "expense" },
        })
      ).status,
      403,
    );
    assert.equal(
      (
        await request("/transactions", {
          method: "POST",
          session: childSession,
          body: {
            type: "expense",
            categoryId: category.id,
            amountCents: 100,
            description: "Lanche",
            occurredOn: "2026-11-16",
          },
        })
      ).status,
      201,
    );
    assert.equal(
      (
        await request(`/transactions/${create.data.id}`, {
          method: "DELETE",
          session: childSession,
        })
      ).status,
      403,
    );
    assert.equal(
      (
        await request(`/children/${child.data.id}`, {
          method: "PATCH",
          session: parent,
          body: { canView: true, canAdd: false },
        })
      ).status,
      200,
    );
    assert.equal(
      (await request("/transactions", { session: childSession })).status,
      200,
    );
    assert.equal(
      (
        await request("/transactions", {
          method: "POST",
          session: childSession,
          body: {
            type: "expense",
            categoryId: category.id,
            amountCents: 100,
            description: "Bloqueado",
            occurredOn: "2026-11-16",
          },
        })
      ).status,
      403,
    );
    assert.equal(
      (await request("/logout", { method: "POST", session: parent })).status,
      204,
    );
    assert.equal((await request("/me", { session: parent })).status, 401);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
