const $ = (selector) => document.querySelector(selector);
const state = { user: null, csrf: null, categories: [], authMode: "login" };
const money = (cents) =>
  new Intl.NumberFormat("pt-BR", { style: "currency", currency: "BRL" }).format(
    cents / 100,
  );
const today = () => new Date().toLocaleDateString("en-CA");
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};
let toastTimer;
function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.remove("show"), 4000);
}
async function api(path, options = {}) {
  const headers = { ...options.headers };
  if (state.csrf && options.method && options.method !== "GET")
    headers["x-csrf-token"] = state.csrf;
  if (options.body && !(options.body instanceof FormData))
    headers["Content-Type"] = "application/json";
  const response = await fetch(`/api${path}`, {
    credentials: "same-origin",
    ...options,
    headers,
  });
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.error || "Não foi possível concluir a ação.");
  }
  if (response.status === 204) return null;
  return response.json();
}
function setAuthMode(mode) {
  state.authMode = mode;
  $("#login-tab").classList.toggle("active", mode === "login");
  $("#register-tab").classList.toggle("active", mode === "register");
  $("#login-tab").setAttribute("aria-pressed", String(mode === "login"));
  $("#register-tab").setAttribute("aria-pressed", String(mode === "register"));
  $("#name-field").hidden = mode === "login";
  $("#name-field input").required = mode === "register";
  $("#auth-title").textContent =
    mode === "login" ? "Acesse sua conta" : "Crie sua conta";
  $("#auth-subtitle").textContent =
    mode === "login"
      ? "Seus registros estão esperando por você."
      : "Comece a organizar as contas da casa.";
  $("#auth-submit").firstChild.textContent =
    mode === "login" ? "Entrar na conta " : "Criar conta ";
  $("#auth-form [name=password]").autocomplete =
    mode === "login" ? "current-password" : "new-password";
}
function showView(view) {
  for (const name of ["overview", "categories", "family"])
    $(`#${name}-view`).hidden = name !== view;
  document.querySelectorAll("[data-view]").forEach((button) => {
    const active = button.dataset.view === view;
    button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  });
  $("#current-view-name").textContent = {
    overview: "VISÃO GERAL",
    categories: "CATEGORIAS",
    family: "FAMÍLIA",
  }[view];
  window.scrollTo({ top: 0, behavior: "auto" });
}
async function refresh() {
  const user = await api("/me");
  state.user = user;
  state.csrf = user.csrfToken;
  $("#auth").hidden = true;
  $("#dashboard").hidden = false;
  $("#sidebar-name").textContent = user.name;
  $("#sidebar-role").textContent =
    user.parentId === null ? "Responsável" : "Conta de filho";
  $("#user-monogram").textContent = user.name.charAt(0).toUpperCase();
  $("#today-label").textContent = new Intl.DateTimeFormat("pt-BR", {
    day: "numeric",
    month: "long",
    year: "numeric",
  }).format(new Date());
  $("#new-entry").hidden = !user.canAdd;
  $("#category-form").hidden = user.parentId !== null;
  $("#family-nav").hidden = user.parentId !== null;
  $("#summary").hidden = !user.canView;
  $(".history").hidden = !user.canView;
  $("#permission-note").hidden = user.canView;
  $("#permission-note").textContent = user.canView
    ? ""
    : "O responsável desativou o acesso ao saldo e ao histórico para esta conta.";
  showView("overview");
  await Promise.all([
    loadCategories(),
    user.canView ? loadTransactions() : Promise.resolve(),
    user.parentId === null ? loadChildren() : Promise.resolve(),
  ]);
}
async function loadCategories() {
  state.categories = await api("/categories");
  const list = $("#categories");
  list.replaceChildren();
  for (const category of state.categories) {
    const row = el("div", "category-row");
    row.append(
      el("strong", "", category.name),
      el(
        "span",
        `category-type ${category.type}`,
        category.type === "income" ? "Entrada" : "Saída",
      ),
    );
    list.append(row);
  }
  if (state.categories.length === 0)
    list.append(el("p", "muted small", "Nenhuma categoria."));
  updateCategoryOptions();
}
function updateCategoryOptions() {
  const type = $("#entry-form [name=type]:checked").value;
  const select = $("#entry-form [name=categoryId]");
  select.replaceChildren();
  for (const category of state.categories.filter((c) => c.type === type)) {
    const option = el("option", "", category.name);
    option.value = category.id;
    select.append(option);
  }
}
async function loadTransactions() {
  const list = $("#transactions");
  list.replaceChildren(el("div", "empty", "Carregando movimentações…"));
  const params = new URLSearchParams();
  if ($("#month-filter").value) params.set("month", $("#month-filter").value);
  if ($("#type-filter").value) params.set("type", $("#type-filter").value);
  let data;
  try {
    data = await api(`/transactions?${params}`);
  } catch (error) {
    const box = el("div", "empty");
    const retry = el("button", "text-action", "Tentar novamente");
    retry.type = "button";
    retry.addEventListener("click", () =>
      loadTransactions().catch((nextError) => toast(nextError.message)),
    );
    box.append(el("b", "", "Não foi possível carregar o histórico"), retry);
    list.replaceChildren(box);
    throw error;
  }
  $("#balance").textContent = money(data.summary.balance);
  $("#income").textContent = money(data.summary.income);
  $("#expense").textContent = money(data.summary.expense);
  $("#row-count").textContent =
    `${data.rows.length} registro${data.rows.length === 1 ? "" : "s"}`;
  list.replaceChildren();
  if (!data.rows.length) {
    const box = el("div", "empty");
    box.append(
      el("b", "", "Nenhum lançamento encontrado"),
      el("span", "", "Adicione um lançamento ou ajuste os filtros."),
    );
    list.append(box);
    return;
  }
  for (const row of data.rows) {
    const item = el("div", "transaction");
    const icon = el(
      "div",
      `tx-icon ${row.type}`,
      row.type === "income" ? "↗" : "↘",
    );
    const info = el("div", "tx-info");
    info.append(
      el("strong", "", row.description),
      el(
        "small",
        "",
        `${new Date(`${row.occurred_on}T12:00:00`).toLocaleDateString("pt-BR")} · ${row.category} · ${row.author}`,
      ),
    );
    const right = el("div", "tx-right");
    right.append(
      el(
        "div",
        `tx-amount ${row.type}`,
        `${row.type === "income" ? "+" : "−"} ${money(row.amount_cents)}`,
      ),
    );
    const actions = el("div", "tx-actions");
    if (row.has_receipt) {
      const link = el("a", "", "Comprovante");
      link.href = `/api/transactions/${row.id}/receipt`;
      actions.append(link);
    }
    if (state.user.parentId === null) {
      const remove = el("button", "", "Excluir");
      remove.type = "button";
      remove.addEventListener("click", async () => {
        if (!confirm("Excluir este lançamento?")) return;
        try {
          await api(`/transactions/${row.id}`, { method: "DELETE" });
          await loadTransactions();
          toast("Lançamento excluído.");
        } catch (error) {
          toast(error.message);
        }
      });
      actions.append(remove);
    }
    right.append(actions);
    item.append(icon, info, right);
    list.append(item);
  }
}
async function loadChildren() {
  const children = await api("/children");
  const list = $("#children");
  list.replaceChildren();
  for (const child of children) {
    const row = el("div", "child-row");
    const identity = el("div", "child-identity");
    identity.append(el("strong", "", child.name), el("small", "", child.email));
    row.append(identity);
    for (const [key, title] of [
      ["can_view", "Ver saldo e histórico"],
      ["can_add", "Registrar lançamentos"],
    ]) {
      const label = el("label");
      const input = el("input");
      input.type = "checkbox";
      input.checked = !!child[key];
      label.append(input, document.createTextNode(` ${title}`));
      row.append(label);
      input.addEventListener("change", async () => {
        try {
          const checks = row.querySelectorAll("input");
          await api(`/children/${child.id}`, {
            method: "PATCH",
            body: JSON.stringify({
              canView: checks[0].checked,
              canAdd: checks[1].checked,
            }),
          });
          toast("Permissões atualizadas.");
        } catch (error) {
          input.checked = !input.checked;
          toast(error.message);
        }
      });
    }
    list.append(row);
  }
  if (!children.length)
    list.append(el("p", "muted small", "Nenhuma conta de filho criada."));
}
$("#login-tab").addEventListener("click", () => setAuthMode("login"));
$("#register-tab").addEventListener("click", () => setAuthMode("register"));
document
  .querySelectorAll("[data-view]")
  .forEach((button) =>
    button.addEventListener("click", () => showView(button.dataset.view)),
  );
$("#auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = $("#auth-submit");
  button.disabled = true;
  try {
    const body = Object.fromEntries(new FormData(form));
    const result = await api(
      state.authMode === "login" ? "/login" : "/register",
      { method: "POST", body: JSON.stringify(body) },
    );
    state.csrf = result.csrfToken;
    form.reset();
    await refresh();
    toast(
      state.authMode === "login"
        ? "Bem-vindo de volta!"
        : "Conta criada com sucesso!",
    );
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
  }
});
$("#logout").addEventListener("click", async () => {
  try {
    await api("/logout", { method: "POST" });
    state.user = null;
    state.csrf = null;
    $("#dashboard").hidden = true;
    $("#auth").hidden = false;
    setAuthMode("login");
    toast("Você saiu da conta.");
  } catch (error) {
    toast(error.message);
  }
});
$("#new-entry").addEventListener("click", () => {
  $("#entry-form").reset();
  $("#entry-form [name=occurredOn]").value = today();
  updateCategoryOptions();
  $("#entry-dialog").showModal();
});
$("#add-child").addEventListener("click", () => {
  $("#child-form").reset();
  $("#child-dialog").showModal();
});
document
  .querySelectorAll("[data-close]")
  .forEach((button) =>
    button.addEventListener("click", () =>
      $(`#${button.dataset.close}`).close(),
    ),
  );
document
  .querySelectorAll("#entry-form [name=type]")
  .forEach((input) => input.addEventListener("change", updateCategoryOptions));
$("#entry-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("[type=submit]");
  button.disabled = true;
  try {
    const data = new FormData(form);
    const raw = String(data.get("amount")).trim().replace(/\s/g, "");
    if (!/^\d+(?:[,.]\d{1,2})?$/.test(raw))
      throw new Error("Informe um valor válido, como 25,90.");
    data.set(
      "amountCents",
      String(Math.round(Number(raw.replace(",", ".")) * 100)),
    );
    data.delete("amount");
    if (!data.get("receipt")?.size) data.delete("receipt");
    await api("/transactions", { method: "POST", body: data });
    $("#entry-dialog").close();
    if (state.user.canView) await loadTransactions();
    toast("Lançamento salvo.");
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
  }
});
$("#child-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("[type=submit]");
  button.disabled = true;
  try {
    const data = Object.fromEntries(new FormData(form));
    data.canView = form.elements.namedItem("canView").checked;
    data.canAdd = form.elements.namedItem("canAdd").checked;
    await api("/children", { method: "POST", body: JSON.stringify(data) });
    $("#child-dialog").close();
    await loadChildren();
    toast("Conta de filho criada.");
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
  }
});
$("#category-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  try {
    await api("/categories", {
      method: "POST",
      body: JSON.stringify(Object.fromEntries(new FormData(form))),
    });
    form.reset();
    await loadCategories();
    toast("Categoria adicionada.");
  } catch (error) {
    toast(error.message);
  }
});
$("#month-filter").addEventListener("change", () =>
  loadTransactions().catch((error) => toast(error.message)),
);
$("#type-filter").addEventListener("change", () =>
  loadTransactions().catch((error) => toast(error.message)),
);
$("#clear-filters").addEventListener("click", () => {
  $("#month-filter").value = "";
  $("#type-filter").value = "";
  loadTransactions().catch((error) => toast(error.message));
});
refresh().catch(() => {
  $("#auth").hidden = false;
  $("#dashboard").hidden = true;
});
