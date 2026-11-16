// functions/api/[[path]].js — API do Dogglot (Cloudflare Pages Functions + D1)
// Variáveis (Settings > Variables and Secrets do projeto no Cloudflare):
//   BREVO_API_KEY (secret), SENDER_EMAIL, APP_NAME, ADMIN_EMAIL
// Binding de banco (Settings > Functions > D1 database bindings): nome DB

const DAILY_HEARTS = 3;
const enc = new TextEncoder();

const hex = (buf) => [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, "0")).join("");
const unhex = (h) => new Uint8Array(h.match(/../g).map(x => parseInt(x, 16)));
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...headers } });
const unauth = () => json({ error: "Não autenticado" }, 401);

// ---- Senhas (PBKDF2-SHA256, suportado pelo Workers; a senha nunca é guardada em texto) ----
async function derive(pass, salt) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256));
}
async function hashPass(p) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `${hex(salt)}:${hex(await derive(p, salt))}`;
}
async function checkPass(p, stored) {
  const [s, h] = stored.split(":");
  return hex(await derive(p, unhex(s))) === h;
}

// ---- Dia no horário de Brasília (UTC-3) ----
const brasiliaDay = () => new Intl.DateTimeFormat("en-CA", { timeZone: "America/Sao_Paulo" }).format(new Date());

async function refresh(db, u) {
  const today = brasiliaDay();
  if (u.hearts_day !== today) {
    u.hearts = DAILY_HEARTS;
    u.hearts_day = today;
    await db.prepare("UPDATE users SET hearts = ?, hearts_day = ? WHERE id = ?").bind(u.hearts, today, u.id).run();
  }
  return u;
}

// ---- Sessões (cookie HttpOnly: a página não consegue ler o token) ----
const tokenOf = (req) => {
  const m = (req.headers.get("Cookie") || "").match(/(?:^|;\s*)sid=([^;]+)/);
  return m ? m[1] : null;
};
async function authUser(env, req) {
  const t = tokenOf(req);
  if (!t) return null;
  const u = await env.DB.prepare(
    "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?"
  ).bind(t).first();
  return u && u.verified ? updateLeague(env, await refresh(env.DB, u)) : null;
}
async function newSession(env, userId) {
  const token = hex(crypto.getRandomValues(new Uint8Array(32)));
  await env.DB.prepare("INSERT INTO sessions (token, user_id) VALUES (?, ?)").bind(token, userId).run();
  return `sid=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`;
}

// hearts: null = infinito (conta do administrador)
const clientIp = (req) => req.headers.get("CF-Connecting-IP") || "anon";

// Limite de tentativas: no máximo `max` ações por `windowSec` segundos para a mesma chave
// Limite de tentativas desativado: nunca bloqueia
async function limited(env, key, max, windowSec) {
  return false;
}

async function sendMail(env, to, name, subject, text) {
  if (!env.BREVO_API_KEY) return;
  const r = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "api-key": env.BREVO_API_KEY, "Content-Type": "application/json", accept: "application/json" },
    body: JSON.stringify({ sender: { name: env.APP_NAME, email: env.SENDER_EMAIL }, to: [{ email: to, name }], subject, textContent: text }),
  });
  if (!r.ok) console.error("Brevo:", r.status, await r.text());
}

async function makeToken(env, userId, kind, hours) {
  const token = hex(crypto.getRandomValues(new Uint8Array(24)));
  await env.DB.prepare("INSERT INTO tokens (token, user_id, kind, expires) VALUES (?, ?, ?, ?)")
    .bind(token, userId, kind, Date.now() + hours * 3600e3).run();
  return token;
}

const dayPlus = (d) => new Intl.DateTimeFormat("en-CA", { timeZone: "America/Sao_Paulo" }).format(new Date(Date.now() + d * 864e5));
const addDaysFrom = (day, d) => { const x = new Date(day + "T12:00:00-03:00"); x.setDate(x.getDate() + d); return new Intl.DateTimeFormat("en-CA", { timeZone: "America/Sao_Paulo" }).format(x); };
const PLANS = {
  mensal: { price: 6, days: 30, title: "Dogglot Pro (mensal)" },
  anual: { price: 50, days: 365, title: "Dogglot Pro (anual)" },
};
const MP = "https://api.mercadopago.com";
const mpHeaders = (env) => ({ Authorization: `Bearer ${env.MP_ACCESS_TOKEN}`, "Content-Type": "application/json" });

const rankOut = (me, all) => {
  const pos = all.findIndex(r => r.id === me.id);
  return json({
    top: all.slice(0, 10).map(({ id, ...x }) => ({ ...x, voce: id === me.id })),
    me: { pos: pos >= 0 ? pos + 1 : null, xp: pos >= 0 ? all[pos].xp : 0, league: me.league || "bronze" },
  });
};

const weekStartDay = () => {
  const hoje = brasiliaDay();
  const dow = (new Date(hoje + "T12:00:00-03:00").getUTCDay() + 6) % 7;
  return addDaysFrom(hoje, -dow);
};
const LEAGUES = ["bronze", "prata", "ouro", "diamante"];
const PROMOTE = { bronze: 100, prata: 250, ouro: 500, diamante: Infinity };
const RELEGATE = { bronze: -1, prata: 50, ouro: 150, diamante: 300 };
const moveLeague = (cur, xp) => {
  const i = LEAGUES.indexOf(cur);
  if (xp >= PROMOTE[cur] && i < LEAGUES.length - 1) return LEAGUES[i + 1];
  if (xp < RELEGATE[cur] && i > 0) return LEAGUES[i - 1];
  return cur;
};
// Na primeira vez que a pessoa aparece numa nova semana, a liga é atualizada com base no XP da semana anterior
async function updateLeague(env, u) {
  const wk = weekStartDay();
  if (u.league_week === wk) return u;
  const row = await env.DB.prepare("SELECT COALESCE(SUM(xp), 0) AS xp FROM xp_log WHERE user_id = ? AND day >= ? AND day <= ?")
    .bind(u.id, addDaysFrom(wk, -7), addDaysFrom(wk, -1)).first();
  const next = moveLeague(u.league || "bronze", (row && row.xp) || 0);
  await env.DB.prepare("UPDATE users SET league = ?, league_week = ? WHERE id = ?").bind(next, wk, u.id).run();
  u.league = next;
  u.league_week = wk;
  return u;
}

const isUnlimited = (u) => u.role === "admin" || (u.plan === "pro" && (!u.pro_until || u.pro_until >= brasiliaDay()));
const pub = (u) => ({
  id: u.id, name: u.name, email: u.email, role: u.role,
  plan: u.role === "admin" ? "admin" : (isUnlimited(u) ? "pro" : "free"),
  league: u.league || "bronze",
  hearts: isUnlimited(u) ? null : u.hearts,
});
const nextLesson = (p, l) => {
  const d = (p.done && p.done[l]) || [];
  return d.length ? Math.max(...d) + 2 : 1;
};

// ---- E-mail de boas-vindas (Brevo, plano gratuito) ----
async function welcome(env, to, name) {
  if (!env.BREVO_API_KEY) return;
  const r = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "api-key": env.BREVO_API_KEY, "Content-Type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      sender: { name: env.APP_NAME, email: env.SENDER_EMAIL },
      to: [{ email: to, name }],
      subject: `Bem-vindo ao ${env.APP_NAME}, ${name}!`,
      textContent: `Olá, ${name}! Sua conta no ${env.APP_NAME} foi criada. Bons estudos!`,
    }),
  });
  if (!r.ok) console.error("Brevo:", r.status, await r.text());
}

// ---- Rotas ----
export async function onRequest({ request, env, waitUntil }) {
  const route = new URL(request.url).pathname.replace(/\/+$/, "");
  const method = request.method;
  const body = ["POST", "PUT"].includes(method) ? await request.json().catch(() => ({})) : {};

  try {
    if (route === "/api/signup" && method === "POST") {
      if (await limited(env, "signup:" + clientIp(request), 5, 3600)) return json({ error: "Muitas tentativas. Tente de novo mais tarde." }, 429);
      const name = String(body.name || "").trim().slice(0, 60);
      const email = String(body.email || "").trim().toLowerCase();
      const password = String(body.password || "");
      if (!name || !/^\S+@\S+\.\S+$/.test(email) || password.length < 6)
        return json({ error: "Preencha nome, e-mail válido e senha com 6 ou mais caracteres" }, 400);
      if (await env.DB.prepare("SELECT 1 FROM users WHERE email = ?").bind(email).first())
        return json({ error: "Este e-mail já está cadastrado" }, 409);

      const role = email === (env.ADMIN_EMAIL || "").toLowerCase() ? "admin" : "user";
      await env.DB.prepare(
        "INSERT INTO users (name, email, pass_hash, role, hearts, hearts_day, last_active) VALUES (?, ?, ?, ?, ?, ?, ?)"
      ).bind(name, email, await hashPass(password), role, DAILY_HEARTS, brasiliaDay(), brasiliaDay()).run();
      const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();

      const vt = await makeToken(env, user.id, "verify", 48);
      waitUntil(sendMail(env, email, name, `${env.APP_NAME}: confirme seu e-mail`, `Olá, ${name}! Confirme seu e-mail para entrar no ${env.APP_NAME}:\n\n${env.APP_URL}/api/verify?token=${vt}`));
      return json({ ok: true, verify: true });
    }

    if (route === "/api/login" && method === "POST") {
      if (await limited(env, "login:" + clientIp(request), 10, 900)) return json({ error: "Muitas tentativas. Espere 15 minutos e tente de novo." }, 429);
      const email = String(body.email || "").trim().toLowerCase();
      const u = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
      if (!u || !(await checkPass(String(body.password || ""), u.pass_hash)))
        return json({ error: "E-mail ou senha incorretos" }, 401);
      if (!u.verified) return json({ error: "Confirme seu e-mail antes de entrar. Veja a caixa de entrada e o spam." }, 403);
      return json(pub(await refresh(env.DB, u)), 200, { "Set-Cookie": await newSession(env, u.id) });
    }

    if (route === "/api/verify" && method === "GET") {
      const tk = new URL(request.url).searchParams.get("token") || "";
      const row = await env.DB.prepare("SELECT user_id FROM tokens WHERE token = ? AND kind = 'verify' AND expires > ?").bind(tk, Date.now()).first();
      if (!row) return new Response("Link inválido ou expirado. Crie a conta de novo.", { status: 400 });
      await env.DB.prepare("UPDATE users SET verified = 1 WHERE id = ?").bind(row.user_id).run();
      await env.DB.prepare("DELETE FROM tokens WHERE token = ?").bind(tk).run();
      return new Response(null, { status: 302, headers: { Location: `${env.APP_URL}/?verificado=1` } });
    }

    if (route === "/api/forgot" && method === "POST") {
      const email = String(body.email || "").trim().toLowerCase();
      if (await limited(env, "forgot:" + clientIp(request), 5, 3600)) return json({ error: "Muitas tentativas. Tente de novo mais tarde." }, 429);
      const u = await env.DB.prepare("SELECT id, name FROM users WHERE email = ?").bind(email).first();
      if (u) {
        const t = await makeToken(env, u.id, "reset", 1);
        await sendMail(env, email, u.name, `${env.APP_NAME}: redefinir senha`, `Olá, ${u.name}! Para criar uma nova senha, abra este link (válido por 1 hora):\n\n${env.APP_URL}/?reset=${t}\n\nSe não foi você, ignore este e-mail.`);
      }
      return json({ ok: true }); // responde igual existindo ou não o e-mail
    }

    if (route === "/api/reset" && method === "POST") {
      if (await limited(env, "reset:" + clientIp(request), 10, 3600)) return json({ error: "Muitas tentativas. Tente de novo mais tarde." }, 429);
      const password = String(body.password || "");
      if (password.length < 6) return json({ error: "A senha precisa de 6 ou mais caracteres" }, 400);
      const row = await env.DB.prepare("SELECT user_id FROM tokens WHERE token = ? AND kind = 'reset' AND expires > ?").bind(String(body.token || ""), Date.now()).first();
      if (!row) return json({ error: "Link inválido ou expirado. Peça um novo." }, 400);
      await env.DB.prepare("UPDATE users SET pass_hash = ? WHERE id = ?").bind(await hashPass(password), row.user_id).run();
      await env.DB.prepare("DELETE FROM tokens WHERE user_id = ? AND kind = 'reset'").bind(row.user_id).run();
      await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(row.user_id).run();
      return json({ ok: true });
    }

    if (route === "/api/ranking" && method === "GET") {
      const me = await authUser(env, request);
      if (!me) return unauth();
      const period = new URL(request.url).searchParams.get("period") || "all";
      if (period !== "all") {
        const hoje = brasiliaDay(); const dow = (new Date(hoje + "T12:00:00-03:00").getUTCDay() + 6) % 7; const since = period === "week" ? addDaysFrom(hoje, -dow) : hoje.slice(0, 8) + "01";
        const rs = await env.DB.prepare(
          "SELECT u.id AS id, u.name AS name, SUM(x.xp) AS xp FROM xp_log x JOIN users u ON u.id = x.user_id WHERE x.day >= ? AND u.verified = 1 GROUP BY u.id ORDER BY xp DESC"
        ).bind(since).all();
        return rankOut(me, rs.results.map(r => ({ id: r.id, nome: String(r.name).split(" ")[0], xp: r.xp || 0 })));
      }
      const { results } = await env.DB.prepare("SELECT id, name, progress FROM users WHERE verified = 1").all();
      const top = results
        .map(r => ({ id: r.id, nome: r.name.split(" ")[0], xp: JSON.parse(r.progress || "{}").xp || 0 }))
        .sort((a, b) => b.xp - a.xp)
        ;
      return rankOut(me, top);
    }

    if (route === "/api/account/delete" && method === "POST") {
      const me = await authUser(env, request);
      if (!me) return unauth();
      if (!(await checkPass(String(body.password || ""), me.pass_hash))) return json({ error: "Senha incorreta" }, 403);
      await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(me.id).run();
      await env.DB.prepare("DELETE FROM tokens WHERE user_id = ?").bind(me.id).run();
      await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(me.id).run();
      return json({ ok: true }, 200, { "Set-Cookie": "sid=; HttpOnly; Secure; Path=/; Max-Age=0" });
    }

    if (route === "/api/trial" && method === "POST") {
      const me = await authUser(env, request);
      if (!me) return unauth();
      if (me.trial_used) return json({ error: "Você já usou o teste grátis." }, 400);
      await env.DB.prepare("UPDATE users SET plan = 'pro', pro_until = ?, trial_used = 1 WHERE id = ?").bind(dayPlus(7), me.id).run();
      return json({ ok: true });
    }

    if (route === "/api/pay/pix" && method === "POST") {
      const me = await authUser(env, request);
      if (!me) return unauth();
      const plan = PLANS[body.plan];
      if (!plan) return json({ error: "Plano inválido" }, 400);
      const cpf = String(body.cpf || "").replace(/\D/g, "");
      if (cpf.length !== 11) return json({ error: "Digite um CPF válido, com 11 números" }, 400);
      const r = await fetch(`${MP}/v1/payments`, {
        method: "POST",
        headers: { ...mpHeaders(env), "X-Idempotency-Key": hex(crypto.getRandomValues(new Uint8Array(16))) },
        body: JSON.stringify({
          transaction_amount: plan.price,
          description: plan.title,
          payment_method_id: "pix",
          payer: { email: me.email, identification: { type: "CPF", number: cpf } },
          external_reference: `${me.id}|${plan.days}`,
          notification_url: `${env.APP_URL}/api/pay/webhook`,
        }),
      });
      const p = await r.json().catch(() => ({}));
      if (!r.ok) { console.error("MP pix:", r.status, JSON.stringify(p)); return json({ error: "Não foi possível gerar o Pix agora. Tente de novo." }, 502); }
      const tx = (p.point_of_interaction && p.point_of_interaction.transaction_data) || {};
      return json({ id: p.id, code: tx.qr_code || "", img: tx.qr_code_base64 || "" });
    }

    if (route === "/api/pay/card" && method === "POST") {
      const me = await authUser(env, request);
      if (!me) return unauth();
      const plan = PLANS[body.plan];
      if (!plan) return json({ error: "Plano inválido" }, 400);
      const r = await fetch(`${MP}/checkout/preferences`, {
        method: "POST",
        headers: mpHeaders(env),
        body: JSON.stringify({
          items: [{ title: plan.title, quantity: 1, unit_price: plan.price, currency_id: "BRL" }],
          external_reference: `${me.id}|${plan.days}`,
          notification_url: `${env.APP_URL}/api/pay/webhook`,
          back_urls: { success: `${env.APP_URL}/`, pending: `${env.APP_URL}/`, failure: `${env.APP_URL}/` },
          auto_return: "approved",
        }),
      });
      const p = await r.json().catch(() => ({}));
      if (!r.ok || !p.init_point) { console.error("MP card:", r.status, JSON.stringify(p)); return json({ error: "Não foi possível abrir o pagamento agora." }, 502); }
      return json({ init_point: p.init_point });
    }

    if (route === "/api/pay/webhook" && method === "POST") {
      const url = new URL(request.url);
      const id = (body.data && body.data.id) || url.searchParams.get("data.id") || url.searchParams.get("id");
      if (!id) return json({ ok: true });
      // evita liberar o Pro duas vezes para o mesmo pagamento
      if (await env.DB.prepare("SELECT 1 FROM payments WHERE id = ?").bind(String(id)).first()) return json({ ok: true });
      const r = await fetch(`${MP}/v1/payments/${id}`, { headers: mpHeaders(env) });
      const p = await r.json().catch(() => ({}));
      if (!r.ok || p.status !== "approved") return json({ ok: true });
      const [uid, days] = String(p.external_reference || "").split("|");
      const user = await env.DB.prepare("SELECT plan, pro_until FROM users WHERE id = ?").bind(Number(uid)).first();
      if (!user) return json({ ok: true });
      // se já for Pro, soma os dias a partir do fim atual
      const base = user.plan === "pro" && user.pro_until && user.pro_until > brasiliaDay() ? user.pro_until : brasiliaDay();
      await env.DB.prepare("UPDATE users SET plan = 'pro', pro_until = ? WHERE id = ?").bind(addDaysFrom(base, Number(days)), Number(uid)).run();
      await env.DB.prepare("INSERT INTO payments (id) VALUES (?)").bind(String(id)).run();
      return json({ ok: true });
    }

    if (route === "/api/logout" && method === "POST") {
      const t = tokenOf(request);
      if (t) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(t).run();
      return json({ ok: true }, 200, { "Set-Cookie": "sid=; HttpOnly; Secure; Path=/; Max-Age=0" });
    }

    if (route === "/api/me" && method === "GET") {
      const me = await authUser(env, request);
      if (!me) return unauth();
      return json({ ...pub(me), progress: JSON.parse(me.progress) });
    }

    if (route === "/api/progress" && method === "PUT") {
      const me = await authUser(env, request);
      if (!me) return unauth();
      const data = JSON.stringify(body.progress || {});
      if (data.length > 200000) return json({ error: "Progresso grande demais" }, 413);
      await env.DB.prepare("UPDATE users SET progress = ?, last_active = ?, reminder_stage = 0 WHERE id = ?").bind(data, brasiliaDay(), me.id).run();
      const xpNow = Number((body.progress || {}).xp) || 0;
      const delta = me.xp_seen === 0 ? 0 : xpNow - me.xp_seen;
      if (delta > 0) {
        await env.DB.prepare("INSERT INTO xp_log (user_id, day, xp) VALUES (?, ?, ?) ON CONFLICT(user_id, day) DO UPDATE SET xp = xp + excluded.xp").bind(me.id, brasiliaDay(), delta).run();
      }
      await env.DB.prepare("UPDATE users SET xp_seen = ? WHERE id = ?").bind(xpNow, me.id).run();
      return json({ ok: true });
    }

    if (route === "/api/hearts/lose" && method === "POST") {
      const me = await authUser(env, request);
      if (!me) return unauth();
      if (isUnlimited(me)) return json({ hearts: null });
      const hearts = Math.max(0, me.hearts - 1);
      await env.DB.prepare("UPDATE users SET hearts = ? WHERE id = ?").bind(hearts, me.id).run();
      return json({ hearts });
    }

    if (route === "/api/admin/users" && method === "GET") {
      const me = await authUser(env, request);
      if (!me) return unauth();
      if (me.role !== "admin") return json({ error: "Sem permissão" }, 403);
      const { results } = await env.DB.prepare(
        "SELECT name, email, role, hearts, progress, created_at FROM users ORDER BY id"
      ).all();
      return json(results.map(r => {
        const p = JSON.parse(r.progress || "{}");
        const done = (l) => (p.done && p.done[l]) || [];
        return {
          nome: r.name, email: r.email, papel: r.role,
          coracoes: r.role === "admin" ? "infinito" : r.hearts,
          criado_em: r.created_at,
          proxima_licao: { ingles: nextLesson(p, "en"), espanhol: nextLesson(p, "es") },
          licoes_concluidas: { ingles: done("en").length, espanhol: done("es").length },
        };
      }));
    }

    if (route === "/api/admin/plan" && method === "POST") {
      const me = await authUser(env, request);
      if (!me) return unauth();
      if (me.role !== "admin") return json({ error: "Sem permissão" }, 403);
      const email = String(body.email || "").trim().toLowerCase();
      const plan = body.plan === "pro" ? "pro" : "free";
      const until = plan === "pro" && body.days
        ? new Intl.DateTimeFormat("en-CA", { timeZone: "America/Sao_Paulo" }).format(new Date(Date.now() + Number(body.days) * 864e5))
        : null;
      await env.DB.prepare("UPDATE users SET plan = ?, pro_until = ? WHERE email = ?").bind(plan, until, email).run();
      return json({ ok: true });
    }

    return json({ error: "Rota não encontrada" }, 404);
  } catch (e) {
    console.error(e);
    return json({ error: "Erro interno" }, 500);
  }
        }
