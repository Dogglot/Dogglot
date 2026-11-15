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
  return u && u.verified ? refresh(env.DB, u) : null;
}
async function newSession(env, userId) {
  const token = hex(crypto.getRandomValues(new Uint8Array(32)));
  await env.DB.prepare("INSERT INTO sessions (token, user_id) VALUES (?, ?)").bind(token, userId).run();
  return `sid=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`;
}

// hearts: null = infinito (conta do administrador)
const clientIp = (req) => req.headers.get("CF-Connecting-IP") || "anon";

// Limite de tentativas: no máximo `max` ações por `windowSec` segundos para a mesma chave
async function limited(env, key, max, windowSec) {
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare("DELETE FROM attempts WHERE ts < ?").bind(now - 86400).run();
  const row = await env.DB.prepare("SELECT COUNT(*) AS c FROM attempts WHERE key = ? AND ts > ?").bind(key, now - windowSec).first();
  if (row.c >= max) return true;
  await env.DB.prepare("INSERT INTO attempts (key, ts) VALUES (?, ?)").bind(key, now).run();
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

const isUnlimited = (u) => u.role === "admin" || (u.plan === "pro" && (!u.pro_until || u.pro_until >= brasiliaDay()));
const pub = (u) => ({
  id: u.id, name: u.name, email: u.email, role: u.role,
  plan: u.role === "admin" ? "admin" : (isUnlimited(u) ? "pro" : "free"),
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
      const { results } = await env.DB.prepare("SELECT name, progress FROM users WHERE verified = 1").all();
      const top = results
        .map(r => ({ nome: r.name.split(" ")[0], xp: JSON.parse(r.progress || "{}").xp || 0 }))
        .sort((a, b) => b.xp - a.xp)
        .slice(0, 10);
      return json(top);
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
