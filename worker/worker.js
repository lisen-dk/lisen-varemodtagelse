// Lisen Varemodtagelse – webhook-modtager for SmartPack.
//
// SmartPack kalder POST /smartpack (basic auth), når ordrer eller lagertal ændres.
// Workeren gemmer INGEN data fra SmartPack. Den samler ændringerne i et 30 sekunders vindue
// (Durable Object med alarm) og beder derefter GitHub om at bygge dashboardet igen
// (repository_dispatch "smartpack"). Mindst 60 sekunder mellem to opstarter.
//
// Dashboardet kan også ændre en PO's forventede leveringsdato (POST /po/dato). Forespørgslen er
// underskrevet (HMAC) med den nøgle, dashboardet afleder af adgangskoden, og gælder kun i 5 minutter.
// Kun feltet expectedDeliveryDate sendes til SmartPack.
//
// Hemmeligheder (sættes ved udrulning): HOOK_USER, HOOK_PASS, GITHUB_TOKEN, DASH_KEY, SP_APP_ID, SP_TOKEN
// Variabler: GITHUB_REPO (fx "lisen-dk/lisen-varemodtagelse"), DASH_ORIGIN (dashboardets adresse)

const SAML_MS = 30_000;       // vent så længe efter første ændring
const MIN_MELLEM_MS = 60_000; // mindst så længe mellem to GitHub-kørsler

function lige(a, b) {
  // sammenligning i konstant tid
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  let d = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) d |= (x[i] || 0) ^ (y[i] || 0);
  return d === 0;
}

function godkendt(req, env) {
  const h = req.headers.get("Authorization") || "";
  if (!env.HOOK_USER || !env.HOOK_PASS) return false;
  return lige(h, "Basic " + btoa(env.HOOK_USER + ":" + env.HOOK_PASS));
}

function cors(env) {
  return {
    "Access-Control-Allow-Origin": env.DASH_ORIGIN || "https://lisen-dk.github.io",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

function svar(env, status, data) {
  return new Response(JSON.stringify(data), { status, headers: { ...cors(env), "content-type": "application/json; charset=utf-8" } });
}

function b64tilBytes(s) {
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

async function hmacHex(noegleB64, besked) {
  const k = await crypto.subtle.importKey("raw", b64tilBytes(noegleB64), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(besked));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sp(env, sti, body) {
  const r = await fetch("https://lisen.smartpack.dk/api/v1" + sti, {
    method: body ? "POST" : "GET",
    headers: {
      "X-SmartPack-AppId": env.SP_APP_ID,
      "X-SmartPack-AccessToken": env.SP_TOKEN,
      "Content-Type": "application/json",
      "User-Agent": "lisen-varemodtagelse-worker",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await r.json(); } catch (_) { /* ikke json */ }
  return { ok: r.ok && data && (data.status === undefined || data.status === 200), status: r.status, data };
}

function gyldigDato(d) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) return false;
  const x = new Date(d + "T00:00:00Z");
  if (isNaN(x) || x.toISOString().slice(0, 10) !== d) return false;
  const aar = x.getUTCFullYear();
  return aar >= 2020 && aar <= 2040;
}

async function poDato(req, env) {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(env) });
  if (req.method !== "POST") return svar(env, 405, { fejl: "Kun POST" });
  if (!env.DASH_KEY || !env.SP_APP_ID || !env.SP_TOKEN) return svar(env, 503, { fejl: "Funktionen er ikke sat op endnu." });
  let b;
  try { b = await req.json(); } catch (_) { return svar(env, 400, { fejl: "Ugyldig forespørgsel." }); }
  const id = Number(b && b.id), dato = String((b && b.dato) || ""), t = Number(b && b.t), sig = String((b && b.sig) || "");
  if (!Number.isInteger(id) || id <= 0 || !gyldigDato(dato) || !Number.isFinite(t)) {
    return svar(env, 400, { fejl: "Ugyldig PO eller dato." });
  }
  if (Math.abs(Date.now() - t) > 5 * 60_000) return svar(env, 403, { fejl: "Forespørgslen er udløbet. Genindlæs siden og prøv igen." });
  const forventet = await hmacHex(env.DASH_KEY, `po-dato|${id}|${dato}|${t}`);
  if (!lige(sig, forventet)) return svar(env, 403, { fejl: "Adgang nægtet. Log ud og ind igen på dashboardet." });

  const g = await sp(env, `/purchaseorder/get/${id}`);
  const po = g.data && g.data.data;
  if (!g.ok || !po) return svar(env, 404, { fejl: `PO ${id} blev ikke fundet i SmartPack.` });
  if (po.state !== 1 && po.state !== 2) return svar(env, 409, { fejl: `PO ${id} er ikke åben længere.` });
  const gammel = String(po.expectedDeliveryDate || "").slice(0, 10);
  if (gammel === dato) return svar(env, 200, { ok: true, id, dato, gammel, uaendret: true });

  const u = await sp(env, "/purchaseorder/update", { id, expectedDeliveryDate: dato });
  if (!u.ok) {
    const msg = (u.data && (u.data.msg || u.data.message)) || `status ${u.status}`;
    return svar(env, 502, { fejl: `SmartPack afviste ændringen (${String(msg).slice(0, 120)}).` });
  }
  const stub = env.SAMLER.get(env.SAMLER.idFromName("dashboard"));
  await stub.fetch("https://samler/log", { method: "POST", body: JSON.stringify({ id, gammel, dato, tid: Date.now() }) });
  await stub.fetch("https://samler/aendring", { method: "POST", body: "po_dato" });
  return svar(env, 200, { ok: true, id, dato, gammel });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname === "/po/dato") return poDato(req, env);
    if (url.pathname === "/" && req.method === "GET") {
      return new Response("Lisen Varemodtagelse – webhook-modtager\n", { headers: { "content-type": "text/plain; charset=utf-8" } });
    }
    if (url.pathname === "/status" && req.method === "GET") {
      if (!godkendt(req, env)) {
        return new Response("Mangler adgang", { status: 401, headers: { "WWW-Authenticate": 'Basic realm="lisen"' } });
      }
      const stub = env.SAMLER.get(env.SAMLER.idFromName("dashboard"));
      return stub.fetch("https://samler/status");
    }
    if (url.pathname !== "/smartpack") return new Response("Ikke fundet", { status: 404 });
    if (req.method !== "POST") return new Response("Kun POST", { status: 405 });
    if (!godkendt(req, env)) {
      return new Response("Mangler adgang", { status: 401, headers: { "WWW-Authenticate": 'Basic realm="lisen"' } });
    }
    // Kun typen læses (til optælling) – indholdet gemmes ikke.
    let type = "ukendt";
    try {
      const b = await req.json();
      if (b && typeof b.type === "string") type = b.type.slice(0, 40);
    } catch (_) { /* tom eller ugyldig krop er ok */ }
    const stub = env.SAMLER.get(env.SAMLER.idFromName("dashboard"));
    await stub.fetch("https://samler/aendring", { method: "POST", body: type });
    return new Response("ok");
  },
};

export class Samler {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(req) {
    const url = new URL(req.url);
    const s = this.state.storage;
    if (url.pathname === "/aendring") {
      const type = await req.text();
      const antal = (await s.get("antal")) || {};
      antal[type] = (antal[type] || 0) + 1;
      await s.put("antal", antal);
      if ((await s.getAlarm()) == null) {
        const sidst = (await s.get("sidst_startet")) || 0;
        const naar = Math.max(Date.now() + SAML_MS, sidst + MIN_MELLEM_MS);
        await s.setAlarm(naar);
      }
      return new Response("ok");
    }
    if (url.pathname === "/log") {
      const post = JSON.parse(await req.text());
      const log = (await s.get("po_log")) || [];
      log.unshift(post);
      await s.put("po_log", log.slice(0, 100));
      return new Response("ok");
    }
    if (url.pathname === "/status") {
      return Response.json({
        po_log: ((await s.get("po_log")) || []).slice(0, 20),
        alarm: await s.getAlarm(),
        sidst_startet: (await s.get("sidst_startet")) || null,
        sidst_svar: (await s.get("sidst_svar")) || null,
        ventende: (await s.get("antal")) || {},
        i_alt: (await s.get("i_alt")) || {},
      });
    }
    return new Response("Ikke fundet", { status: 404 });
  }

  async alarm() {
    const s = this.state.storage;
    const antal = (await s.get("antal")) || {};
    // Noteres før GitHub-kaldet, så ændringer, der kommer imens, venter de fulde 60 sekunder.
    const start = Date.now();
    await s.put("sidst_startet", start);
    const r = await fetch(`https://api.github.com/repos/${this.env.GITHUB_REPO}/dispatches`, {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + this.env.GITHUB_TOKEN,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "lisen-varemodtagelse-worker",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ event_type: "smartpack", client_payload: { aendringer: antal } }),
    });
    await s.put("sidst_svar", { status: r.status, tid: Date.now() });
    if (r.status >= 300) {
      // GitHub svarede ikke ok – prøv igen om et par minutter; tællingen bevares.
      await s.setAlarm(Date.now() + 5 * 60_000);
      return;
    }
    // Træk kun de ændringer fra, der blev sendt med (nye kan være kommet til imens).
    const nu = (await s.get("antal")) || {};
    const i_alt = (await s.get("i_alt")) || {};
    for (const [k, v] of Object.entries(antal)) {
      i_alt[k] = (i_alt[k] || 0) + v;
      nu[k] = (nu[k] || 0) - v;
      if (nu[k] <= 0) delete nu[k];
    }
    await s.put({ i_alt, antal: nu });
  }
}
