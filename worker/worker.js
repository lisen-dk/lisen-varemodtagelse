// Lisen Varemodtagelse – webhook-modtager for SmartPack.
//
// SmartPack kalder POST /smartpack (basic auth), når ordrer eller lagertal ændres.
// Workeren gemmer INGEN data fra SmartPack. Den samler ændringerne i et 30 sekunders vindue
// (Durable Object med alarm) og beder derefter GitHub om at bygge dashboardet igen
// (repository_dispatch "smartpack"). Mindst 60 sekunder mellem to opstarter.
//
// Hemmeligheder (sættes ved udrulning): HOOK_USER, HOOK_PASS, GITHUB_TOKEN
// Variabler: GITHUB_REPO (fx "lisen-dk/lisen-varemodtagelse")

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

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
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
    if (url.pathname === "/status") {
      return Response.json({
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
    await s.put({ i_alt, antal: nu, sidst_startet: Date.now() });
  }
}
