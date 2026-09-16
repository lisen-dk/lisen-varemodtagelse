#!/usr/bin/env python3
"""
Udruller Cloudflare-Workeren "lisen-varemodtagelse" og tilmelder den som webhook i SmartPack.

Læser nøgler fra noegler.env (i mappen over github-varemodtagelse):
  SMARTPACK_APP_ID, SMARTPACK_TOKEN, CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN, GITHUB_TOKEN,
  DASHBOARD_PASSWORD (samme som GitHub-hemmeligheden – bruges til at godkende datoændringer fra
  dashboardet; skiftes adgangskoden, skal Workeren udrulles igen)
Webhookens brugernavn/adgangskode oprettes første gang og gemmes i noegler-worker.env.

Brug:  python3 udrul.py            udrul Workeren (og vis adressen)
       python3 udrul.py webhook    tilmeld webhook i SmartPack (kun hvis den ikke findes)
       python3 udrul.py status     vis Workerens status
Skriver aldrig nøgler ud.
"""
import base64, hashlib, json, os, secrets, sys, urllib.error, urllib.request, uuid

HER = os.path.dirname(os.path.abspath(__file__))
NAVN = "lisen-varemodtagelse"
REPO = "lisen-dk/lisen-varemodtagelse"
DASH_ORIGIN = "https://lisen-dk.github.io"
# Samme afledning som dashboardet (build.py / template.html)
SALT, ITER = b"lisen-varemodtagelse/v1", 310000
SCOPES = ["order_updated", "order_state_updated", "item_quantity_updated"]


def find_env():
    d = HER
    for _ in range(4):
        f = os.path.join(d, "noegler.env")
        if os.path.exists(f):
            return d
        d = os.path.dirname(d)
    sys.exit("Fandt ikke noegler.env")


MAPPE = find_env()


def laes(f):
    k = {}
    if os.path.exists(f):
        for line in open(f, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                a, b = line.split("=", 1)
                k[a.strip()] = b.strip().strip('"').strip("'")
    return k


K = laes(os.path.join(MAPPE, "noegler.env"))
WF = os.path.join(MAPPE, "noegler-worker.env")
W = laes(WF)
if not W.get("HOOK_PASS"):
    W = {"HOOK_USER": "smartpack", "HOOK_PASS": secrets.token_urlsafe(32)}
    with open(WF, "w", encoding="utf-8") as f:
        f.write("# Oprettet af udrul.py – brugernavn/adgangskode til SmartPack-webhooken\n")
        for a, b in W.items():
            f.write(f"{a}={b}\n")
    os.chmod(WF, 0o600)


def http(url, data=None, headers=None, method=None):
    h = {"User-Agent": "lisen-varemodtagelse/1.0"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def cf(path, data=None, method=None, ctype="application/json"):
    h = {"Authorization": "Bearer " + K["CLOUDFLARE_API_TOKEN"]}
    if data is not None:
        h["Content-Type"] = ctype
    url = "https://api.cloudflare.com/client/v4" + path.replace("{acc}", K["CLOUDFLARE_ACCOUNT_ID"])
    s, b = http(url, data, h, method)
    try:
        return s, json.loads(b)
    except ValueError:
        return s, {"success": False, "errors": [{"message": b[:200].decode("utf-8", "replace")}]}


def fejl(r):
    return "; ".join(f"{e.get('code')}: {e.get('message')}" for e in (r.get("errors") or []))


def sp(path, body=None):
    h = {"X-SmartPack-AppId": K["SMARTPACK_APP_ID"], "X-SmartPack-AccessToken": K["SMARTPACK_TOKEN"]}
    data = None
    if body is not None:
        h["Content-Type"] = "application/json"
        data = json.dumps(body).encode()
    s, b = http("https://lisen.smartpack.dk/api/v1" + path, data, h, "POST" if body is not None else "GET")
    return s, json.loads(b or b"{}")


def subdomain():
    s, r = cf("/accounts/{acc}/workers/subdomain")
    if s == 200 and (r.get("result") or {}).get("subdomain"):
        return r["result"]["subdomain"]
    navn = "lisen-" + secrets.token_hex(3)
    s, r = cf("/accounts/{acc}/workers/subdomain", json.dumps({"subdomain": navn}).encode(), "PUT")
    if s != 200:
        sys.exit("Kunne ikke oprette workers.dev-underdomæne: " + fejl(r))
    return r["result"]["subdomain"]


def dash_key():
    pw = K.get("DASHBOARD_PASSWORD")
    if not pw:
        print("Bemærk: DASHBOARD_PASSWORD mangler i noegler.env – datoændring fra dashboardet er slået fra.")
        return []
    raw = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), SALT, ITER, 32)
    return [{"type": "secret_text", "name": "DASH_KEY", "text": base64.b64encode(raw).decode()}]


def upload(med_migrering):
    if not K.get("GITHUB_TOKEN"):
        sys.exit("GITHUB_TOKEN mangler i noegler.env")
    meta = {
        "main_module": "worker.js",
        "compatibility_date": "2025-09-01",
        "bindings": [
            {"type": "durable_object_namespace", "name": "SAMLER", "class_name": "Samler"},
            {"type": "plain_text", "name": "GITHUB_REPO", "text": REPO},
            {"type": "secret_text", "name": "HOOK_USER", "text": W["HOOK_USER"]},
            {"type": "secret_text", "name": "HOOK_PASS", "text": W["HOOK_PASS"]},
            {"type": "secret_text", "name": "GITHUB_TOKEN", "text": K["GITHUB_TOKEN"]},
            {"type": "plain_text", "name": "DASH_ORIGIN", "text": DASH_ORIGIN},
            {"type": "secret_text", "name": "SP_APP_ID", "text": K["SMARTPACK_APP_ID"]},
            {"type": "secret_text", "name": "SP_TOKEN", "text": K["SMARTPACK_TOKEN"]},
        ] + dash_key(),
        "observability": {"enabled": False},
    }
    if med_migrering:
        meta["migrations"] = {"new_tag": "v1", "new_sqlite_classes": ["Samler"]}
    kode = open(os.path.join(HER, "worker.js"), "rb").read()
    grænse = "----lisen" + uuid.uuid4().hex
    dele = [
        (f'--{grænse}\r\nContent-Disposition: form-data; name="metadata"; filename="metadata.json"\r\n'
         f"Content-Type: application/json\r\n\r\n").encode() + json.dumps(meta).encode() + b"\r\n",
        (f'--{grænse}\r\nContent-Disposition: form-data; name="worker.js"; filename="worker.js"\r\n'
         f"Content-Type: application/javascript+module\r\n\r\n").encode() + kode + b"\r\n",
        f"--{grænse}--\r\n".encode(),
    ]
    return cf(f"/accounts/{{acc}}/workers/scripts/{NAVN}", b"".join(dele), "PUT",
              "multipart/form-data; boundary=" + grænse)


def udrul():
    s, r = cf("/user/tokens/verify")
    if s != 200:
        sys.exit("Cloudflare-tokenet virker ikke: " + fejl(r))
    sub = subdomain()
    s, r = upload(True)
    if s != 200 and "migration" in fejl(r).lower():
        s, r = upload(False)
    if s != 200:
        sys.exit(f"Upload fejlede ({s}): " + fejl(r))
    s, r = cf(f"/accounts/{{acc}}/workers/scripts/{NAVN}/subdomain", json.dumps({"enabled": True}).encode(), "POST")
    if s != 200:
        print("Advarsel: kunne ikke slå workers.dev-adressen til: " + fejl(r))
    url = f"https://{NAVN}.{sub}.workers.dev"
    with open(WF, "a", encoding="utf-8") as f:
        if "WORKER_URL" not in W:
            f.write(f"WORKER_URL={url}\n")
    print("Workeren er udrullet:", url)
    return url


def worker_url():
    return laes(WF).get("WORKER_URL") or sys.exit("Workeren er ikke udrullet endnu")


def webhook():
    url = worker_url() + "/smartpack"
    s, r = sp("/webhook/list")
    eksisterende = r.get("data") or []
    for w in eksisterende:
        if (w.get("endpoint") or "").rstrip("/") == url:
            print("Webhooken findes allerede i SmartPack.")
            return
    print(f"SmartPack har {len(eksisterende)} andre webhooks – de røres ikke.")
    body = {"type": 1, "endpoint": url, "scope": SCOPES, "authenticationType": 1,
            "basicUsername": W["HOOK_USER"], "basicPassword": W["HOOK_PASS"]}
    s, r = sp("/webhook/create", body)
    print("Tilmeldt webhook:", s, r.get("msg"), "scope:", ", ".join(SCOPES))


def status():
    auth = "Basic " + base64.b64encode(f"{W['HOOK_USER']}:{W['HOOK_PASS']}".encode()).decode()
    s, b = http(worker_url() + "/status", headers={"Authorization": auth})
    print(s, b.decode("utf-8", "replace"))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "udrul"
    {"udrul": udrul, "webhook": webhook, "status": status}[cmd]()
