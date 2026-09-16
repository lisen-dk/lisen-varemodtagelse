#!/usr/bin/env python3
"""
Lægger filer op i GitHub-repoet og starter/følger kørsler – via GitHub's API (ingen browser).

Læser GITHUB_TOKEN fra noegler.env. Skriver aldrig tokenet ud.

Brug:
  python3 github.py push "besked" build.py template.html varemodtagelse.yml=.github/workflows/varemodtagelse.yml
      (lokal sti relativt til github-varemodtagelse; "lokal=sti-i-repo", hvis de er forskellige)
  python3 github.py koer            start workflowet manuelt
  python3 github.py seneste         vis de seneste kørsler
  python3 github.py log [run-id]    vis loggen fra trinnet "Hent tal og byg siden"
"""
import base64, io, json, os, re, sys, time, urllib.error, urllib.request, zipfile

HER = os.path.dirname(os.path.abspath(__file__))
REPO = "lisen-dk/lisen-varemodtagelse"
WORKFLOW = "varemodtagelse.yml"


def find_env():
    d = HER
    for _ in range(4):
        f = os.path.join(d, "noegler.env")
        if os.path.exists(f):
            return f
        d = os.path.dirname(d)
    sys.exit("Fandt ikke noegler.env")


TOKEN = None
for line in open(find_env(), encoding="utf-8"):
    if line.strip().startswith("GITHUB_TOKEN="):
        TOKEN = line.split("=", 1)[1].strip().strip('"').strip("'")
if not TOKEN:
    sys.exit("GITHUB_TOKEN mangler i noegler.env")


def gh(path, body=None, method=None, raw=False):
    url = path if path.startswith("http") else "https://api.github.com" + path
    h = {"Authorization": "Bearer " + TOKEN, "Accept": "application/vnd.github+json",
         "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "lisen-varemodtagelse"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=h, method=method or ("POST" if body is not None else "GET"))
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            b = r.read()
            return r.status, (b if raw else (json.loads(b) if b else {}))
    except urllib.error.HTTPError as e:
        b = e.read()
        try:
            return e.code, json.loads(b)
        except ValueError:
            return e.code, {"message": b[:200].decode("utf-8", "replace")}


def push(besked, filer, rod):
    """Én commit med alle filerne (git data API)."""
    s, ref = gh(f"/repos/{REPO}/git/ref/heads/main")
    if s != 200:
        sys.exit(f"Kan ikke læse main ({s}): {ref.get('message')}")
    base = ref["object"]["sha"]
    s, commit = gh(f"/repos/{REPO}/git/commits/{base}")
    tree = []
    for f in filer:
        lokal, _, f = f.partition("=") if "=" in f else (f, "", f)
        indhold = open(os.path.join(rod, lokal), "rb").read()
        s, blob = gh(f"/repos/{REPO}/git/blobs", {"content": base64.b64encode(indhold).decode(), "encoding": "base64"})
        if s != 201:
            sys.exit(f"Blob fejlede for {f} ({s}): {blob.get('message')}")
        tree.append({"path": f, "mode": "100644", "type": "blob", "sha": blob["sha"]})
    s, t = gh(f"/repos/{REPO}/git/trees", {"base_tree": commit["tree"]["sha"], "tree": tree})
    if s != 201:
        sys.exit(f"Tree fejlede ({s}): {t.get('message')}")
    if t["sha"] == commit["tree"]["sha"]:
        print("Ingen ændringer – intet at committe.")
        return base
    s, c = gh(f"/repos/{REPO}/git/commits", {"message": besked, "tree": t["sha"], "parents": [base]})
    if s != 201:
        sys.exit(f"Commit fejlede ({s}): {c.get('message')}")
    s, r = gh(f"/repos/{REPO}/git/refs/heads/main", {"sha": c["sha"]}, "PATCH")
    if s != 200:
        sys.exit(f"Opdatering af main fejlede ({s}): {r.get('message')}")
    print("Commit", c["sha"][:7], "–", besked, "–", len(filer), "filer")
    return c["sha"]


def koer():
    s, r = gh(f"/repos/{REPO}/actions/workflows/{WORKFLOW}/dispatches", {"ref": "main"})
    print("Startet" if s == 204 else f"Fejl {s}: {r.get('message')}")


def seneste(n=5):
    s, r = gh(f"/repos/{REPO}/actions/workflows/{WORKFLOW}/runs?per_page={n}")
    for run in r.get("workflow_runs", []):
        print(run["id"], f"#{run['run_number']}", run["event"], run["status"], run.get("conclusion"),
              run["head_sha"][:7], run["created_at"])
    return r.get("workflow_runs", [])


def log(run_id=None):
    if not run_id:
        runs = [x for x in seneste(10) if x["status"] == "completed"]
        run_id = runs[0]["id"]
    s, jobs = gh(f"/repos/{REPO}/actions/runs/{run_id}/jobs")
    for j in jobs.get("jobs", []):
        if j["name"] != "byg":
            continue
        s, b = gh(f"/repos/{REPO}/actions/jobs/{j['id']}/logs", raw=True)
        tekst = b.decode("utf-8", "replace")
        inde = False
        for line in tekst.splitlines():
            line = re.sub(r"^\S+Z ", "", line)
            if "python3 build.py" in line:
                inde = True
                continue
            if inde and (line.startswith("##[group]") or "upload-pages-artifact" in line):
                break
            if inde and not line.startswith("##[endgroup]") and not line.startswith("  "):
                print(line)
        print("Resultat:", j.get("conclusion"))


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "seneste"
    if cmd == "push":
        rod = os.path.dirname(HER)  # github-varemodtagelse
        push(sys.argv[2], sys.argv[3:], rod)
    elif cmd == "koer":
        koer()
    elif cmd == "seneste":
        seneste()
    elif cmd == "log":
        log(sys.argv[2] if len(sys.argv) > 2 else None)
