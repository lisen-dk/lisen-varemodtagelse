#!/usr/bin/env python3
"""
Varemodtagelse – overblik over åbne indkøbsordrer for lager og kundeservice.

Alt hentes direkte fra SmartPack (ingen Shopify-kald):
  1. åbne indkøbsordrer (PO'er)                 purchaseorder/list
  2. alle åbne ordrer inkl. ordrelinjer          order/list
  3. hyldeplaceringer for hele lageret           stock/list
  4. varedetaljer (navn, billede, total/reserveret) for ordrernes varer   item/list

Ordrerne klassificeres her med samme logik som Mechanic-opgaven "Lagertags på ordrer"
(se klassificer) – dashboardet afhænger ikke af tags.

Presell: ordrer med mindst én presell-linje; linjerne kobles til den tidligste åbne PO,
der har varianten på presell.

Flere lagre: ordrer, der hverken kan pakkes samlet i Ramløse (lager + butik) eller i Helsinge.
De varer på sådanne ordrer, der KUN ligger i Helsinge, skal flyttes til Ramløse – de samles på
en flytteliste.

Butik: butikken er sidste mulighed – kun det, som Lager Ramløse og Lager Helsinge ikke kan
dække, skal hentes i butikken (se beregn_butik).

Resultatet krypteres med adgangskoden (AES-GCM, nøgle fra PBKDF2) og skrives ind i
site/index.html, som GitHub Pages viser. Uden adgangskoden kan siden ikke læses.

Miljøvariabler (GitHub secrets):
  SMARTPACK_APP_ID, SMARTPACK_TOKEN, DASHBOARD_PASSWORD
Test uden netværk: TEST_DIR=mappe med po.json, sp_orders.json, stock.json og items.json
(samme format som SmartPacks API-svar).

Loggen skriver kun antal – aldrig ordrenumre eller varedata (repoet kan være offentligt).
"""
import base64
import collections
import gzip
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SP_BASE = "https://lisen.smartpack.dk/api/v1"
PBKDF2_ITER = 310000
# Fast salt: så husker enhederne adgangen, indtil adgangskoden skiftes.
SALT = b"lisen-varemodtagelse/v1"
# Cloudflare-Workeren, som dashboardet sender datoændringer til
WORKER_URL = os.environ.get("WORKER_URL") or "https://lisen-varemodtagelse.lone-c5f.workers.dev"
TEST_DIR = os.environ.get("TEST_DIR")
HER = os.path.dirname(os.path.abspath(__file__))
UD = os.path.join(HER, "site")


def log(*a):
    print(*a, flush=True)


# ---------------------------------------------------------------- HTTP

def http(url, data=None, headers=None, method=None, tries=6, timeout=300):
    for n in range(tries):
        try:
            h = dict(headers or {})
            h.setdefault("Accept-Encoding", "gzip")
            req = urllib.request.Request(url, data=data, headers=h, method=method)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                raw = r.read()
                if (r.headers.get("Content-Encoding") or "").lower() == "gzip":
                    raw = gzip.decompress(raw)
                return raw
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and n < tries - 1:
                time.sleep(min(60, 2 ** n * 2))
                continue
            raise RuntimeError(f"HTTP {e.code} fra {url.split('?')[0]}")
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if n < tries - 1:
                time.sleep(min(60, 2 ** n * 2))
                continue
            raise


# ---------------------------------------------------------------- SmartPack

def sp_get(path):
    url = path if path.startswith("http") else SP_BASE + path
    return json.loads(http(url, headers={
        "X-SmartPack-AppId": os.environ["SMARTPACK_APP_ID"],
        "X-SmartPack-AccessToken": os.environ["SMARTPACK_TOKEN"],
    }))


def sp_sider(path, maks=60):
    """Alle sider af en SmartPack-liste (følger nextPage; SmartPack giver højst 300 pr. side)."""
    out, sider, set_ids = [], 0, set()
    while path and sider < maks:
        d = sp_get(path)
        data = d.get("data") or []
        nye = [x for x in data if x.get("id") is None or x.get("id") not in set_ids]
        if not nye:
            break
        set_ids.update(x.get("id") for x in nye)
        out += nye
        nxt = d.get("nextPage") or ""
        path = nxt.split("/api/v1", 1)[1] if "/api/v1" in nxt else nxt
        sider += 1
    return out


def hent_po():
    if TEST_DIR:
        return json.load(open(os.path.join(TEST_DIR, "po.json")))
    # 1 = kladde, 2 = åben (bestilt hos leverandøren)
    return sp_sider("/purchaseorder/list?state=1,2&pageSize=300")


# Åbne ordrer: alt andet end Pakket (5) og Annulleret (6).
# -30 er ikke dokumenteret af SmartPack, men indeholder ordrer, der venter på presell-varer.
SP_ORDRE_STATES = "0,1,2,3,4,-5,-10,-20,-30"


def hent_sp_ordrer():
    if TEST_DIR:
        return json.load(open(os.path.join(TEST_DIR, "sp_orders.json")))
    return sp_sider(f"/order/list/?state={SP_ORDRE_STATES}&orderType=1&pageSize=300&p=1")


def ddmmyyyy(s):
    """SmartPacks "24-08-2026 13:13:50" -> "2026-08-24". Tom streng, hvis datoen ikke kan læses."""
    d = (s or "")[:10].split("-")
    return f"{d[2]}-{d[1]}-{d[0]}" if len(d) == 3 and len(d[2]) == 4 else ""


def hent_lager():
    """(sku -> [[hyldenavn, antal, flag]], returkasser) fra SmartPacks lagerliste. Flag K = karantæne.

    Returvarer, der er sat på en almindelig hylde, er almindeligt lager (SmartPack plukker dem).
    Returkasserne (Tote Retur…) er det, der er kommet retur og endnu ikke er sat på plads."""
    if TEST_DIR:
        rows = json.load(open(os.path.join(TEST_DIR, "stock.json")))
    else:
        rows = sp_get("/stock/list").get("data") or []
    pl = collections.defaultdict(lambda: collections.defaultdict(float))
    kasser = {}
    for r in rows:
        if (r.get("location") or "normal") != "normal":
            continue
        navn = r.get("placementName") or ""
        flag = "K" if r.get("quarantine") else ""
        pl[r.get("sku") or ""][(navn, flag)] += float(r.get("quantity") or 0)
        if "retur" in navn.lower():
            k = kasser.setdefault(navn, {"navn": navn, "stk": 0, "linjer": 0, "aeldst": ""})
            k["stk"] += float(r.get("quantity") or 0)
            k["linjer"] += 1
            d = ddmmyyyy(r.get("arrivalDate"))
            if d and (not k["aeldst"] or d < k["aeldst"]):
                k["aeldst"] = d
    for k in kasser.values():
        k["stk"] = tal(k["stk"])
    return ({sku: [[navn, tal(antal), flag] for (navn, flag), antal in d.items()] for sku, d in pl.items()},
            sorted(kasser.values(), key=lambda k: (k["aeldst"] or "9", -k["stk"])))


def hent_varer(skus):
    """sku -> varedetaljer (navn, størrelse, billede, total/reserveret) for de varer, ordrerne indeholder."""
    if TEST_DIR:
        rows = json.load(open(os.path.join(TEST_DIR, "items.json")))
    else:
        rows, skus = [], sorted(s for s in skus if s)
        pakke, laengde = [], 0
        def hent(pakke):
            q = urllib.parse.quote(",".join(pakke), safe="")
            return sp_sider(f"/item/list?includeDetails=true&pageSize=300&p=1&skus={q}", maks=5)
        for s in skus:
            if pakke and (len(pakke) >= 100 or laengde + len(s) > 3000):
                rows += hent(pakke)
                pakke, laengde = [], 0
            pakke.append(s)
            laengde += len(s) + 1
        if pakke:
            rows += hent(pakke)
    return {r.get("sku"): r for r in rows if r.get("sku")}


# ---------------------------------------------------------------- returneringer

# SmartPacks returpakker (/returnshipment/list): kunden opretter en retur og får en label,
# og pakken bliver først "færdig", når lageret har behandlet den.
#   state 1 = Ventende (oprettet, pakken er ikke modtaget)   3 = Færdig
#   state 2 = Modtaget                                       4 = Aflyst
# Listen kan ikke filtreres på dato eller status, så sagerne gemmes i state/retur.json
# (GitHub-cache mellem kørsler): de nyeste sider hentes hver gang, og hele vinduet
# gennemgås med mellemrum, fordi en sag skifter status uden at rykke op i listen.
RETUR_STATE = {1: "ventende", 2: "modtaget", 3: "faerdig", 4: "aflyst"}
RETUR_DAGE = int(os.environ.get("RETUR_DAGE") or 14)           # vindue for færdige sager
RETUR_VENT_DAGE = int(os.environ.get("RETUR_VENT_DAGE") or 60)  # ventende sager beholdes længere
RETUR_NYE_SIDER = int(os.environ.get("RETUR_NYE_SIDER") or 2)   # nyeste sider hver kørsel
RETUR_BAGUD_SIDER = int(os.environ.get("RETUR_BAGUD_SIDER") or 1)  # sider længere nede pr. kørsel
RETUR_TJEK = int(os.environ.get("RETUR_TJEK") or 60)            # ventende sager, der slås op enkeltvis
RETUR_FIL = os.path.join(HER, "state", "retur.json")


def retur_fragt(url):
    u = (url or "").lower()
    return "dao" if "dao" in u else "gls" if "gls" in u else ""


def retur_sag(x):
    """Kun det, siden skal bruge – ingen kundeoplysninger."""
    pk = x.get("package") or {}
    return {
        "nr": x.get("shipmentNo"), "ordre": x.get("orderNo") or "", "oid": x.get("orderId"),
        "st": tal(x.get("state")), "op": (x.get("createdAt") or "")[:19],
        "fa": (x.get("finishedAt") or "")[:19],
        "stk": tal(sum(float(l.get("quantity") or 0) for l in (x.get("lines") or []))),
        "fragt": retur_fragt(pk.get("trackingUrl")), "tt": pk.get("trackingUrl") or "",
    }


def hent_retur():
    """Returpakker. Gemmes i state/retur.json og holdes ajour lidt ad gangen.

    Listen kan hverken filtreres på dato eller status, og en side langt nede tager
    ca. 40 sekunder. Derfor:
      - de nyeste sider hentes hver kørsel (nye sager)
      - én side længere nede pr. kørsel, indtil vinduet er dækket
      - ventende sager slås op enkeltvis (0,2 sek. pr. stk), for de skifter status,
        uden at rykke op i listen – ældste og længst utjekkede først
    """
    if TEST_DIR:
        sti = os.path.join(TEST_DIR, "returnshipments.json")
        raa = json.load(open(sti)) if os.path.exists(sti) else []
        return [retur_sag(x) for x in raa]
    nu = datetime.now(timezone.utc)
    graense = (nu - timedelta(days=RETUR_DAGE)).strftime("%Y-%m-%d")
    vent_graense = (nu - timedelta(days=RETUR_VENT_DAGE)).strftime("%Y-%m-%d")
    gemt = {"sager": {}, "bagud": 3, "faerdig": False}
    try:
        gemt.update(json.load(open(RETUR_FIL)))
    except Exception:
        pass
    sager = gemt["sager"]
    nye, sider = 0, 0

    def laes(nr):
        d = sp_get(f"/returnshipment/list?pageSize=300&p={nr}")
        raekker = d.get("data") or []
        aeldst = ""
        for x in raekker:
            sag = retur_sag(x)
            sid = str(x.get("shipmentId"))
            dag = sag["op"][:10]
            if not aeldst or dag < aeldst:
                aeldst = dag
            if sid not in sager:
                sager[sid] = sag
                return_nye[0] += 1
            else:
                sager[sid].update(sag)
            sager[sid]["tjek"] = nu.strftime("%Y-%m-%dT%H:%M:%SZ")
        return len(raekker), aeldst

    return_nye = [0]
    for nr in range(1, RETUR_NYE_SIDER + 1):
        antal, _ = laes(nr)
        sider += 1
        if not antal:
            break
    if not gemt.get("faerdig"):
        for _ in range(RETUR_BAGUD_SIDER):
            nr = max(RETUR_NYE_SIDER + 1, tal(gemt.get("bagud")) or 3)
            antal, aeldst = laes(nr)
            sider += 1
            gemt["bagud"] = nr + 1
            if not antal or (aeldst and aeldst < graense):
                gemt["faerdig"] = True
                break
    nye = return_nye[0]

    # ventende sager: slå de ældste/længst utjekkede op enkeltvis
    ventende = sorted((sid for sid, s in sager.items() if s.get("st") == 1),
                      key=lambda sid: (sager[sid].get("tjek") or "", sager[sid].get("op") or ""))
    tjekket, aendret = 0, 0
    for sid in ventende[:RETUR_TJEK]:
        d = sp_get(f"/returnshipment/get/{sid}")
        x = d.get("data") if isinstance(d, dict) else None
        tjekket += 1
        if not x:
            continue
        sag = retur_sag(x)
        if sag["st"] != sager[sid].get("st"):
            aendret += 1
        sager[sid].update(sag)
        sager[sid]["tjek"] = nu.strftime("%Y-%m-%dT%H:%M:%SZ")

    gemt["sager"] = {k: v for k, v in sager.items()
                     if (v.get("op", "")[:10] >= graense
                         or (v.get("st") == 1 and v.get("op", "")[:10] >= vent_graense))}
    try:
        os.makedirs(os.path.dirname(RETUR_FIL), exist_ok=True)
        json.dump(gemt, open(RETUR_FIL, "w"), separators=(",", ":"))
    except Exception as e:
        log(f"Kunne ikke gemme returdata: {e}")
    ud = list(gemt["sager"].values())
    log(f"Returpakker: {len(ud)} sager · {sider} sider ({nye} nye) · "
        f"{tjekket} ventende tjekket ({aendret} skiftede status)"
        + ("" if gemt.get("faerdig") else f" · henter stadig bagud (side {gemt.get('bagud')})"))
    return ud


def beregn_retur(sager, kasser):
    """Status, ventende sager efter alder, udvikling pr. dag og lagerets returkasser."""
    idag = datetime.now(timezone.utc).date()
    stat = collections.Counter(RETUR_STATE.get(s["st"], "andet") for s in sager)
    ventende = sorted((s for s in sager if s["st"] == 1), key=lambda s: s["op"])
    behandling = []
    for s in sager:
        if s["st"] == 3 and s["op"] and s["fa"]:
            try:
                a = datetime.fromisoformat(s["op"][:10])
                b = datetime.fromisoformat(s["fa"][:10])
                behandling.append((b - a).days)
            except ValueError:
                pass
    behandling.sort()
    # fast akse: de sidste 14 dage, også dem uden sager
    dage = {(idag - timedelta(days=i)).isoformat(): {"op": 0, "fa": 0} for i in range(13, -1, -1)}
    for s in sager:
        if s["op"][:10] in dage:
            dage[s["op"][:10]]["op"] += 1
        if s["st"] == 3 and s["fa"][:10] in dage:
            dage[s["fa"][:10]]["fa"] += 1
    gammel = sum(1 for s in ventende if s["op"][:10] < (idag - timedelta(days=7)).isoformat())
    return {
        "dage_vindue": RETUR_DAGE,
        "stat": {k: stat.get(k, 0) for k in ("ventende", "modtaget", "faerdig", "aflyst")},
        "gamle": gammel,
        "stk_ventende": tal(sum(s["stk"] for s in ventende)),
        "median": behandling[len(behandling) // 2] if behandling else None,
        "snit": round(sum(behandling) / len(behandling), 1) if behandling else None,
        "behandlet": len(behandling),
        "ventende": ventende[:400],
        "flere_ventende": max(0, len(ventende) - 400),
        "dage": [{"d": d, **v} for d, v in sorted(dage.items())],
        "kasser": kasser,
        "kasse_stk": tal(sum(k["stk"] for k in kasser)),
    }


# ---------------------------------------------------------------- salg de sidste dage

# SmartPacks ordreliste kan ikke filtreres på dato, og en side dybt nede i listen tager ca. 12 sekunder.
# Derfor tælles salget op lidt ad gangen og gemmes i state/salg.json (GitHub-cache mellem kørsler):
#   - forfra:  de nyeste sider, indtil vi møder ordrer, vi allerede har talt med
#   - bagud:   nogle få sider længere nede, indtil de sidste SALG_DAGE er dækket
SALG_DAGE = int(os.environ.get("SALG_DAGE") or 14)
SALG_FORFRA = int(os.environ.get("SALG_FORFRA") or 3)     # højst så mange nye sider pr. kørsel
SALG_BAGUD = int(os.environ.get("SALG_BAGUD") or 2)       # højst så mange sider bagud pr. kørsel
SALG_FIL = os.path.join(HER, "state", "salg.json")
SALG_STATES = "5,6"   # 5 = pakket, 6 = afsluttet


def _salg_side(nr):
    return sp_get(f"/order/list/?orderType=1&state={SALG_STATES}&pageSize=300&p={nr}").get("data") or []


def _salg_tael(ordrer, gemt, graense):
    """Lægger nye ordrer til optællingen. Returnerer (nye ordrer, ældste dato på siden)."""
    nye, aeldst = 0, ""
    for o in ordrer:
        dag = (o.get("orderDate") or "")[:10]
        if dag and (not aeldst or dag < aeldst):
            aeldst = dag
        oid = str(o.get("id"))
        if not dag or dag < graense or oid in gemt["ordrer"] or o.get("isReturn"):
            continue
        gemt["ordrer"][oid] = dag
        dagbog = gemt["dage"].setdefault(dag, {})
        for it in o.get("items") or []:
            if it.get("type") == 1:      # NonItem (fragt, gebyr)
                continue
            sku = (it.get("sku") or "").strip()
            antal = tal(it.get("qty"))
            if sku and antal > 0:
                dagbog[sku] = dagbog.get(sku, 0) + antal
        nye += 1
    return nye, aeldst


def hent_salg():
    """sku -> solgte stk de sidste SALG_DAGE dage. Tælles op lidt ad gangen mellem kørslerne."""
    if TEST_DIR:
        sti = os.path.join(TEST_DIR, "salg.json")
        solgt = json.load(open(sti)) if os.path.exists(sti) else {}
        return {"solgt": solgt, "dage": SALG_DAGE, "daekket": SALG_DAGE if solgt else 0}
    graense = (datetime.now(timezone.utc) - timedelta(days=SALG_DAGE)).strftime("%Y-%m-%d")
    gemt = {"dage": {}, "ordrer": {}, "bagud": 2, "faerdig": False}
    try:
        gemt.update(json.load(open(SALG_FIL)))
    except Exception:
        pass
    # gamle dage ud af vinduet
    gemt["dage"] = {d: v for d, v in gemt["dage"].items() if d >= graense}
    gemt["ordrer"] = {o: d for o, d in gemt["ordrer"].items() if d >= graense}

    nye_i_alt, sider = 0, 0
    for nr in range(1, SALG_FORFRA + 1):
        nye, _ = _salg_tael(_salg_side(nr), gemt, graense)
        sider += 1
        nye_i_alt += nye
        if not nye:            # siden er allerede talt med – resten længere nede er det også
            break
    # bagud, indtil vinduet er dækket – derefter holder de nyeste sider det ved lige
    if not gemt.get("faerdig") and (not gemt["dage"] or min(gemt["dage"]) > graense):
        nr = max(2, tal(gemt.get("bagud")) or 2)
        for _ in range(SALG_BAGUD):
            side = _salg_side(nr)
            sider += 1
            if not side:
                gemt["faerdig"] = True
                break
            nye, aeldst = _salg_tael(side, gemt, graense)
            nye_i_alt += nye
            nr += 1
            gemt["bagud"] = nr
            if aeldst and aeldst < graense:
                gemt["faerdig"] = True
                break
    gemt["hentet"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        os.makedirs(os.path.dirname(SALG_FIL), exist_ok=True)
        json.dump(gemt, open(SALG_FIL, "w"), separators=(",", ":"))
    except Exception as e:
        log(f"Kunne ikke gemme salgstal: {e}")
    solgt = collections.Counter()
    for dagbog in gemt["dage"].values():
        solgt.update(dagbog)
    dage = sorted(gemt["dage"])
    daekket = (datetime.now(timezone.utc).date() - date.fromisoformat(dage[0])).days + 1 if dage else 0
    log(f"Salg: {len(gemt['ordrer'])} ordrer · {len(solgt)} varer · {sum(solgt.values())} stk "
        f"· {daekket} af {SALG_DAGE} dage dækket · {sider} nye sider ({nye_i_alt} nye ordrer)")
    return {"solgt": dict(solgt), "dage": SALG_DAGE, "daekket": daekket}


def lille_billede(url):
    """Shopify-CDN-billeder hentes i thumbnail-størrelse."""
    if url and "cdn.shopify.com" in url and "width=" not in url:
        return url + ("&" if "?" in url else "?") + "width=120"
    return url or ""


def sp_til_noder(sp_ordrer, lager, varer):
    """SmartPack-ordrer i det interne format, som klassificeringen bruger."""
    noder = []
    for o in sp_ordrer:
        if o.get("isReturn") or o.get("exclude"):
            continue
        linjer = []
        for it in o.get("items") or []:
            if it.get("type") != 0:          # fragt, gebyrer o.l.
                continue
            sku = (it.get("sku") or "").strip()
            v = varer.get(sku) or {}
            qty = tal(it.get("qty"))
            leveret = it.get("_StateDescription") == "Delivered"
            rest = 0 if leveret else max(0, qty - tal(it.get("shippedQty")))
            produkt = v.get("productName") or it.get("description") or sku
            str_ = v.get("variantName") or ""
            linjer.append({
                "sku": sku, "name": produkt + (" - " + str_ if str_ else ""),
                "currentQuantity": qty, "unfulfilledQuantity": rest,
                "image": {"url": lille_billede(v.get("imageUrl") or it.get("imageUrl"))},
                "sp_state": it.get("_StateDescription") or "",
                "variant": {"id": sku, "title": str_, "personale": {"jsonValue": {
                    "tot": tal(v.get("totalCombined")), "res": tal(v.get("reservedCombined")),
                    "pl": lager.get(sku) or []}}},
            })
        noder.append({"id": str(o.get("id")), "name": o.get("orderNo") or str(o.get("id")),
                      "createdAt": o.get("orderDate") or "", "sourceName": "", "sp_state": o.get("state"),
                      "lineItems": {"nodes": linjer}})
    return noder


# ---------------------------------------------------------------- beregning

def tal(x):
    x = float(x or 0)
    return int(x) if x == int(x) else round(x, 2)


def gid_id(g):
    """Shopify-gid ("gid://shopify/X/123") -> "123". Alt andet (SmartPack-id, SKU) returneres uændret –
    SKU'er kan indeholde "/"."""
    g = str(g or "")
    return g.rsplit("/", 1)[-1] if g.startswith("gid://") else g


def navn_farve(produktnavn):
    """"Navn | Farve | Type fra Mærke" -> (navn, farve). Mangler farven, er 2. del typen ("... fra ...")."""
    dele = [d.strip() for d in (produktnavn or "").split(" | ")]
    farve = dele[1] if len(dele) > 2 or (len(dele) == 2 and " fra " not in dele[1]) else ""
    return dele[0], farve


def omraade(hylde):
    if hylde.startswith("Hall Butik"):
        return "butik"
    if hylde.startswith("Hall Hel"):
        return "helsinge"
    return "lager"


VENTER_PAA_VARER = {"WaitingForStock", "OutOfStock"}


def placeringer(pl):
    """Hyldeplaceringer -> (antal pr. område, hylder pr. område).

    Karantæne (flag) og returkasser (Tote Retur…) tæller ikke som lager."""
    stk = {"lager": 0, "butik": 0, "helsinge": 0}
    hylder = {"lager": [], "butik": [], "helsinge": []}
    for r in pl or []:
        navn, antal, flag = (list(r) + [None, None, None])[:3]
        antal = tal(antal)
        if flag or antal <= 0 or (navn or "").startswith("Tote Retur"):
            continue
        omr = omraade(navn or "")
        stk[omr] += antal
        hylder[omr].append([navn, antal])
    return stk, hylder


STR_ORDEN = ["XXXS", "XXS", "XS", "XS/S", "S", "S/M", "M", "M/L", "L", "L/XL", "XL", "XL/XXL", "XXL", "XXXL",
             "2XL", "3XL", "4XL", "ONE SIZE", "OS"]


LANGE_STR = [("XXX-LARGE", "XXXL"), ("XX-LARGE", "XXL"), ("X-LARGE", "XL"), ("XXX-SMALL", "XXXS"),
             ("XX-SMALL", "XXS"), ("X-SMALL", "XS"), ("SMALL", "S"), ("MEDIUM", "M"), ("LARGE", "L"),
             ("ONESIZE", "ONE SIZE")]


def str_noegle(s):
    s = (s or "").strip().upper()
    for lang, kort in LANGE_STR:
        s = s.replace(lang, kort)
    s = s.replace(" / ", "/")
    if s in STR_ORDEN:
        return (0, STR_ORDEN.index(s), s)
    tal_del = "".join(c for c in s if c.isdigit() or c == ".")
    try:
        return (1, float(tal_del), s)
    except ValueError:
        return (2, 0, s)


def beregn_kun_helsinge(lager, varer, klass, salg=None):
    """Produkter med varianter, der KUN ligger i Helsinge (intet på Lager Ramløse eller i butikken)."""
    efterspurgt = collections.defaultdict(lambda: {"stk": 0, "ordrer": {}})
    for o, k in klass:
        for l in k["linjer"]:
            e = efterspurgt[l["sku"]]
            e["stk"] += l["q"]
            e["ordrer"][gid_id(o["id"])] = {"id": gid_id(o["id"]), "n": o["name"], "t": o["createdAt"]}
    grupper = {}
    for sku, pl in lager.items():
        stk, hylder = placeringer(pl)
        if stk["helsinge"] <= 0 or stk["lager"] > 0 or stk["butik"] > 0:
            continue
        v = varer.get(sku) or {}
        produkt = v.get("productName") or sku
        navn, farve = navn_farve(produkt)
        g = grupper.setdefault(produkt, {
            "navn": navn, "farve": farve, "maerke": v.get("manufacturerName") or "",
            "img": lille_billede(v.get("imageUrl")), "stk": 0, "ord_stk": 0,
            "varianter": [], "_hylder": collections.Counter(), "_ordrer": {},
        })
        e = efterspurgt.get(sku) or {"stk": 0, "ordrer": {}}
        g["stk"] += stk["helsinge"]
        g["ord_stk"] += e["stk"]
        g["img"] = g["img"] or lille_billede(v.get("imageUrl"))
        g["varianter"].append({"sku": sku, "str": v.get("variantName") or "", "stk": tal(stk["helsinge"]),
                               "res": tal(v.get("reservedCombined")), "ord": tal(e["stk"]),
                               "solgt": tal((salg or {}).get(sku))})
        for h, a in hylder["helsinge"]:
            g["_hylder"][h] += a
        g["_ordrer"].update(e["ordrer"])
    ud = []
    for g in grupper.values():
        g["varianter"].sort(key=lambda x: str_noegle(x["str"]))
        g["hylder"] = [[h, tal(a)] for h, a in g.pop("_hylder").most_common(8)]
        g["solgt"] = tal(sum(v["solgt"] for v in g["varianter"]))
        ordrer = sorted(g.pop("_ordrer").values(), key=lambda x: x["t"])
        g["antal_ordrer"] = len(ordrer)
        g["ordrer"] = [{"id": x["id"], "n": x["n"]} for x in ordrer[:12]]
        g["stk"], g["ord_stk"] = tal(g["stk"]), tal(g["ord_stk"])
        ud.append(g)
    ud.sort(key=lambda g: (-g["stk"], g["navn"].lower(), g["farve"].lower()))
    return ud


def klassificer(o):
    """Samme logik som Mechanic-opgaven "Lagertags på ordrer" – men beregnet her, uafhængigt af tags.

    Hver ikke-afsendt linje er enten
      - presell: SmartPack melder, at linjen venter på varer (WaitingForStock / OutOfStock), eller
      - lager:   med antal på Lager Ramløse, i butikken og i Helsinge.
    Butikken er sidste mulighed: en linje tæller kun som "Ramløse" via butikken, hvis varen
    hverken ligger på Lager Ramløse eller i Helsinge.
    Ordren er
      - PAK_Ramløse   alle lagerlinjer kan tages i Ramløse (har forrang)
      - PAK_Helsinge  ellers, hvis alle lagerlinjer kan tages i Helsinge
      - FlereLagre    ellers – varer uden for Lager Ramløse flyttes fra Helsinge
    Karantæne og returkasser (Tote Retur…) tæller ikke som lager. Varer i andre kasser
    (KlarTilPak, ButikOut, Modtagelse …) er i Ramløse. Kender vi ingen placering for en vare,
    som SmartPack har klar, regnes den som Ramløse.
    """
    linjer, antal_stk = [], 0
    for li in (o.get("lineItems") or {}).get("nodes") or []:
        antal_stk += tal(li.get("currentQuantity"))
        q = tal(li.get("unfulfilledQuantity"))
        v = li.get("variant")
        if q <= 0 or not v:
            continue
        p = ((v.get("personale") or {}).get("jsonValue")) or {}
        stk, hylder = placeringer(p.get("pl"))
        hel_hylder, butik_hylder = hylder["helsinge"], hylder["butik"]
        ramlose = stk["lager"] + stk["butik"]
        sp_state = li.get("sp_state")
        if sp_state:
            presell = sp_state in VENTER_PAA_VARER
        else:  # ældre dataformat uden SmartPack-linjestatus
            presell = tal(p.get("res")) > tal(p.get("tot")) or (ramlose <= 0 and stk["helsinge"] <= 0)
        ukendt_sted = ramlose <= 0 and stk["helsinge"] <= 0
        linjer.append({"li": li, "v": v, "vid": gid_id(v.get("id")), "sku": li.get("sku") or "", "q": q,
                       "presell": presell, "ramlose": ramlose, "hel": stk["helsinge"], "hylder": hel_hylder,
                       "lager_stk": stk["lager"], "butik_stk": stk["butik"], "butik_hylder": butik_hylder,
                       # butikken bruges kun, når varen hverken er på Lager Ramløse eller i Helsinge
                       "kan_r": stk["lager"] > 0 or ukendt_sted or (stk["butik"] > 0 and stk["helsinge"] <= 0)})
    lager = [l for l in linjer if not l["presell"]]
    pak = ""
    if lager:
        if all(l["kan_r"] for l in lager):
            pak = "PAK_Ramløse"
        elif all(l["hel"] > 0 for l in lager):
            pak = "PAK_Helsinge"
        else:
            pak = "FlereLagre"
    return {"linjer": linjer, "lager": lager, "presell": [l for l in linjer if l["presell"]],
            "pak": pak, "single": antal_stk == 1}


def beregn_flyt(klass, detaljer=None):
    """Ordrer, der ligger på to lagre, og de Helsinge-varer, der skal flyttes."""
    ordrer_ud, varer = [], {}
    for o, k in klass:
        if k["pak"] != "FlereLagre":
            continue
        venter = bool(k["presell"])
        oid = gid_id(o["id"])
        flyt = [l for l in k["lager"] if l["lager_stk"] <= 0 and l["hel"] > 0]
        ordrer_ud.append({
            "id": oid, "n": o["name"], "t": o["createdAt"],
            "linjer": len(k["lager"]), "flyt": tal(sum(l["q"] for l in flyt)), "presell": venter,
        })
        for l in flyt:
            li, v = l["li"], l["v"]
            vid = l["vid"]
            navn_str = li.get("name") or ""
            titel = v.get("title") or ""
            grund = navn_str[: -len(" - " + titel)] if titel and navn_str.endswith(" - " + titel) else navn_str
            navn, farve = navn_farve(grund)
            e = varer.setdefault(vid, {
                "vid": vid, "sku": l["sku"], "navn": navn, "farve": farve,
                "maerke": ((detaljer or {}).get(l["sku"]) or {}).get("manufacturerName") or "",
                "str": titel, "img": ((li.get("image") or {}).get("url")) or "",
                "stk": 0, "hel_stk": l["hel"], "hylder": sorted(l["hylder"], key=lambda h: -h[1])[:6],
                "ordrer": [], "aeldst": o["createdAt"],
            })
            e["stk"] += l["q"]
            e["ordrer"].append({"id": oid, "n": o["name"], "presell": venter})
            e["aeldst"] = min(e["aeldst"], o["createdAt"])
    ordrer_ud.sort(key=lambda x: x["t"])
    return {"ordrer": ordrer_ud, "varer": sorted(varer.values(), key=lambda x: (-x["stk"], x["aeldst"], x["sku"]))}


def vare_info(l, detaljer=None):
    li, v = l["li"], l["v"]
    navn_str = li.get("name") or ""
    titel = v.get("title") or ""
    grund = navn_str[: -len(" - " + titel)] if titel and navn_str.endswith(" - " + titel) else navn_str
    navn, farve = navn_farve(grund)
    return {"vid": l["vid"], "sku": l["sku"], "navn": navn, "farve": farve, "str": titel,
            "maerke": ((detaljer or {}).get(l["sku"]) or {}).get("manufacturerName") or "",
            "img": ((li.get("image") or {}).get("url")) or ""}


def beregn_helsinge(klass, detaljer=None):
    """Ordrer uden presell, hvor alle varer kan plukkes i Helsinge.

    kun = 1: varerne kan ikke tages i Ramløse – ordren SKAL pakkes i Helsinge.
    kun = 0: ordren kan pakkes begge steder (Ramløse har forrang i pluk-reglen).
    """
    ordrer, varer = [], {}
    for o, k in klass:
        if k["presell"] or not k["lager"]:
            continue
        if not all(l["hel"] > 0 for l in k["lager"]):
            continue
        kun = 0 if all(l["kan_r"] for l in k["lager"]) else 1
        oid = gid_id(o["id"])
        ordrer.append({"id": oid, "n": o["name"], "t": o["createdAt"], "kun": kun,
                       "stk": tal(sum(l["q"] for l in k["lager"])), "linjer": len(k["lager"])})
        for l in k["lager"]:
            e = varer.setdefault(l["vid"], dict(vare_info(l, detaljer), stk=0, ordrer=0,
                                                stk_kun=0, ordrer_kun=0,
                                                hel_stk=l["hel"],
                                                hylder=sorted(l["hylder"], key=lambda h: -h[1])[:6],
                                                aeldst=o["createdAt"]))
            e["stk"] += l["q"]
            e["ordrer"] += 1
            if kun:
                e["stk_kun"] += l["q"]
                e["ordrer_kun"] += 1
            e["aeldst"] = min(e["aeldst"], o["createdAt"])
    ordrer.sort(key=lambda x: x["t"])
    for e in varer.values():
        e["stk"], e["stk_kun"] = tal(e["stk"]), tal(e["stk_kun"])
    return {"ordrer": ordrer, "varer": sorted(varer.values(), key=lambda x: (-x["stk"], x["aeldst"]))}


def beregn_butik(klass, detaljer=None):
    """Varer, der skal hentes i butikken i Ramløse til webshop-ordrer.

    Butikken er altid sidste mulighed: så længe varen kan plukkes på Lager Ramløse eller
    Lager Helsinge, tages den der. Kun det, som de to lagre ikke kan dække, hentes i butikken.
    Ordrer, der kan pakkes nu (uden presell-varer), får lagrene først – ældste ordre først.
    """
    varer = {}
    for o, k in sorted(klass, key=lambda x: x[0]["createdAt"]):
        klar = not k["presell"]
        for l in k["lager"]:
            if l["butik_stk"] <= 0:
                continue
            e = varer.get(l["vid"])
            if e is None:
                e = varer[l["vid"]] = dict(vare_info(l, detaljer), lager_stk=l["lager_stk"], hel_stk=l["hel"], butik_stk=l["butik_stk"],
                                           hylder=sorted(l["butik_hylder"], key=lambda h: -h[1])[:6],
                                           klar=0, senere=0, ordrer=[], aeldst=o["createdAt"])
            e["klar" if klar else "senere"] += l["q"]
            e["ordrer"].append({"id": gid_id(o["id"]), "n": o["name"], "t": o["createdAt"],
                                "q": l["q"], "presell": not klar})
    ud = []
    for e in varer.values():
        andre = e["lager_stk"] + e["hel_stk"]  # butikken er sidste mulighed
        nu = min(e["butik_stk"], max(0, e["klar"] - andre))
        rest_lager = max(0, andre - e["klar"])
        senere = min(e["butik_stk"] - nu, max(0, e["senere"] - rest_lager))
        if nu <= 0 and senere <= 0:
            continue
        e["nu"], e["senere_butik"] = tal(nu), tal(senere)
        e["ordrer"].sort(key=lambda x: (x["presell"], x["t"]))
        ud.append(e)
    ud.sort(key=lambda x: (x["nu"] <= 0, x["aeldst"], x["sku"]))
    return ud


# Ordrer i kø: hver åben ordre får én grund til, at den ikke er sendt – den værste først.
#   ingenpo  presell-varer, som ingen åben indkøbsordre har        (kræver handling)
#   po       presell-varer, der kommer på en åben indkøbsordre
#   flyt     kan ikke pakkes samlet – noget skal flyttes fra Helsinge
#   hel      hele ordren pakkes i Helsinge
#   butik    en vare findes kun i butikken i Ramløse
#   klar     ingen hindring – alt kan plukkes på Lager Ramløse
KOE_ORDEN = ["ingenpo", "po", "flyt", "hel", "butik", "klar"]


def beregn_ordrekoe(klass, var_po, detaljer=None):
    """Åbne ordrer grupperet efter, hvad de venter på. Ældste ordre først i hver gruppe."""
    ud = []
    for o, k in klass:
        ikke_sendt = sum(l["q"] for l in k["linjer"])
        if ikke_sendt <= 0:
            continue
        e = {"id": gid_id(o["id"]), "n": o["name"], "t": o["createdAt"],
             "stk": tal(ikke_sendt), "linjer": len(k["linjer"])}
        if k["presell"]:
            datoer, uden = [], False
            for l in k["presell"]:
                po = var_po.get(l["vid"])
                if po:
                    datoer.append(po[0])       # (dato, po-id) – tidligste PO med varen
                else:
                    uden = True
            e["g"] = "ingenpo" if uden else "po"
            if not uden and datoer:
                dato, pid = max(datoer)        # ordren kan først sendes, når den sidste vare er hjemme
                e["dato"], e["po"] = dato, pid
            vigtige = k["presell"]
            e["q"] = tal(sum(l["q"] for l in k["presell"]))
            e["mangler"] = sum(1 for l in k["presell"] if l["vid"] not in var_po)
        elif k["pak"] == "FlereLagre":
            e["g"] = "flyt"
            vigtige = [l for l in k["lager"] if l["lager_stk"] <= 0 and l["hel"] > 0]
            e["q"] = tal(sum(l["q"] for l in vigtige))
        elif k["pak"] == "PAK_Helsinge":
            e["g"] = "hel"
            vigtige = k["lager"]
            e["q"] = tal(sum(l["q"] for l in k["lager"]))
        else:
            butik = [l for l in k["lager"] if l["butik_stk"] > 0 and l["lager_stk"] <= 0 and l["hel"] <= 0]
            if butik:
                e["g"] = "butik"
                vigtige = butik
                e["q"] = tal(sum(l["q"] for l in butik))
            else:
                e["g"] = "klar"
                vigtige = []
                e["q"] = 0
        if vigtige:
            e["varer"] = [dict(vare_info(l, detaljer), q=tal(l["q"])) for l in vigtige[:4]]
            if len(vigtige) > 4:
                e["flere"] = len(vigtige) - 4
        ud.append(e)
    ud.sort(key=lambda e: (KOE_ORDEN.index(e["g"]), e["t"]))
    return ud


def beregn(raw_po, raw_ordrer, lager=None, detaljer=None, salg=None):
    # PO'er i et enkelt format
    pos = []
    for p in raw_po:
        linjer = []
        for l in p.get("items") or []:
            it = l.get("item") or {}
            navn, farve = navn_farve(it.get("productName"))
            linjer.append({
                "sku": (l.get("sku") or "").strip(), "vid": (l.get("sku") or "").strip(),
                "qty": tal(l.get("qty")), "lev": tal(l.get("deliveredQty")),
                "under": tal(l.get("beingDeliveredQty")), "mangler": tal(l.get("undeliveredQty")),
                "ps": bool(l.get("preSell")), "navn": navn, "farve": farve,
                "str": it.get("variantName") or "", "maerke": it.get("manufacturerName") or "",
                "pris": float(l.get("unitPrice") or l.get("price") or 0),
            })
        pos.append({
            "id": p["id"], "ref": (p.get("referenceNo") or "").strip(),
            "lev": ((p.get("supplier") or {}).get("name") or "").strip(),
            "bestilt": (p.get("orderDate") or "")[:10],
            "dato": (p.get("expectedDeliveryDate") or p.get("orderDate") or "")[:10],
            "note": (p.get("note") or "").replace("\r\n", "\n").strip(),
            "godkendt": bool(p.get("approved")), "linjer": linjer,
            "kladde": p.get("state") == 1, "valuta": p.get("orderCurrency") or "DKK",
            "tracking": [t for t in (p.get("trackingNumbers") or []) if t][:5] if isinstance(p.get("trackingNumbers"), list) else [],
        })

    # vare -> åbne PO'er med varen, der ikke er leveret. Presell-markerede PO-linjer først,
    # derefter øvrige – hver gruppe tidligste først.
    var_po = collections.defaultdict(list)
    info = {}
    for p in pos:
        for l in p["linjer"]:
            if l["vid"]:
                info.setdefault(l["vid"], l)
            if l["mangler"] > 0 and l["vid"] and not p["kladde"]:   # kladder er ikke bestilt endnu
                var_po[l["vid"]].append((0 if l["ps"] else 1, p["dato"], p["id"]))
    for vid in var_po:
        var_po[vid] = [(d, pid) for _, d, pid in sorted(var_po[vid])]
    po_by_id = {p["id"]: p for p in pos}
    detaljer = detaljer or {}

    def billede(sku):
        return lille_billede((detaljer.get(sku) or {}).get("imageUrl"))

    def vare_navn(sku):
        v = detaljer.get(sku) or {}
        navn, farve = navn_farve(v.get("productName") or sku)
        return navn, farve, v.get("variantName") or ""
    ps_paa_po = collections.Counter()
    for p in pos:
        for l in p["linjer"]:
            if l["ps"] and l["mangler"] > 0:
                ps_paa_po[l["vid"]] += l["mangler"]

    # ordrer – klassificeret med samme logik som Mechanic (ikke ud fra tags)
    klass = [(o, klassificer(o)) for o in raw_ordrer if (o.get("sourceName") or "") != "pos"]
    ordrer = []
    for o, k in klass:
        if not k["presell"]:
            continue
        ordrer.append({"id": gid_id(o["id"]), "n": o["name"], "t": o["createdAt"],
                       "pak": k["pak"], "single": k["single"],
                       "lines": [{"sku": l["sku"], "q": l["q"], "vid": l["vid"]} for l in k["presell"]]})
    ordrer.sort(key=lambda o: o["t"])

    po_ord = collections.defaultdict(dict)
    po_linje_vent = collections.defaultdict(collections.Counter)
    var_vent = {}
    uden = []
    for o in ordrer:
        koblet = False
        for l in o["lines"]:
            if l["vid"] not in var_po:
                continue
            koblet = True
            pid = var_po[l["vid"]][0][1]
            e = po_ord[pid].setdefault(o["id"], {
                "id": o["id"], "n": o["n"], "t": o["t"], "stk": 0,
                "pak": [o["pak"]] if o["pak"] else [], "single": o["single"]})
            e["stk"] += l["q"]
            po_linje_vent[pid][l["vid"]] += l["q"]
            vv = var_vent.setdefault(l["vid"], {"stk": 0, "ordrer": set(), "aeldst": o["t"]})
            vv["stk"] += l["q"]
            vv["ordrer"].add(o["id"])
        if not koblet:
            uden.append({"id": o["id"], "n": o["n"], "t": o["t"],
                         "skus": [l["sku"] for l in o["lines"]][:6],
                         "varer": [dict(zip(("navn", "farve", "str"), vare_navn(l["sku"])),
                                        sku=l["sku"], img=billede(l["sku"])) for l in o["lines"]][:6]})

    ud_po = []
    for p in pos:
        mangler = [l for l in p["linjer"] if l["mangler"] > 0]
        if not mangler or p["kladde"]:
            continue
        ud_po.append({
            "id": p["id"], "ref": p["ref"], "lev": p["lev"], "bestilt": p["bestilt"], "dato": p["dato"],
            "godkendt": p["godkendt"], "note": p["note"],
            "maerker": sorted({l["maerke"] for l in p["linjer"] if l["maerke"]}),
            "stk": tal(sum(l["mangler"] for l in mangler)),
            "under": tal(sum(l["under"] for l in p["linjer"])),
            "modtaget": tal(sum(l["lev"] for l in p["linjer"])),
            "bestilt_stk": tal(sum(l["qty"] for l in p["linjer"])),
            "ps": tal(sum(l["mangler"] for l in mangler if l["ps"])),
            "linjer": [{"sku": l["sku"], "navn": l["navn"], "farve": l["farve"], "str": l["str"],
                        "stk": l["mangler"], "ps": l["ps"], "img": billede(l["sku"]),
                        "vent": po_linje_vent[p["id"]].get(l["vid"], 0)} for l in mangler],
            "ordrer": sorted(po_ord.get(p["id"], {}).values(), key=lambda x: x["t"]),
        })

    alle_po = []
    for p in pos:
        L = p["linjer"]
        vent = po_linje_vent.get(p["id"], {})
        img = next((billede(l["sku"]) for l in L if billede(l["sku"])), "")
        maerker = collections.Counter(l["maerke"] for l in L if l["maerke"])
        alle_po.append({
            "id": p["id"], "ref": p["ref"], "lev": p["lev"], "note": p["note"],
            "maerker": [m for m, _ in maerker.most_common()],
            "bestilt": p["bestilt"], "dato": p["dato"], "kladde": p["kladde"], "godkendt": p["godkendt"],
            "linjer": len(L), "varer": len({l["sku"] for l in L}),
            "bestilt_stk": tal(sum(l["qty"] for l in L)), "modtaget": tal(sum(l["lev"] for l in L)),
            "under": tal(sum(l["under"] for l in L)), "mangler": tal(sum(l["mangler"] for l in L)),
            "ps": tal(sum(l["mangler"] for l in L if l["ps"])),
            "ps_linjer": sum(1 for l in L if l["ps"] and l["mangler"] > 0),
            "solgt": tal(sum(vent.values())), "ordrer": len(po_ord.get(p["id"], {})),
            "vaerdi": round(sum(l["qty"] * l["pris"] for l in L)),
            "vaerdi_mangler": round(sum(l["mangler"] * l["pris"] for l in L)),
            "valuta": p["valuta"], "tracking": p["tracking"], "img": img,
        })

    varer = []
    for vid, vv in var_vent.items():
        l = info.get(vid, {})
        pid = var_po[vid][0][1]
        pp = po_by_id[pid]
        varer.append({
            "sku": l.get("sku"), "navn": l.get("navn"), "farve": l.get("farve"),
            "maerke": l.get("maerke"), "str": l.get("str"), "img": billede(l.get("sku")),
            "stk": vv["stk"], "ordrer": len(vv["ordrer"]), "aeldst": vv["aeldst"],
            "ps_po": ps_paa_po.get(vid, 0),
            "dato": var_po[vid][0][0], "po": pid, "ref": pp["ref"], "lev": pp["lev"],
        })

    return {
        "hentet": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "po": ud_po, "alle_po": alle_po, "varer": varer, "uden_po": uden, "forsalg_ordrer": len(ordrer),
        "flyt": beregn_flyt(klass, detaljer),
        "butik": beregn_butik(klass, detaljer),
        "kun_hel": beregn_kun_helsinge(lager or {}, detaljer or {}, klass, (salg or {}).get("solgt")),
        "helsinge": beregn_helsinge(klass, detaljer),
        "salg": {"dage": (salg or {}).get("dage", 0), "daekket": (salg or {}).get("daekket", 0)},
        "koe": beregn_ordrekoe(klass, var_po, detaljer),
    }


# ---------------------------------------------------------------- kryptering og side

def komprimer_billeder(d):
    """Fælles start på billedadresserne gemmes én gang (d["imgp"]); hvert billede får "~" + resten."""
    felter = []

    def find(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k == "img" and isinstance(v, str) and v:
                    felter.append(x)
                else:
                    find(v)
        elif isinstance(x, list):
            for v in x:
                find(v)
    find(d)
    starter = collections.Counter(x["img"].rsplit("/", 1)[0] + "/" for x in felter)
    if not starter:
        return
    prefix = starter.most_common(1)[0][0]
    d["imgp"] = prefix
    for x in felter:
        if x["img"].startswith(prefix):
            x["img"] = "~" + x["img"][len(prefix):]


def krypter(data_bytes, adgangskode):
    salt, iv = SALT, os.urandom(12)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITER)
    noegle = kdf.derive(adgangskode.encode("utf-8"))
    ct = AESGCM(noegle).encrypt(iv, gzip.compress(data_bytes, 9), None)
    return {"v": 1, "iter": PBKDF2_ITER, "salt": base64.b64encode(salt).decode(),
            "iv": base64.b64encode(iv).decode(), "ct": base64.b64encode(ct).decode()}


def main():
    adgangskode = os.environ.get("DASHBOARD_PASSWORD") or ""
    if len(adgangskode) < 6:
        sys.exit("DASHBOARD_PASSWORD mangler eller er kortere end 6 tegn.")

    raw_po = hent_po()
    log(f"SmartPack: {len(raw_po)} åbne indkøbsordrer ({sum(1 for p in raw_po if p.get('state') == 1)} kladder)")
    sp_ordrer = hent_sp_ordrer()
    lager, retur_kasser = hent_lager()
    skus = {(it.get("sku") or "").strip() for o in sp_ordrer for it in (o.get("items") or []) if it.get("type") == 0}
    skus |= {(l.get("sku") or "").strip() for p in raw_po for l in (p.get("items") or [])}
    kun_hel = {sku for sku, pl in lager.items()
               if (lambda st: st["helsinge"] > 0 and st["lager"] <= 0 and st["butik"] <= 0)(placeringer(pl)[0])}
    alle_skus = skus | kun_hel
    varer = hent_varer(alle_skus)
    raw_ordrer = sp_til_noder(sp_ordrer, lager, varer)
    log(f"SmartPack: {len(raw_ordrer)} åbne ordrer · {len(lager)} varer på lager · "
        f"{len(alle_skus & set(varer))} af {len(alle_skus)} varer med detaljer")

    salg = hent_salg()
    d = beregn(raw_po, raw_ordrer, lager, varer, salg)
    d["retur"] = beregn_retur(hent_retur(), retur_kasser)
    koblet = len({o["id"] for p in d["po"] for o in p["ordrer"]})
    log(f"PO'er med manglende varer: {len(d['po'])} · ordrer koblet til en PO: {koblet} · "
        f"uden PO: {len(d['uden_po'])} · presell-varianter i ordrer: {len(d['varer'])}")
    log(f"Butik: {len(d['butik'])} varianter skal hentes i butikken i Ramløse "
        f"({sum(v['nu'] for v in d['butik'])} stk nu, {sum(v['senere_butik'] for v in d['butik'])} stk senere)")
    log(f"Kun i Helsinge: {sum(len(g['varianter']) for g in d['kun_hel'])} varianter "
        f"({sum(g['stk'] for g in d['kun_hel'])} stk) i {len(d['kun_hel'])} produkter")
    log(f"Flere lagre: {len(d['flyt']['ordrer'])} ordrer · "
        f"{len(d['flyt']['varer'])} varianter skal flyttes fra Helsinge")
    hh = d["helsinge"]["ordrer"]
    log(f"Helsinge: {sum(1 for o in hh if o['kun'])} ordrer skal pakkes i Helsinge · "
        f"{len(hh)} kan pakkes der ({len(d['helsinge']['varer'])} varianter)")
    r = d["retur"]
    log(f"Returneringer: {r['stat']['ventende']} ventende ({r['gamle']} over 7 dage) · "
        f"{r['stat']['faerdig']} færdige · {r['kasse_stk']} stk i {len(r['kasser'])} returkasser")
    koe = collections.Counter(o["g"] for o in d["koe"])
    log("Ordrer i kø: " + " · ".join(f"{g} {koe.get(g, 0)}" for g in KOE_ORDEN))

    komprimer_billeder(d)
    blob = krypter(json.dumps(d, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), adgangskode)
    skabelon = open(os.path.join(HER, "template.html"), encoding="utf-8").read()
    side = skabelon.replace("__WORKER__", WORKER_URL).replace("__DATA__", json.dumps(blob))
    os.makedirs(UD, exist_ok=True)
    with open(os.path.join(UD, "index.html"), "w", encoding="utf-8") as f:
        f.write(side)
    with open(os.path.join(UD, "robots.txt"), "w") as f:
        f.write("User-agent: *\nDisallow: /\n")
    with open(os.path.join(UD, ".nojekyll"), "w") as f:
        f.write("")
    log(f"Side skrevet: {len(side) // 1024} KB")


if __name__ == "__main__":
    main()
