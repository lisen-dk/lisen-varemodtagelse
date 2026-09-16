#!/usr/bin/env python3
"""
Varemodtagelse – overblik over åbne indkøbsordrer for lager og kundeservice.

Henter
  1. åbne indkøbsordrer (PO'er) fra SmartPack
  2. alle åbne, ikke (fuldt) afsendte webshop-ordrer fra Shopify med varernes hyldeplaceringer
     (metafeltet lisen.personale, sat af SmartPack presell-sync)

Ordrerne klassificeres her med samme logik som Mechanic-opgaven "Lagertags på ordrer"
(se klassificer) – dashboardet afhænger IKKE af, om ordrerne er tagget i Shopify.

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
  SMARTPACK_APP_ID, SMARTPACK_TOKEN, SHOPIFY_CLIENT_ID, SHOPIFY_CLIENT_SECRET,
  DASHBOARD_PASSWORD
Test uden netværk: TEST_DIR=mappe med po.json (SmartPack-format) og orders.json (Shopify-noder).

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
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SHOP = "lisendk.myshopify.com"
API_VERSION = "2026-07"
SP_BASE = "https://lisen.smartpack.dk/api/v1"
PBKDF2_ITER = 310000
# Fast salt: så husker enhederne adgangen, indtil adgangskoden skiftes.
SALT = b"lisen-varemodtagelse/v1"
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


def hent_po():
    if TEST_DIR:
        return json.load(open(os.path.join(TEST_DIR, "po.json")))
    path, out, sider = "/purchaseorder/list?state=2&pageSize=500", [], 0
    while path and sider < 50:
        d = sp_get(path)
        out += d.get("data") or []
        path = d.get("nextPage")
        sider += 1
    return out


# Åbne SmartPack-ordrer (alt andet end Pakket og Annulleret), så dashboardet kan linke til SmartPack
SP_ORDRE_STATES = "0,1,2,3,4,-5,-10,-20"
SP_SIDE = 500


def hent_sp_ordrer():
    """[(smartpack-id, ordrenummer, externalId)] for åbne ordrer. Fejler det, linker siden til Shopify."""
    if TEST_DIR:
        f = os.path.join(TEST_DIR, "sp_orders.json")
        return json.load(open(f)) if os.path.exists(f) else []
    out, fuld, forrige = [], 0, None
    try:
        for side in range(1, 61):
            d = sp_get(f"/order/list/?state={SP_ORDRE_STATES}&orderType=1&pageSize={SP_SIDE}&p={side}")
            data = d.get("data") or []
            if not data or data[0].get("id") == forrige:
                break
            forrige = data[0].get("id")
            out += [[x.get("id"), x.get("orderNo") or "", str(x.get("externalId") or "")] for x in data]
            fuld = fuld or len(data)  # SmartPack giver højst 300 pr. side, uanset pageSize
            if len(data) < fuld:
                break
    except Exception as e:  # noqa: BLE001 – links er en bekvemmelighed, siden skal stadig bygges
        log(f"SmartPack-ordrer kunne ikke hentes ({type(e).__name__}) – ordrer linker til Shopify")
    return out


def sp_links(raw_ordrer, sp_ordrer):
    """{shopify-ordre-id: smartpack-id} for de åbne Shopify-ordrer, der findes i SmartPack."""
    efter_nr, efter_ext = {}, {}
    for sid, nr, ext in sp_ordrer:
        if sid is None:
            continue
        efter_nr.setdefault(nr.lstrip("#").strip(), sid)
        if ext:
            efter_ext.setdefault(ext, sid)
    ud = {}
    for o in raw_ordrer:
        oid = gid_id(o.get("id"))
        sid = efter_nr.get((o.get("name") or "").lstrip("#").strip()) or efter_ext.get(oid)
        if sid is not None:
            ud[oid] = sid
    return ud


# ---------------------------------------------------------------- Shopify

_token = None


def shopify_token():
    global _token
    if _token is None:
        data = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": os.environ["SHOPIFY_CLIENT_ID"],
            "client_secret": os.environ["SHOPIFY_CLIENT_SECRET"],
        }).encode()
        r = json.loads(http(f"https://{SHOP}/admin/oauth/access_token", data=data,
                            headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST"))
        _token = r["access_token"]
    return _token


def gql(query, variables=None, tries=8):
    url = f"https://{SHOP}/admin/api/{API_VERSION}/graphql.json"
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    for n in range(tries):
        r = json.loads(http(url, data=body, method="POST", headers={
            "Content-Type": "application/json", "X-Shopify-Access-Token": shopify_token()}))
        errors = r.get("errors") or []
        if any((e.get("extensions") or {}).get("code") == "THROTTLED" for e in errors):
            time.sleep(min(30, 2 ** n))
            continue
        if errors:
            koder = sorted({(e.get("extensions") or {}).get("code") or "?" for e in errors})
            if "ACCESS_DENIED" in koder:
                raise RuntimeError("Shopify-appen mangler adgangen read_orders (se vejledningen).")
            raise RuntimeError(f"GraphQL-fejl: {koder} {json.dumps(errors)[:300]}")
        t = ((r.get("extensions") or {}).get("cost") or {}).get("throttleStatus") or {}
        if t and t.get("currentlyAvailable", 1000) < 300:
            time.sleep(2)
        return r["data"]
    raise RuntimeError("GraphQL: for mange THROTTLED-svar")


ORDRE_Q = """
query($after: String) {
  orders(first: 20, after: $after, sortKey: CREATED_AT,
         query: "status:open AND (fulfillment_status:unfulfilled OR fulfillment_status:partial)") {
    pageInfo { hasNextPage endCursor }
    nodes {
      id name createdAt tags sourceName
      lineItems(first: 30) {
        nodes {
          sku name unfulfilledQuantity currentQuantity
          image { url(transform: {maxWidth: 120, maxHeight: 120}) }
          variant { id title personale: metafield(namespace: "lisen", key: "personale") { jsonValue } }
        }
      }
    }
  }
}"""


def hent_ordrer():
    if TEST_DIR:
        return json.load(open(os.path.join(TEST_DIR, "orders.json")))
    out, after = [], None
    for _ in range(1000):
        d = gql(ORDRE_Q, {"after": after})["orders"]
        out += d["nodes"]
        if not d["pageInfo"]["hasNextPage"]:
            break
        after = d["pageInfo"]["endCursor"]
    return out


# ---------------------------------------------------------------- beregning

def tal(x):
    x = float(x or 0)
    return int(x) if x == int(x) else round(x, 2)


def gid_id(g):
    return (g or "").rsplit("/", 1)[-1]


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


def klassificer(o):
    """Samme logik som Mechanic-opgaven "Lagertags på ordrer" – men beregnet her, uafhængigt af tags.

    Hver ikke-afsendt linje er enten
      - presell: varen ligger ikke på nogen hylde, eller der er reserveret flere stk., end der er
        på lager (res > tot), eller
      - lager:   med antal på Lager Ramløse, i butikken og i Helsinge.
    Butikken er sidste mulighed: en linje tæller kun som "Ramløse" via butikken, hvis varen
    hverken ligger på Lager Ramløse eller i Helsinge.
    Ordren er
      - PAK_Ramløse   alle lagerlinjer kan tages i Ramløse (har forrang)
      - PAK_Helsinge  ellers, hvis alle lagerlinjer kan tages i Helsinge
      - FlereLagre    ellers – varer uden for Lager Ramløse flyttes fra Helsinge
    Retur/karantæne og totes tæller ikke som lager.
    """
    linjer, antal_stk = [], 0
    for li in (o.get("lineItems") or {}).get("nodes") or []:
        antal_stk += tal(li.get("currentQuantity"))
        q = tal(li.get("unfulfilledQuantity"))
        v = li.get("variant")
        if q <= 0 or not v:
            continue
        p = ((v.get("personale") or {}).get("jsonValue")) or {}
        stk = {"lager": 0, "butik": 0, "helsinge": 0}
        hel_hylder, butik_hylder = [], []
        for r in p.get("pl") or []:
            navn, antal, flag = (list(r) + [None, None, None])[:3]
            antal = tal(antal)
            if flag or antal <= 0 or (navn or "").startswith("Tote"):
                continue
            omr = omraade(navn or "")
            stk[omr] += antal
            if omr == "helsinge":
                hel_hylder.append([navn, antal])
            elif omr == "butik":
                butik_hylder.append([navn, antal])
        ramlose = stk["lager"] + stk["butik"]
        presell = tal(p.get("res")) > tal(p.get("tot")) or (ramlose <= 0 and stk["helsinge"] <= 0)
        linjer.append({"li": li, "v": v, "vid": gid_id(v.get("id")), "sku": li.get("sku") or "", "q": q,
                       "presell": presell, "ramlose": ramlose, "hel": stk["helsinge"], "hylder": hel_hylder,
                       "lager_stk": stk["lager"], "butik_stk": stk["butik"], "butik_hylder": butik_hylder,
                       # butikken bruges kun, når varen hverken er på Lager Ramløse eller i Helsinge
                       "kan_r": stk["lager"] > 0 or (stk["butik"] > 0 and stk["helsinge"] <= 0)})
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


def beregn_flyt(klass):
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
                "str": titel, "img": ((li.get("image") or {}).get("url")) or "",
                "stk": 0, "hel_stk": l["hel"], "hylder": sorted(l["hylder"], key=lambda h: -h[1])[:6],
                "ordrer": [], "aeldst": o["createdAt"],
            })
            e["stk"] += l["q"]
            e["ordrer"].append({"id": oid, "n": o["name"], "presell": venter})
            e["aeldst"] = min(e["aeldst"], o["createdAt"])
    ordrer_ud.sort(key=lambda x: x["t"])
    return {"ordrer": ordrer_ud, "varer": sorted(varer.values(), key=lambda x: (x["aeldst"], x["sku"]))}


def vare_info(l):
    li, v = l["li"], l["v"]
    navn_str = li.get("name") or ""
    titel = v.get("title") or ""
    grund = navn_str[: -len(" - " + titel)] if titel and navn_str.endswith(" - " + titel) else navn_str
    navn, farve = navn_farve(grund)
    return {"vid": l["vid"], "sku": l["sku"], "navn": navn, "farve": farve, "str": titel,
            "img": ((li.get("image") or {}).get("url")) or ""}


def beregn_butik(klass):
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
                e = varer[l["vid"]] = dict(vare_info(l), lager_stk=l["lager_stk"], hel_stk=l["hel"], butik_stk=l["butik_stk"],
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


def beregn(raw_po, raw_ordrer):
    # PO'er i et enkelt format
    pos = []
    for p in raw_po:
        linjer = []
        for l in p.get("items") or []:
            it = l.get("item") or {}
            navn, farve = navn_farve(it.get("productName"))
            linjer.append({
                "sku": (l.get("sku") or "").strip(), "vid": str(it.get("externalId") or ""),
                "qty": tal(l.get("qty")), "lev": tal(l.get("deliveredQty")),
                "under": tal(l.get("beingDeliveredQty")), "mangler": tal(l.get("undeliveredQty")),
                "ps": bool(l.get("preSell")), "navn": navn, "farve": farve,
                "str": it.get("variantName") or "", "maerke": it.get("manufacturerName") or "",
            })
        pos.append({
            "id": p["id"], "ref": (p.get("referenceNo") or "").strip(),
            "lev": ((p.get("supplier") or {}).get("name") or "").strip(),
            "bestilt": (p.get("orderDate") or "")[:10],
            "dato": (p.get("expectedDeliveryDate") or p.get("orderDate") or "")[:10],
            "note": (p.get("note") or "").replace("\r\n", "\n").strip(),
            "godkendt": bool(p.get("approved")), "linjer": linjer,
        })

    # variant -> PO'er med presell, der ikke er leveret (tidligste først)
    var_po = collections.defaultdict(list)
    info = {}
    for p in pos:
        for l in p["linjer"]:
            if l["vid"]:
                info.setdefault(l["vid"], l)
            if l["ps"] and l["mangler"] > 0 and l["vid"]:
                var_po[l["vid"]].append((p["dato"], p["id"]))
    for v in var_po.values():
        v.sort()
    po_by_id = {p["id"]: p for p in pos}
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
                         "skus": [l["sku"] for l in o["lines"]][:6]})

    ud_po = []
    for p in pos:
        mangler = [l for l in p["linjer"] if l["mangler"] > 0]
        if not mangler:
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
                        "stk": l["mangler"], "ps": l["ps"],
                        "vent": po_linje_vent[p["id"]].get(l["vid"], 0)} for l in mangler],
            "ordrer": sorted(po_ord.get(p["id"], {}).values(), key=lambda x: x["t"]),
        })

    varer = []
    for vid, vv in var_vent.items():
        l = info.get(vid, {})
        pid = var_po[vid][0][1]
        pp = po_by_id[pid]
        varer.append({
            "sku": l.get("sku"), "navn": l.get("navn"), "farve": l.get("farve"),
            "maerke": l.get("maerke"), "str": l.get("str"),
            "stk": vv["stk"], "ordrer": len(vv["ordrer"]), "aeldst": vv["aeldst"],
            "ps_po": ps_paa_po.get(vid, 0),
            "dato": var_po[vid][0][0], "po": pid, "ref": pp["ref"], "lev": pp["lev"],
        })

    return {
        "hentet": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "po": ud_po, "varer": varer, "uden_po": uden, "forsalg_ordrer": len(ordrer),
        "flyt": beregn_flyt(klass),
        "butik": beregn_butik(klass),
    }


# ---------------------------------------------------------------- kryptering og side

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
    log(f"SmartPack: {len(raw_po)} åbne indkøbsordrer")
    raw_ordrer = hent_ordrer()
    log(f"Shopify: {len(raw_ordrer)} åbne, ikke afsendte ordrer")

    d = beregn(raw_po, raw_ordrer)
    sp_ordrer = hent_sp_ordrer()
    d["sp"] = sp_links(raw_ordrer, sp_ordrer)
    log(f"SmartPack-ordrer: {len(sp_ordrer)} åbne · {len(d['sp'])} af {len(raw_ordrer)} Shopify-ordrer linker til SmartPack")
    koblet = len({o["id"] for p in d["po"] for o in p["ordrer"]})
    log(f"PO'er med manglende varer: {len(d['po'])} · ordrer koblet til en PO: {koblet} · "
        f"uden PO: {len(d['uden_po'])} · presell-varianter i ordrer: {len(d['varer'])}")
    log(f"Butik: {len(d['butik'])} varianter skal hentes i butikken i Ramløse "
        f"({sum(v['nu'] for v in d['butik'])} stk nu, {sum(v['senere_butik'] for v in d['butik'])} stk senere)")
    log(f"Flere lagre: {len(d['flyt']['ordrer'])} ordrer · "
        f"{len(d['flyt']['varer'])} varianter skal flyttes fra Helsinge")

    blob = krypter(json.dumps(d, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), adgangskode)
    skabelon = open(os.path.join(HER, "template.html"), encoding="utf-8").read()
    side = skabelon.replace("__DATA__", json.dumps(blob))
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
