#!/bin/bash
# debug-funcapp.sh — diagnose why the Function App isn't loading functions
# Usage: bash scripts/debug-funcapp.sh

RG="rg-saml-cert-rotation"
FUNC="samlcert-func-hefor3uaz27ae"

echo "====== 1. Getting Kudu credentials ======"
KV_USER=$(az functionapp deployment list-publishing-credentials \
    -g "$RG" -n "$FUNC" --query 'publishingUserName' -o tsv)
KV_PASS=$(az functionapp deployment list-publishing-credentials \
    -g "$RG" -n "$FUNC" --query 'publishingPassword' -o tsv)
CREDS="$KV_USER:$KV_PASS"

if [ -z "$KV_USER" ] || [ -z "$KV_PASS" ]; then
    echo "ERROR: Could not retrieve publishing credentials"
    exit 1
fi
echo "Credentials retrieved OK (user: $KV_USER)"

echo "====== 2. Files deployed to wwwroot ======"
curl -s -u "$CREDS" \
    "https://$FUNC.scm.azurewebsites.net/api/vfs/site/wwwroot/" \
    | python3 -c "
import sys, json
try:
    files = json.load(sys.stdin)
    for f in files:
        print(f.get('name','?'), f.get('size',''), f.get('mime',''))
except Exception as e:
    print('Parse error:', e)
    sys.stdin.seek(0)
    print(sys.stdin.read())
"

echo ""
echo "====== 3. Running processes (is worker alive?) ======"
curl -s -u "$CREDS" \
    "https://$FUNC.scm.azurewebsites.net/api/processes" \
    | python3 -c "
import sys, json
try:
    for p in json.load(sys.stdin):
        print(p.get('id','?'), p.get('name','?'), p.get('href',''))
except Exception as e:
    print('Parse error:', e)
"

echo ""
echo "====== 4. host.json from wwwroot ======"
curl -s -u "$CREDS" \
    "https://$FUNC.scm.azurewebsites.net/api/vfs/site/wwwroot/host.json"

echo ""
echo ""
echo "====== 5. Latest Kudu deployment log ======"
curl -s -u "$CREDS" \
    "https://$FUNC.scm.azurewebsites.net/api/deployments/latest/log" \
    | python3 -c "
import sys, json
try:
    for entry in json.load(sys.stdin):
        print(entry.get('log_time',''), entry.get('message',''))
except Exception as e:
    print('Parse error:', e)
    print(sys.stdin.read())
"

echo ""
echo "====== 6. EventLog / application errors via Kudu ======"
curl -s -u "$CREDS" \
    "https://$FUNC.scm.azurewebsites.net/api/vfs/LogFiles/Application/" \
    | python3 -c "
import sys, json
try:
    files = json.load(sys.stdin)
    for f in files:
        print(f.get('name','?'), f.get('size',''))
except Exception as e:
    print('No Application log files or parse error:', e)
"

echo ""
echo "====== 7. Application Insights — recent exceptions ======"
AI_NAME=$(az resource list -g "$RG" \
    --resource-type microsoft.insights/components \
    --query "[0].name" -o tsv 2>/dev/null)

if [ -n "$AI_NAME" ]; then
    echo "App Insights resource: $AI_NAME"
    az monitor app-insights query \
        --app "$AI_NAME" -g "$RG" \
        --analytics-query "exceptions | order by timestamp desc | take 10 | project timestamp, outerMessage, innermostMessage, outerType" \
        --offset 1h -o table 2>/dev/null || echo "Could not query App Insights"
else
    echo "No App Insights component found in resource group"
fi

echo ""
echo "====== 8. Direct HTTP probe (capture response body) ======"
curl -v "https://$FUNC.azurewebsites.net/api/applications" 2>&1 | head -60

echo ""
echo "====== Done ======"
