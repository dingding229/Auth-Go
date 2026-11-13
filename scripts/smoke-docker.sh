#!/bin/sh
# Build and smoke-test the single application image in an isolated project.
# Usage: sh scripts/smoke-docker.sh
# Reuse a source-built image: AUTHGO_SMOKE_SKIP_BUILD=1 AUTHGO_SMOKE_IMAGE=<repository:tag>
set -eu
[ "$(df -Pk . | awk 'NR==2 {print $4}')" -ge 10485760 ] || { echo "FAIL 可用磁盘不足10GB"; exit 1; }
unset AUTHGO_MASTER_KEY AUTHGO_ADMIN_PASSWORD AUTHGO_PUBLIC_URL AUTHGO_TRUSTED_PROXIES
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
PROJECT="${AUTHGO_SMOKE_PREFIX:-authgo-smoke}-$$"
if [ "${AUTHGO_SMOKE_SKIP_BUILD:-0}" = 1 ]; then
  SMOKE_IMAGE="${AUTHGO_SMOKE_IMAGE:?AUTHGO_SMOKE_SKIP_BUILD requires an existing source-built repository:tag}"
else
  SMOKE_IMAGE="$PROJECT:${AUTHGO_SMOKE_IMAGE_VERSION:-smoke}"
fi
TMP=$(mktemp -d "$ROOT/.authgo-smoke.XXXXXX")
chmod 700 "$TMP"
cleanup() {
  docker rm -f "$PROJECT-ip" "$PROJECT-large" "$PROJECT-sdk" "$PROJECT-restore" "$PROJECT-restore-files" >/dev/null 2>&1 || true
  docker compose --project-directory "$ROOT" --env-file "$TMP/.env" -f "$ROOT/docker-compose.yml" -f "$TMP/compose.override.yml" -p "$PROJECT" down -v >/dev/null 2>&1 || true
  docker volume rm "$PROJECT-gomod" "$PROJECT-gocache" "$PROJECT-restore-data" >/dev/null 2>&1 || true
  if [ "${AUTHGO_SMOKE_SKIP_BUILD:-0}" != 1 ]; then
    docker image rm "$SMOKE_IMAGE" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
: > "$TMP/.env"
printf 'SMOKE_PASSWORD=%s\n' "$(openssl rand -hex 24)" >> "$TMP/.env"
SMOKE_SUBNET="${AUTHGO_SMOKE_SUBNET:-10.253.$((($$ % 180) + 30)).0/24}"
SMOKE_VERSION="${AUTHGO_SMOKE_IMAGE_VERSION:-smoke}"
# Production Compose only pulls its published image. Keep source builds and
# local-only image selection in this disposable test override, never in deployment.
SMOKE_ROOT="$ROOT" SMOKE_IMAGE="$SMOKE_IMAGE" SMOKE_SUBNET="$SMOKE_SUBNET" SMOKE_VERSION="$SMOKE_VERSION" SMOKE_SKIP_BUILD="${AUTHGO_SMOKE_SKIP_BUILD:-0}" python3 - "$TMP/compose.override.yml" <<'PYCOMPOSE'
import ipaddress,json,os,pathlib,sys
subnet=os.environ["SMOKE_SUBNET"]
gateway=str(ipaddress.ip_network(subnet).network_address + 1) + "/32"
service={"image":os.environ["SMOKE_IMAGE"],"mem_limit":"512m","pull_policy":"never","networks":["authgo"],"ports":["127.0.0.1::8080"],"environment":{
    "AUTHGO_ADDR":":8080",
    "AUTHGO_DATA_DIR":"/data",
    "AUTHGO_ADMIN_USER":"smoke-owner",
    "AUTHGO_TRUSTED_PROXIES":gateway,
    "AUTHGO_SWAGGER_ENABLED":"${AUTHGO_SMOKE_SWAGGER_ENABLED:-false}",
    "AUTHGO_CLIENT_IP_RATE":"1",
    "AUTHGO_CLIENT_IP_BURST":"10",
}}
if os.environ["SMOKE_SKIP_BUILD"]!="1":
    service["build"]={"context":os.environ["SMOKE_ROOT"],"dockerfile":"Dockerfile","args":{
        "VERSION":os.environ["SMOKE_VERSION"],
        "COMMIT":"${AUTHGO_COMMIT:-unknown}",
        "BUILD_TIME":"${AUTHGO_BUILD_TIME:-unknown}",
    }}
# Compose v2.24.4+ !override replaces the production port instead of appending
# a second published port. JSON scalar values safely encode paths and build args.
ports=service.pop("ports")
lines=["services:","  authgo:","    ports: !override " + json.dumps(ports)]
lines.extend("    " + key + ": " + json.dumps(value) for key,value in service.items())
lines.append("networks: " + json.dumps({"authgo":{"ipam":{"config":[{"subnet":subnet}]}}}))
pathlib.Path(sys.argv[1]).write_text("\n".join(lines) + "\n")
PYCOMPOSE
compose() { docker compose --project-directory "$ROOT" --env-file "$TMP/.env" -f "$ROOT/docker-compose.yml" -f "$TMP/compose.override.yml" -p "$PROJECT" "$@"; }
printf 'AUTHGO_SMOKE_SUBNET=%s\n' "$SMOKE_SUBNET" >> "$TMP/.env"
if [ "${AUTHGO_SMOKE_SKIP_BUILD:-0}" != 1 ]; then compose build; fi
compose up -d --no-build
CID=$(compose ps -q authgo)
n=0
until [ "$(docker inspect --format '{{.State.Health.Status}}' "$CID")" = healthy ]; do
  n=$((n+1))
  if [ "$n" -ge 60 ]; then
    # Do not dump environment or credentials on failure.
    docker inspect --format 'status={{.State.Status}} health={{.State.Health.Status}} exit={{.State.ExitCode}}' "$CID"
    exit 1
  fi
  sleep 2
done
AUTHGO_BROWSER_IMAGE="$SMOKE_IMAGE" AUTHGO_BROWSER_PREFIX="$PROJECT-browser" sh "$ROOT/scripts/test-admin-browser.sh"
ENDPOINT=$(compose port authgo 8080)
SETUP_TOKEN=$(compose logs --no-color authgo | sed -n 's/.*"setup_token":"\([A-Za-z0-9_-]*\)".*/\1/p' | tail -n 1)
SETUP_TOKEN="$SETUP_TOKEN" BASE_URL="http://$ENDPOINT" python3 - "$TMP/.env" <<'PY'
import json, os, re, sys, urllib.request, urllib.error
base=os.environ['BASE_URL']
env=dict(line.rstrip('\n').split('=',1) for line in open(sys.argv[1]) if '=' in line)
def request(path, data=None, token=None, method=None):
    headers={'Content-Type':'application/json'} if data else {}
    if token: headers['Authorization']='Bearer '+token
    with urllib.request.urlopen(urllib.request.Request(base+path, data=json.dumps(data).encode() if data else None, headers=headers,method=method),timeout=10) as r:
        return r.status, r.headers, r.read()
status,_,raw=request('/healthz')
assert status==200 and json.loads(raw)['status']=='ok'
print('GET /healthz -> 200 {"status":"ok"}')
for path in ['/admin/login','/admin/licenses/123','/portal','/portal/activations']:
    status,headers,raw=request(path)
    assert status==200 and 'text/html' in headers['Content-Type'] and b'id="app"' in raw
    assert headers['Cache-Control']=='no-cache' and headers['X-Content-Type-Options']=='nosniff'
    assert headers['X-Frame-Options']=='DENY' and "object-src 'none'" in headers['Content-Security-Policy']
    assets=re.findall(r'(?:src|href)="(/assets/[^\"]+)"',raw.decode())
    assert assets
    for asset in assets:
        code,h,body=request(asset)
        assert code==200 and body and not body.startswith(b'<!doctype')
        assert 'max-age=31536000' in h['Cache-Control']
    print(f'GET {path} -> 200 HTML; {len(assets)} entry assets accessible')
status,headers,_=request('/admin/setup?token='+os.environ['SETUP_TOKEN'])
assert status==200 and headers['Cache-Control']=='no-store' and headers['Referrer-Policy']=='no-referrer'
status,_,raw=request('/api/v1/admin/status')
assert json.loads(raw)['data']['setup_required'] is True
for bad in ['', 'wrong-token']:
    try: request('/api/v1/admin/auth/setup',{'token':bad,'username':'smoke-owner','password':env['SMOKE_PASSWORD']})
    except urllib.error.HTTPError as e: assert e.code==401
    else: raise AssertionError('Invalid initialization token accepted')
status,_,raw=request('/api/v1/admin/auth/setup',{'token':os.environ['SETUP_TOKEN'],'username':'smoke-owner','password':env['SMOKE_PASSWORD']})
assert status==200
print('First-run setup -> invalid tokens rejected; account created and signed in')
try: request('/api/v1/admin/auth/setup',{'token':os.environ['SETUP_TOKEN'],'username':'duplicate','password':env['SMOKE_PASSWORD']})
except urllib.error.HTTPError as e: assert e.code==404
else: raise AssertionError('Setup token reused')
_,_,state=request('/api/v1/admin/status')
assert json.loads(state)['data']['setup_required'] is False
# The frontend guard, not the API server, owns setup-page availability.
status,headers,_=request('/admin/setup')
assert status==200 and headers['Cache-Control']=='no-store' and headers['Referrer-Policy']=='no-referrer'
body=json.loads(raw)
assert status==200 and body['code']=='OK' and body['data']['access_token'] and body['data']['refresh_token']
print('POST /api/v1/admin/auth/setup -> 200 code=OK; access_token/refresh_token present (redacted)')
_,_,raw=request('/api/v1/admin/applications',{'name':'容器持久化测试'},body['data']['access_token'])
application=json.loads(raw)
assert application['code']=='OK' and application['data']['id']
with open(os.path.join(os.path.dirname(sys.argv[1]),'application-id'),'w') as f: f.write(str(application['data']['id']))
admin_token=body['data']['access_token']
with open(os.path.join(os.path.dirname(sys.argv[1]),'admin-token'),'w') as f: f.write(admin_token)
_,_,doc=request('/api/v1/admin/integration/protocol',token=admin_token)
assert '# ' in json.loads(doc)['data']['text']
print('Authenticated protocol endpoint -> Markdown from API')
_,_,user_raw=request('/api/v1/admin/users',{'name':'容器用户','email':'smoke@example.com','portal_password':env['SMOKE_PASSWORD']},admin_token)
user=json.loads(user_raw)['data']
_,_,license_raw=request('/api/v1/admin/licenses',{'app_id':application['data']['id'],'user_id':user['id']},admin_token)
license=json.loads(license_raw)['data']
_,_,portal_raw=request('/api/v1/portal/user/login',{'email':'SMOKE@example.com','password':env['SMOKE_PASSWORD']})
portal_token=json.loads(portal_raw)['data']['portal_token']
_,_,list_raw=request('/api/v1/portal/licenses',token=portal_token)
assert json.loads(list_raw)['data']['total']==1
_,_,switch_raw=request('/api/v1/portal/switch',{'license_id':license['id']},portal_token)
assert json.loads(switch_raw)['data']['license']['id']==license['id']
request('/api/v1/admin/users/'+str(user['id']),{'status':'disabled'},admin_token,method='PATCH')
try: request('/api/v1/portal/session',token=portal_token)
except urllib.error.HTTPError as e: assert e.code==401
else: raise AssertionError('Disabled user token remained valid')
request('/api/v1/admin/users/'+str(user['id']),{'status':'active'},admin_token,method='PATCH')
try: request('/api/v1/portal/session',token=portal_token)
except urllib.error.HTTPError as e: assert e.code==401
else: raise AssertionError('Old user token revived')
print('User center -> user issuance, login, own-license switch, disable/token revocation OK')
_,_,config_raw=request('/api/v1/admin/applications/'+str(application['data']['id'])+'/connection',{'url':base},admin_token)
config=json.loads(config_raw)['data']['config']
import base64
assert config.startswith('authgo2.')
with open(os.path.join(os.path.dirname(sys.argv[1]),'sdk-config'),'w') as f: f.write(config)
with open(os.path.join(os.path.dirname(sys.argv[1]),'sdk-license'),'w') as f: f.write(license['key'])
payload=config.split('.',1)[1]
connection=json.loads(base64.urlsafe_b64decode(payload+'='*((-len(payload))%4)))
assert len(base64.urlsafe_b64decode(connection['gateway_key']+'='*((-len(connection['gateway_key']))%4)))==32
assert len(base64.b64decode(connection['public_key']))==32
assert connection['app_key']==application['data']['app_key']
# Never print the configuration or any secret. Only the structural assertions.
try: request('/api/v1/client/gateway',{'v':2,'k':'invalid','e':'','n':'','c':''})
except urllib.error.HTTPError as e: assert e.code==400 and e.read()==b'{"error":"invalid request"}'
else: raise AssertionError('Bad encrypted message accepted')
print('authgo2 configuration and encrypted gateway validation -> PASS')

_,_,raw=request('/api/v1/admin/applications/'+str(application['data']['id'])+'/secret',token=body['data']['access_token'])
import hashlib
with open(os.path.join(os.path.dirname(sys.argv[1]),'secret-digest'),'w') as f: f.write(hashlib.sha256(json.loads(raw)['data']['app_secret'].encode()).hexdigest())
try: request('/swagger/openapi.json')
except urllib.error.HTTPError as e:
    assert e.code==404
    print('Swagger disabled by default -> 404')
else: raise AssertionError('Swagger unexpectedly exposed')
PY
mkdir -p "$TMP/sdk"
cat > "$TMP/sdk/go.mod" <<'SDKMOD'
module authgo-smoke-sdk

go 1.26.0
require authgo/sdk v0.0.0
replace authgo/sdk => /src/sdk/go
SDKMOD
cat > "$TMP/sdk/main.go" <<'SDKGO'
package main
import (
 "context"
 "fmt"
 "os"
 "strings"
 sdk "authgo/sdk"
)
const authConfig = "AUTHGO_COMPILED_CONFIG"
func main() {
 key,e:=os.ReadFile("/smoke/sdk-license");if e!=nil{panic(e)}
 c,e:=sdk.New(authConfig,sdk.WithCacheDir("/tmp/sdk-cache"),sdk.WithFingerprint(func()(string,error){return strings.Repeat("a",64),nil}));if e!=nil{panic(e)}
 ctx:=context.Background();r,e:=c.Check(ctx,string(key));if e!=nil{panic(e)}
 if r.Availability!="online"{panic("not online")};if e=c.Validate(r.Ticket());e!=nil{panic(e)}
 if _,e=c.Verify(ctx);e!=nil{panic(e)};if _,e=c.Heartbeat(ctx);e!=nil{panic(e)};if e=c.Deactivate(ctx);e!=nil{panic(e)}
 fmt.Println("Go SDK encrypted activate/verify/heartbeat/deactivate via single Go server -> PASS; signed ticket validated")
}
SDKGO
python3 - "$TMP" <<'SDKBUILD'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]);source=root/'sdk/main.go'
source.write_text(source.read_text().replace('"AUTHGO_COMPILED_CONFIG"',json.dumps((root/'sdk-config').read_text())))
SDKBUILD
docker run --rm --name "$PROJECT-sdk" --network host -v "$ROOT:/src:ro" -v "$TMP:/smoke:ro" -v "$PROJECT-gomod:/go/pkg/mod" -v "$PROJECT-gocache:/root/.cache/go-build" -w /smoke/sdk --memory=1536m golang:1.26-alpine go run .
compose exec -T authgo /authgo healthcheck
compose exec -T authgo /authgo version
docker inspect --format 'user={{.Config.User}} health={{.State.Health.Status}} read_only={{.HostConfig.ReadonlyRootfs}}' "$CID"
[ "$(compose ps --services | wc -l | tr -d ' ')" = 1 ]
docker export "$CID" | tar -tf - > "$TMP/image-files"
! grep -Eq '(^|/)(node_modules|nginx)(/|$)' "$TMP/image-files"
echo 'One nonroot, read-only container owns UI and API; no Node/nginx runtime'
# A separately named network client proves an untrusted peer cannot rotate its identity using forged XFF.
NETWORK="${PROJECT}_authgo"
SUBNET=$(grep '^AUTHGO_SMOKE_SUBNET=' "$TMP/.env" | cut -d= -f2)
CLIENT_IP="${SUBNET%0/24}23"
docker run --rm -i --name "$PROJECT-ip" --network "$NETWORK" --ip "$CLIENT_IP" --memory=128m python:3.13-alpine python - <<'PYIP'
import json, urllib.request, urllib.error
# Direct Go API routes never fall back to HTML.
for path in ['/api/missing', '/api/v1/missing']:
    try: urllib.request.urlopen('http://authgo:8080'+path,timeout=10)
    except urllib.error.HTTPError as e:
        assert e.code==404 and 'application/json' in e.headers['Content-Type'];json.loads(e.read())
    else: raise AssertionError(path)
for i in range(70):
    r=urllib.request.Request('http://authgo:8080/api/v1/client/gateway',data=b'{}',headers={'Content-Type':'application/json','X-Forwarded-For':'203.0.113.'+str(i+1)})
    try: urllib.request.urlopen(r,timeout=5)
    except urllib.error.HTTPError as e: assert e.code==400
codes=[]
for i in range(7):
    r=urllib.request.Request('http://authgo:8080/api/v1/admin/auth/login',data=json.dumps({'username':'smoke-ip-limit','password':'incorrect-password'}).encode(),headers={'Content-Type':'application/json','X-Forwarded-For':'198.51.100.'+str(i+1)})
    try: urllib.request.urlopen(r,timeout=5)
    except urllib.error.HTTPError as e: codes.append(e.code)
assert 429 in codes, codes
print('API unknown routes -> JSON 404; changing forged XFF still rate limited')
PYIP
sleep 3
ENDPOINT=$(compose port authgo 8080)
CLIENT_IP="$CLIENT_IP" BASE_URL="http://$ENDPOINT" SMOKE_DIR="$TMP" python3 - <<'PYLOG'
import os,json,urllib.request
headers={'Authorization':'Bearer '+open(os.path.join(os.environ['SMOKE_DIR'],'admin-token')).read()}
u=os.environ['BASE_URL']+'/api/v1/admin/verify-logs?ip='+os.environ['CLIENT_IP']
with urllib.request.urlopen(urllib.request.Request(u,headers=headers),timeout=10) as r: rows=json.load(r)['data']['items']
assert rows and all(x['ip']==os.environ['CLIENT_IP'] for x in rows),rows
print('External client IP preserved in verification log and rate limiter; forged XFF cannot rotate IP')
PYLOG
compose logs --no-color authgo | grep -q '\"ip\":\"'"$CLIENT_IP"'\"'

compose restart authgo
sleep 3
# Docker can reassign a dynamically published host port on restart.
ENDPOINT=$(compose port authgo 8080)
BASE_URL="http://$ENDPOINT" python3 - "$TMP/.env" <<'PY'
import json,os,sys,time,urllib.request,urllib.error
env=dict(line.rstrip('\n').split('=',1) for line in open(sys.argv[1]) if '=' in line)
r=urllib.request.Request(os.environ['BASE_URL']+'/api/v1/admin/auth/login',data=json.dumps({'username':'smoke-owner','password':env['SMOKE_PASSWORD']}).encode(),headers={'Content-Type':'application/json'})
for attempt in range(30):
    try:
        with urllib.request.urlopen(r,timeout=10) as response:
            assert json.load(response)['code']=='OK'
        break
    except (urllib.error.URLError,ConnectionError):
        if attempt==29: raise
        time.sleep(1)
with urllib.request.urlopen(r,timeout=10) as response:
    token=json.load(response)['data']['access_token']
cid=open(os.path.join(os.path.dirname(sys.argv[1]),'application-id')).read()
with urllib.request.urlopen(urllib.request.Request(os.environ['BASE_URL']+'/api/v1/admin/applications/'+cid,headers={'Authorization':'Bearer '+token}),timeout=10) as response:
    assert json.load(response)['data']['name']=='容器持久化测试'
with urllib.request.urlopen(urllib.request.Request(os.environ['BASE_URL']+'/api/v1/admin/applications/'+cid+'/secret',headers={'Authorization':'Bearer '+token}),timeout=10) as response:
    import hashlib
    secret=json.load(response)['data']['app_secret']
assert hashlib.sha256(secret.encode()).hexdigest()==open(os.path.join(os.path.dirname(sys.argv[1]),'secret-digest')).read()
print('Restart with the same named volume -> login OK; application preserved; encrypted secret decrypts identically')
r=urllib.request.Request(os.environ['BASE_URL']+'/api/v1/portal/user/login',data=json.dumps({'email':'smoke@example.com','password':env['SMOKE_PASSWORD']}).encode(),headers={'Content-Type':'application/json'})
with urllib.request.urlopen(r,timeout=10) as response:
    assert json.load(response)['data']['portal_token']
print('User center login after restart -> OK; user password/status persisted')
PY
# Swagger remains owned by its existing Go routes when enabled.
printf 'AUTHGO_SMOKE_SWAGGER_ENABLED=true\n' >> "$TMP/.env"
compose up -d --no-build
ENDPOINT=$(compose port authgo 8080)
BASE_URL="http://$ENDPOINT" SMOKE_DIR="$TMP" python3 - <<'PYDOC'
import json,os,time,urllib.request,urllib.error
base=os.environ['BASE_URL']
for attempt in range(30):
    try:
        with urllib.request.urlopen(base+'/swagger/openapi.json',timeout=10) as r:
            spec=json.load(r)
        break
    except (urllib.error.URLError,ConnectionError):
        if attempt==29: raise
        time.sleep(1)
assert spec['openapi']=='3.1.0'
assert not any(path.startswith('/api/v1/admin') for path in spec['paths'])
assert 'AdminBearer' not in spec.get('components',{}).get('securitySchemes',{})
admin_token=open(os.path.join(os.environ['SMOKE_DIR'],'admin-token')).read()
request=urllib.request.Request(base+'/api/v1/admin/docs/openapi.json',headers={'Authorization':'Bearer '+admin_token})
with urllib.request.urlopen(request,timeout=10) as r:
    private_spec=json.load(r)['data']
assert private_spec['openapi']=='3.1.0' and '/api/v1/admin/auth/login' in private_spec['paths']
properties=set(private_spec['components']['schemas']['licensing.CreateInput']['properties'])
assert {'app_id','user_id','verify_methods','max_activations','validity_rule','features','maintenance_days','maintenance_until'} <= properties
assert not properties.intersection({'ip_whitelist','domain_whitelist','require_domain_verification','ip_lock_mode','allowed_client_versions','unbind_limit','unbind_cooldown_seconds'})
with urllib.request.urlopen(base+'/swagger/',timeout=10) as r:
    assert 'Auth Go 接口文档' in r.read().decode()
for path in ['/swagger/swagger-ui.css','/swagger/swagger-ui-bundle.js','/swagger/initializer.js']:
    with urllib.request.urlopen(base+path,timeout=10) as r:
        assert r.status==200 and r.read()
print('Public Swagger -> no management operations; authenticated management OpenAPI 3.1.0; UI assets accessible')
PYDOC
CID=$(compose ps -q authgo)
n=0
until [ "$(docker inspect --format '{{.State.Health.Status}}' "$CID")" = healthy ]; do
  n=$((n+1))
  [ "$n" -lt 60 ] || exit 1
  sleep 2
done
# Exercise real Go backup streaming/Range above the 64MiB /tmp ceiling.
# Add a test-only 80MiB SQLite table to this isolated data volume while stopped.
compose stop authgo
docker run --rm -i --name "$PROJECT-large" --memory=256m -v "${PROJECT}_authgo_data:/data" python:3.13-alpine python - <<'PYLARGE'
import sqlite3
with sqlite3.connect('/data/authgo.db') as db:
    db.execute('CREATE TABLE smoke_stream_probe (payload BLOB)')
    db.executemany('INSERT INTO smoke_stream_probe VALUES (randomblob(?))', [(1024*1024,)]*80)
PYLARGE
compose start authgo
ENDPOINT=$(compose port authgo 8080)
BASE_URL="http://$ENDPOINT" SMOKE_DIR="$TMP" python3 - <<'PYSTREAM'
import os,json,time,urllib.request,urllib.error
base=os.environ['BASE_URL']; root=os.environ['SMOKE_DIR']
env=dict(line.rstrip('\n').split('=',1) for line in open(root+'/.env') if '=' in line)
for attempt in range(30):
    try:
        req=urllib.request.Request(base+'/api/v1/admin/auth/login',data=json.dumps({'username':'smoke-owner','password':env['SMOKE_PASSWORD']}).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=10) as r: token=json.load(r)['data']['access_token']
        break
    except (urllib.error.URLError,ConnectionError):
        if attempt==29: raise
        time.sleep(1)
headers={'Authorization':'Bearer '+token,'Content-Type':'application/json'}
with urllib.request.urlopen(urllib.request.Request(base+'/api/v1/admin/system/backups',data=b'{}',headers=headers),timeout=60) as r: backup=json.load(r)['data']
url=base+'/api/v1/admin/system/backups/'+backup['name']
with urllib.request.urlopen(urllib.request.Request(url,headers=headers),timeout=60) as r:
    size=int(r.headers['Content-Length']);assert size>80*1024*1024
    assert r.headers.get('Content-Security-Policy') is None
    count=0
    while chunk:=r.read(65536): count+=len(chunk)
    assert count==size
with urllib.request.urlopen(urllib.request.Request(url,headers={**headers,'Range':f'bytes={size-2097152}-'}),timeout=10) as r:
    assert r.status==206 and r.headers['Content-Range']==f'bytes {size-2097152}-{size-1}/{size}'
    assert len(r.read())==2097152
with urllib.request.urlopen(urllib.request.Request(url,headers=headers),timeout=60) as r, open(root+'/restore.zip','wb') as f:
    import shutil
    shutil.copyfileobj(r,f)
print('Real Go backup streaming >80MiB and 2MiB Range -> PASS; API security headers unchanged')
PYSTREAM
# Offline restoration into a NEW named volume. The original service is stopped;
# no old WAL/SHM is mixed into the VACUUM snapshot, and no online import is used.
compose stop authgo
[ "$(docker inspect --format '{{.State.Running}}' "$(compose ps -aq authgo)")" = false ]
docker volume create "$PROJECT-restore-data" >/dev/null
docker run --rm -i --name "$PROJECT-restore-files" --memory=256m \
  -v "$PROJECT-restore-data:/data" -v "$TMP:/smoke:ro" python:3.13-alpine python - <<'PYFILES'
import base64,os,shutil,sqlite3,zipfile
# Model stale files already present in the destination. They must be removed.
for suffix in ['-wal','-shm']:
    open('/data/authgo.db'+suffix,'wb').write(b'old-database-not-this-snapshot')
for suffix in ['-wal','-shm']:
    os.remove('/data/authgo.db'+suffix)
with zipfile.ZipFile('/smoke/restore.zip') as z:
    assert sorted(z.namelist())==['authgo.db','master.key'] and z.testzip() is None
    for name in ['authgo.db','master.key']:
        with z.open(name) as src,open('/data/'+name,'wb') as dst: shutil.copyfileobj(src,dst)
        os.chown('/data/'+name,65532,65532);os.chmod('/data/'+name,0o600)
assert len(base64.b64decode(open('/data/master.key','rb').read().strip(),validate=True))==32
with sqlite3.connect('file:/data/authgo.db?mode=ro',uri=True) as db:
    assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
os.chown('/data',65532,65532);os.chmod('/data',0o700)
for name,mode in [('/data',0o700),('/data/authgo.db',0o600),('/data/master.key',0o600)]:
    st=os.stat(name);assert (st.st_uid,st.st_gid,st.st_mode&0o777)==(65532,65532,mode)
assert not os.path.exists('/data/authgo.db-wal') and not os.path.exists('/data/authgo.db-shm')
print('Offline named-volume restore: SQLite integrity=ok; UID:GID=65532:65532; directory=0700; DB/key=0600; stale WAL/SHM absent')
PYFILES
docker run -d --name "$PROJECT-restore" --memory=512m --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m --security-opt no-new-privileges:true --cap-drop ALL \
  -p "$ENDPOINT:8080" -v "$PROJECT-restore-data:/data" \
  "$SMOKE_IMAGE" >/dev/null
BASE_URL="http://$ENDPOINT" SMOKE_DIR="$TMP" python3 - <<'PYVERIFY'
import base64,hashlib,json,os,pathlib,time,urllib.request,urllib.error,zipfile,io
root=pathlib.Path(os.environ['SMOKE_DIR']);base=os.environ['BASE_URL']
env=dict(line.rstrip('\n').split('=',1) for line in open(root/'.env') if '=' in line)
for attempt in range(30):
    try:
        with urllib.request.urlopen(base+'/healthz',timeout=5) as r: assert json.load(r)['status']=='ok'
        break
    except (urllib.error.URLError,ConnectionError):
        if attempt==29: raise
        time.sleep(1)
def call(path,body=None,token=None):
    h={'Content-Type':'application/json'}
    if token:h['Authorization']='Bearer '+token
    req=urllib.request.Request(base+path,data=json.dumps(body).encode() if body is not None else None,headers=h)
    with urllib.request.urlopen(req,timeout=60) as r:return json.load(r)['data']
token=call('/api/v1/admin/auth/login',{'username':'smoke-owner','password':env['SMOKE_PASSWORD']})['access_token']
aid=(root/'application-id').read_text()
assert call('/api/v1/admin/applications/'+aid,token=token)['name']=='容器持久化测试'
secret=call('/api/v1/admin/applications/'+aid+'/secret',token=token)['app_secret']
assert hashlib.sha256(secret.encode()).hexdigest()==(root/'secret-digest').read_text()
backup=call('/api/v1/admin/system/backups',{},token)
req=urllib.request.Request(base+'/api/v1/admin/system/backups/'+backup['name'],headers={'Authorization':'Bearer '+token})
with urllib.request.urlopen(req,timeout=60) as r:z=zipfile.ZipFile(io.BytesIO(r.read()))
assert sorted(z.namelist())==['authgo.db','master.key'] and z.testzip() is None
# Compare effective key with the original complete ZIP, without logging it.
with zipfile.ZipFile(root/'restore.zip') as original:assert z.read('master.key')==original.read('master.key')
newconfig=call('/api/v1/admin/applications/'+aid+'/connection',{'url':base},token)['config']
source=root/'sdk/main.go'
source.write_text(source.read_text().replace(json.dumps((root/'sdk-config').read_text()),json.dumps(newconfig)))
print('Restored nonroot server: health/login/application PASS; original encrypted AppSecret decrypts identically; new complete backup/key PASS (secrets redacted)')
PYVERIFY
docker run --rm --name "$PROJECT-sdk" --network host -v "$ROOT:/src:ro" -v "$TMP:/smoke:ro" \
  -v "$PROJECT-gomod:/go/pkg/mod" -v "$PROJECT-gocache:/root/.cache/go-build" \
  -w /smoke/sdk --memory=1536m golang:1.26-alpine go run .
echo 'Offline named-volume restoration + real SDK -> PASS'
compose ps
echo "contract single-image smoke -> PASS"
