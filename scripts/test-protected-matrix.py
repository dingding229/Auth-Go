#!/usr/bin/env python3
"""payload server-only real protected examples. Existing unprotected tests are untouched.
All resources are named, each language is sequential. No TLS bypass or runtime config.
"""
import datetime as dt
import importlib.util
import json
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.error
import http.server
import ssl
import threading

ROOT=pathlib.Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('payload_helpers',ROOT/'scripts/test-protected-elf.py')
h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h);d=h.d
PREFIX='authgo-contract-payload-'+str(os.getpid())+'-'
d.PREFIX=PREFIX;d.API=PREFIX+'api';d.API2=PREFIX+'other-api';d.IMAGE=PREFIX+'server'
MARKER=b'AUTHGO_payload_PROTECTED_CORE';MARKERS=(MARKER,MARKER.decode().encode('utf-16le'),MARKER.decode().encode('utf-16be'));TOOLS=os.environ.get('AUTHGO_TEST_TOOLS_IMAGE','authgo-contract-payload-tools:test')
REPORT=ROOT.parent/'payload-protected-results.json';report={};performance={}
if REPORT.exists():
 prior=json.loads(REPORT.read_text());report=prior.get('matrix',{});performance=prior.get('performance',{})
LABELS={1:'有效授权/核心功能',2:'单席位/无INSTANCE_REPLACED',3:'跳Guard无法取密钥',4:'docker save全层无明文',5:'信封构建晚于维护期拒绝77',6:'信封版本篡改拒绝',7:'禁用版本拒绝新启动',8:'试用同镜像/无密钥缓存/离线重启失败',9:'断网缓存重启/窗口耗尽/空卷失败',10:'卷复制到另一实例不可用',11:'运行中吊销退出并清密钥',12:'docker stop正常退出立即释放',13:'缓存和可写层无明文',14:'非root/readonly/dropALL/defaultseccomp',15:'GoRust真实业务PID1/直接入口仍受保护',16:'实际启动耗时/RSS'}

class MatrixProxy(h.Proxy):
 def forward(self):
  if self.headers.get('Transfer-Encoding','').lower()=='chunked':
   chunks=[];total=0
   while True:
    line=self.rfile.readline(128);size=int(line.split(b';',1)[0].strip(),16)
    if size==0:
     while self.rfile.readline(8192) not in (b'\r\n',b'\n',b''):pass
     break
    total+=size;assert total<=2*1024**2,'proxy request limit exceeded'
    chunk=self.rfile.read(size);assert len(chunk)==size and self.rfile.read(2)==b'\r\n';chunks.append(chunk)
   body=b''.join(chunks)
  else:
   size=int(self.headers.get('Content-Length','0'));assert 0<=size<=2*1024**2;body=self.rfile.read(size) if size else None
  request=urllib.request.Request(d.state['base']+self.path,data=body,method=self.command,headers={'Content-Type':self.headers.get('Content-Type','application/json')})
  try:
   with urllib.request.urlopen(request,timeout=5) as response:raw,status=response.read(),response.status
  except urllib.error.HTTPError as error:raw,status=error.read(),error.code
  except OSError:raw,status=b'{"transport":"unreachable"}',502
  try:
   self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
  except (BrokenPipeError,ConnectionResetError):pass

# This test-only adapter retains the original HTTPS certificate verification.
h.Proxy=MatrixProxy
def disk():assert shutil.disk_usage(ROOT).free>=10*1024**3,'disk below 10GiB; no pruning'
def persist():REPORT.write_text(json.dumps({'matrix':report,'performance':performance},ensure_ascii=False,indent=2)+'\n')
def case(lang,n,fn):
 try:detail=fn();report[lang][str(n)]={**report[lang][str(n)],'status':'PASS','detail':detail or LABELS[n]};print('PASS '+lang+' '+str(n)+' '+LABELS[n],flush=True)
 except Exception as e:
  detail=str(e) if isinstance(e,AssertionError) else type(e).__name__
  report[lang][str(n)]={**report[lang][str(n)],'status':'FAIL','detail':detail};print('FAIL '+lang+' '+str(n)+' '+detail,flush=True);raise
 finally:persist()
def iso(t):return t.isoformat().replace('+00:00','Z')
def caches(volume):return list(pathlib.Path(json.loads(d.docker('volume','inspect',volume))[0]['Mountpoint']).glob('authgo-payload-v[12]-*.cache'))
def mountpath(volume):return pathlib.Path(json.loads(d.docker('volume','inspect',volume))[0]['Mountpoint'])
def lic(**extra):
 body={'app_id':d.state['app']['id'],'user_id':d.state['user_id'],'verify_methods':['KEY','FLOATING'],'max_activations':1,**extra}
 v=d.request('/api/v1/admin/licenses',body);d.SENSITIVE.add(v['key']);return v

def request(address):
 try:
  with urllib.request.urlopen('http://'+address,timeout=2) as response:return response.status,json.load(response)
 except urllib.error.HTTPError as error:
  try:body=json.load(error)
  except (ValueError,OSError):body={}
  return error.code,body
 except Exception as error:return 0,{'transport':type(error).__name__}
READINESS_EVIDENCE={}
def ready(name,address):
 def probe():
  status,body=request(address);alive=d.running(name)
  code=body.get('code',body.get('transport','none'));code=code if isinstance(code,str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',code) else 'non-code'
  rows=READINESS_EVIDENCE.setdefault(name,[]);rows.append({'monotonic':time.monotonic(),'http_status':status,'code':code,'marker_present':body.get('marker')==MARKER.decode(),'running':alive});del rows[:-100]
  return status==200 or not alive
 d.wait(probe,50,'protected example not ready')
 status,body=request(address);code=body.get('code',body.get('transport','none'));code=code if isinstance(code,str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,63}',code) else 'non-code'
 assert d.running(name) and body.get('marker')==MARKER.decode(),'protected business did not run; HTTP='+str(status)+' code='+code
def start(label,key,volume,image,extra=None,entry=None):
 disk()
 name=PREFIX+label;d.containers.append(name);port=d.port();address='127.0.0.1:'+str(port)
 args=['run','-d','--name',name,'--network=host','--memory=384m','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges:true','--tmpfs','/tmp:rw,nosuid,size=256m','-v',volume+':/var/lib/authgo','-e','AUTHGO_LICENSE='+key]
 for k,v in (extra or {}).items():args+=['-e',k+'='+v]
 if entry:args+=['--entrypoint',entry]
 begin=time.monotonic();d.docker(*args,image,'-listen',address)
 return name,address,begin

# Test-only scanner: docker export excludes volumes/tmpfs, so never use it alone.
import protected_scan as plaintext

def scan_content(source,name='',depth=0,budget=None):
 scanner=plaintext.Scanner();scanner.content(source,name,depth);return scanner.summary()
def scan(args):return plaintext.docker_scan(args)
def scan_self_test():
 subprocess.run([sys.executable,str(ROOT/'scripts/test-protected-scan.py')],check=True)
def scan_volume(volume):return plaintext.scan_tree(mountpath(volume))
def scan_live(name,volume):return plaintext.live_scan(name,volume,d.inspect)

def build(lang,config,key,qa):
 disk();context=d.TMP/(lang+'-context');context.mkdir()
 for source in ('sdk','examples/docker-protected'):
  shutil.copytree(ROOT/source,context/source,ignore=shutil.ignore_patterns('target','node_modules','bin','obj','__pycache__','reports'))
 qa=pathlib.Path(qa).resolve();qa_file=qa/'ca.crt';assert qa_file.is_file(), 'temporary test CA was not generated'
 (context/'qa').mkdir(parents=True,exist_ok=True);shutil.copy2(qa_file,context/'qa/ca.crt')
 directory=context/'examples/docker-protected'/lang;dockerfile=(directory/'Dockerfile').read_text()
 # Dockerfile-specific ignore files start with ** and otherwise omit the root QA directory.
 # This is a temporary build-context change; the repository's customer examples stay untouched.
 ignore=directory/'Dockerfile.dockerignore'
 if ignore.exists():
  text=ignore.read_text()
  if '!qa/' not in text:
   ignore.write_text(text.rstrip()+'\n!qa/\n!qa/**\n')
 final=dockerfile.rfind('\nFROM ');body=dockerfile[final:]
 if lang in ('go','rust'):ca='COPY qa/ca.crt /etc/ssl/certs/ca-certificates.crt\n'
 elif lang=='java':ca='COPY qa/ca.crt /authgo-test-ca.crt\nRUN keytool -importcert -noprompt -alias authgo-public-test -cacerts -storepass changeit -file /authgo-test-ca.crt >/dev/null\n'
 elif lang.startswith('php'):ca='COPY qa/ca.crt /usr/local/share/ca-certificates/authgo-public-test.crt\nRUN update-ca-certificates >/dev/null\n'
 else:ca='COPY qa/ca.crt /authgo-test-ca.crt\nENV SSL_CERT_FILE=/authgo-test-ca.crt NODE_EXTRA_CA_CERTS=/authgo-test-ca.crt\n'
 if lang=='csharp':ca='COPY qa/ca.crt /usr/local/share/ca-certificates/authgo-public-test.crt\nRUN update-ca-certificates >/dev/null\n'
 body=body.replace('USER 65532:65532',ca+'USER 65532:65532',1);dockerfile=dockerfile[:final]+body
 if lang=='rust':
  h.checked(['openssl','x509','-in',str(qa/'ca.crt'),'-outform','DER','-out',str(directory/'src/qa-ca.der')])
  file=directory/'src/main.rs';text=file.read_text().replace('let options = GuardOptions {','let options = GuardOptions { sdk_options: authgo::Options {root_cert_der: Some(include_bytes!("qa-ca.der").to_vec()), ..Default::default()},');file.write_text(text)
 # Inject only a test-only bypass before Guard startup. The public examples have no bypass.
 inject_probe(lang,directory)
 (directory/'Dockerfile').write_text(dockerfile)
 image=PREFIX+lang;d.images.append(image);args=['docker','build','--memory=1536m','-f','examples/docker-protected/'+lang+'/Dockerfile','-t',image]
 for k,v in {'AUTHGO_TOOLS_IMAGE':TOOLS,'AUTHGO_CONFIG':config,'VERSION':'1.0.0','PAYLOAD_PUBLIC_KEY':key['public_key'],'PAYLOAD_KEY_ID':key['key_id'],'PAYLOAD_APP_KEY':d.state['app']['app_key']}.items():args+=['--build-arg',k+'='+v]
 args+=['.'];h.checked(args,context,(config,));return image,context

def inject_probe(lang,directory):
 if lang=='python':
  file=directory/'main.py';s=file.read_text().replace('import signal','import os\nfrom pathlib import Path\nimport signal');s=s.replace('guard = authgo.start_guard(config=CONFIG, version=VERSION)','''if os.getenv("AUTHGO_TEST_SKIP_GUARD"):
            authgo.Client(CONFIG).unlock_payload(authgo.parse_payload(Path("/opt/authgo/payload.json").read_bytes()))
            raise RuntimeError("bypass obtained key")
        guard = authgo.start_guard(config=CONFIG, version=VERSION)''');file.write_text(s)
 elif lang=='node':
  file=directory/'main.mjs';s=file.read_text().replace('import http from','import fs from "node:fs";\nimport {Client} from "./sdk/index.js";\nimport {parsePayload} from "./sdk/payload.js";\nimport http from');s=s.replace('const core = await guard.requireSealed("core");','console.log("QA_GUARD_STARTED"); const core = await guard.requireSealed("core");');s=s.replace('console.error(`授权验证失败: ${error}`);','console.error(`授权验证失败: ${error.stack || error}`);');s=s.replace('guard = await startGuard(','''if(process.env.AUTHGO_TEST_SKIP_GUARD){await new Client(CONFIG).unlockPayload(parsePayload(fs.readFileSync("/opt/authgo/payload.json")));throw new Error("bypass obtained key");}
    guard = await startGuard(''');file.write_text(s)
 elif lang=='php':
  file=directory/'main.php';s=file.read_text().replace('try{$guard=AuthGo\\start_guard(','''try{if(getenv('AUTHGO_TEST_SKIP_GUARD')){(new AuthGo\\Client(CONFIG))->unlockPayload(AuthGo\\Payload::parsePayload(file_get_contents('/opt/authgo/payload.json')));throw new RuntimeException('bypass obtained key');}$guard=AuthGo\\start_guard(''');file.write_text(s)
 elif lang=='java':
  file=directory/'build.sh';s=file.read_text().replace('try { Bootstrap.run(options, "app", args); }', '''try { if(System.getenv("AUTHGO_TEST_SKIP_GUARD")!=null) { new Client(options.config).unlockPayload(Payload.parsePayload(java.nio.file.Files.readAllBytes(java.nio.file.Path.of("/opt/authgo/payload.json")))); throw new RuntimeException("bypass obtained key"); } Bootstrap.run(options, "app", args); }''');file.write_text(s)
 elif lang=='csharp':
  file=directory/'Launcher/Program.cs';s=file.read_text();prefix='''using AuthGo;
if(Environment.GetEnvironmentVariable("AUTHGO_TEST_SKIP_GUARD") is not null){try{new Client(Build.Config).UnlockPayload(Payload.ParsePayload(File.ReadAllBytes("/opt/authgo/payload.json")));return 1;}catch(AuthGoException e){Console.Error.WriteLine(e.Code);return Guard.ExitLicense;}}
''';file.write_text(prefix+s.replace('using AuthGo;',''))
 # Go/Rust share the Go ELF launcher, whose separate no-Guard probe is built by tools setup.

def altered(lang,image,name,version):
 folder=d.TMP/(lang+'-'+name);folder.mkdir();container=PREFIX+lang+'-extract-'+name;d.containers.append(container)
 d.docker('create','--name',container,'--memory=64m',image)
 if lang in ('go','rust'):
  path=folder/'app';d.docker('cp',container+':/app',str(path));raw=path.read_bytes();footer=bytearray(raw[-64:]);stub,plen,cipher=struct.unpack_from('>QQQ',footer,24)
  obj=json.loads(raw[stub:stub+plen]);obj['version']=version;encoded=json.dumps(obj,separators=(',',':')).encode();struct.pack_into('>Q',footer,32,len(encoded));path.write_bytes(raw[:stub]+encoded+raw[stub+plen:-64]+footer);path.chmod(0o755);copy='COPY app /app\n'
 else:
  path=folder/'payload.json';d.docker('cp',container+':/opt/authgo/payload.json',str(path));obj=json.loads(path.read_text());obj['version']=version;path.write_text(json.dumps(obj));path.chmod(0o644);copy='COPY payload.json /opt/authgo/payload.json\n'
 d.docker('rm',container);tag=PREFIX+lang+'-'+name;d.images.append(tag);(folder/'Dockerfile').write_text('FROM '+image+'\n'+copy);h.checked(['docker','build','--memory=384m','-t',tag,'.'],folder);return tag

def suite(lang,qa,endpoint):
 report[lang]={str(n):{'status':'未运行','detail':LABELS[n]} for n in LABELS};persist()
 app=d.request('/api/v1/admin/applications',{'name':'payload '+lang,'heartbeat_interval':5,'next_check_in':1,'grace_hours':72});d.state['app']=app
 key=d.request('/api/v1/admin/applications/'+str(app['id'])+'/payload-keys',{},'POST');config=d.request('/api/v1/admin/applications/'+str(app['id'])+'/connection',{'url':endpoint})['config'];d.SENSITIVE.add(config)
 image,context=build(lang,config,key,qa);license=lic();volume=d.volume_new(lang+'-valid');name,address,begin=start(lang+'-valid',license['key'],volume,image)
 def valid():
  ready(name,address);performance[lang]={'startup_seconds':round(time.monotonic()-begin,3)}
  assert request(address)[1]['language']==lang
 case(lang,1,valid)
 case(lang,2,lambda:(_ for _ in ()).throw(AssertionError('seat conflict')) if len(h.active_seats(license))!=1 or 'INSTANCE_REPLACED' in d.logs(name) else None)
 # Runtime export must occur before any denial and after a valid core request.
 # remains unpassed until the original post-revocation checks also complete.
 try:
  ready(name,address);assert len(h.active_seats(license))==1
  live=scan_live(name,volume)
  ready(name,address);assert len(h.active_seats(license))==1
  report[lang]['13']['live']={'status':'PASS','evidence':live,'authorized_core_before_and_after':True}
  print('PASS '+lang+' 13a AUTHORIZED_LIVE '+json.dumps(live),flush=True)
 except Exception:
  report[lang]['13']['live']={'status':'FAIL'};report[lang]['13']['status']='FAIL';raise
 finally:persist()

 def bypass():
  v=d.volume_new(lang+'-bypass')
  if lang in ('go','rust'):
   # The same Go launcher protects both ELF languages; do not invent a Rust decryption API.
   probe_context=d.TMP/(lang+'-probe-context');probe_context.mkdir();shutil.copytree(ROOT/'sdk/go',probe_context/'sdk/go')
   source='package main\nimport (sdk "authgo/sdk";"os";"context";"fmt")\nfunc main(){f,e:=os.Open("/app");if e!=nil{panic(e)};st,_:=f.Stat();p,e:=sdk.ReadProtectedImage(f,st.Size());if e!=nil{panic(e)};c,e:=sdk.New('+json.dumps(config)+');if e!=nil{panic(e)};key,e:=c.UnlockPayload(context.Background(),p.Payload);clear(key);fmt.Println(e);if e!=nil{os.Exit(77)};os.Exit(1)}'
   (probe_context/'main.go').write_text(source);(probe_context/'go.mod').write_text('module payloadprobe\ngo 1.26.0\nrequire authgo/sdk v0.0.0\nreplace authgo/sdk => ./sdk/go\n')
   d.docker('cp',name+':/app',str(probe_context/'encrypted-app'))
   (probe_context/'Dockerfile').write_text('FROM golang:1.26-alpine AS build\nWORKDIR /src\nCOPY . .\nRUN CGO_ENABLED=0 go build -mod=mod -o /probe .\nFROM alpine:3.22\nCOPY --from=build /probe /probe\nCOPY encrypted-app /app\nUSER 65532:65532\nENTRYPOINT ["/probe"]\n')
   probe_image=PREFIX+lang+'-probe-image';d.images.append(probe_image);h.checked(['docker','build','--memory=768m','-t',probe_image,'.'],probe_context,(config,))
   p=PREFIX+lang+'-probe';d.containers.append(p)
   output=d.docker('run','--name',p,'--memory=128m','--network=none','-e','AUTHGO_TEST_SKIP_GUARD=1',probe_image,check=False)
   assert 'SDK_NOT_ACTIVATED' in output and d.inspect(p)['State']['ExitCode']==77,'ELF launcher no-Guard probe did not reject'
  else:
   n,_,_=start(lang+'-bypass',license['key'],v,image,{'AUTHGO_TEST_SKIP_GUARD':'1'});d.ended(n,77,text='SDK_NOT_ACTIVATED',seconds=20)
  assert not caches(v),'bypass wrote key cache'
 case(lang,3,bypass)
 case(lang,4,lambda:scan(['save',image]))
 def maintenance():
  # Backdated display metadata cannot authorize an envelope built after maintenance.
  d.request('/api/v1/admin/applications/'+str(app['id'])+'/versions',{'version':'1.0.0','encrypted':True,'built_at':'2000-01-01T00:00:00Z','published_at':'2000-01-01T00:00:00Z'},'POST')
  l=lic(maintenance_until=iso(dt.datetime.now(dt.timezone.utc)-dt.timedelta(days=1)));v=d.volume_new(lang+'-old');n,_,_=start(lang+'-maintenance',l['key'],v,image);d.ended(n,77,text='MAINTENANCE_EXPIRED',seconds=30);assert not caches(v)
 case(lang,5,maintenance)
 def tamper():
  tag=altered(lang,image,'tampered','0.9.0');l=lic();v=d.volume_new(lang+'-tampered');n,_,_=start(lang+'-tampered',l['key'],v,tag);d.ended(n,77,seconds=30);assert not caches(v)
 case(lang,6,tamper)
 def disabled():
  d.stop(name)
  v=d.request('/api/v1/admin/applications/'+str(app['id'])+'/versions')['items'][0];d.request('/api/v1/admin/versions/'+str(v['id']),{'disabled':True},'PATCH');l=lic();n,_,_=start(lang+'-disabled',l['key'],d.volume_new(lang+'-disabled'),image);d.ended(n,77,text='VERSION_DISABLED',seconds=30);d.request('/api/v1/admin/versions/'+str(v['id']),{'disabled':False},'PATCH');d.docker('start',name);ready(name,address)
 case(lang,7,disabled)
 def trial():
  d.request('/api/v1/admin/applications/'+str(app['id'])+'/trial',{'trial_enabled':True,'trial_days':14},'PATCH');v=d.volume_new(lang+'-trial');n,a,_=start(lang+'-trial','',v,image);ready(n,a);assert not caches(v);d.stop(n);d.stop_api()
  try:d.docker('start',n);d.ended(n,77,seconds=35);assert not caches(v)
  finally:d.restore_api()
 case(lang,8,trial)
 def outage():
  # A real short-lived license caps the signed offline window. No mocked clock.
  end=dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=55);l=lic(validity_rule='fixed_expiry',expires_at=iso(end));v=d.volume_new(lang+'-grace');n,a,_=start(lang+'-grace',l['key'],v,image);ready(n,a);assert caches(v);d.stop(n);d.stop_api()
  try:
   d.docker('start',n);ready(n,a)
   empty,_,_=start(lang+'-empty',l['key'],d.volume_new(lang+'-empty'),image);d.ended(empty,77,seconds=35)
   d.ended(n,77,seconds=max(10,(end-dt.datetime.now(dt.timezone.utc)).total_seconds()+15))
   return 'signed window capped by real license expiry, no test clock'
  finally:d.restore_api()
 case(lang,9,outage)
 def copied():
  v=d.volume_new(lang+'-copied');shutil.copytree(mountpath(volume),mountpath(v),dirs_exist_ok=True);d.stop_api()
  try:
   n,_,_=start(lang+'-copied',license['key'],v,image,{'AUTHGO_INSTANCE_ID':'different-payload-instance'});d.ended(n,77,seconds=35)
  finally:d.restore_api()
 case(lang,10,copied)
 def revoke():
  ready(name,address);d.request('/api/v1/admin/licenses/'+str(license['id'])+'/revoke',{},'POST');d.ended(name,77,seconds=30);assert not caches(volume)
 case(lang,11,revoke)
 def stop():
  l=lic();v=d.volume_new(lang+'-stop');n,a,_=start(lang+'-stop',l['key'],v,image);ready(n,a);assert len(h.active_seats(l))==1;before=time.monotonic();d.stop(n);d.wait(lambda:not h.active_seats(l),5,'seat not released');performance[lang]['stop_release_seconds']=round(time.monotonic()-before,3)
 case(lang,12,stop)
 def post_exit_plaintext():
  assert report[lang]['13'].get('live',{}).get('status')=='PASS','missing authorized live scan'
  evidence={'cache_volume':scan_volume(volume),'export':scan(['export',name])}
  report[lang]['13']['post_exit']={'status':'PASS','evidence':evidence}
  return '13a authorized live cache/upperdir/export/all rw tmpfs + 13b original post-exit cache/export PASS'
 case(lang,13,post_exit_plaintext)
 def security():
  cfg=d.inspect(name);assert cfg['Config']['User']=='65532:65532';host=cfg['HostConfig'];assert host['ReadonlyRootfs'] and 'ALL' in host['CapDrop'] and host['Memory']==384*1024**2 and not host['Privileged'];assert not any('seccomp=unconfined' in x for x in host['SecurityOpt']);assert 'seccomp' in d.docker('info','--format','{{json .SecurityOptions}}')
 case(lang,14,security)
 if lang not in ('go','rust'):report[lang]['15']={'status':'不适用','detail':'only Go/Rust ELF launcher PID1'};persist()
 else:
  def pid1():
   l=lic();v=d.volume_new(lang+'-pid');n,a,_=start(lang+'-pid',l['key'],v,image,entry='/app');ready(n,a);pid=d.inspect(n)['State']['Pid'];exe=os.readlink('/proc/'+str(pid)+'/exe');assert 'memfd:authgo-main' in exe or '(deleted)' in exe;assert len(pathlib.Path('/proc/'+str(pid)+'/exe').read_bytes())>=100*1024**2;d.stop(n)
   n,_,_=start(lang+'-direct-denied',l['key'],d.volume_new(lang+'-direct-denied'),image,{'AUTHGO_LICENSE':'AUTH-INVALID'},entry='/app');d.ended(n,77,seconds=30)
  case(lang,15,pid1)
 def rss():
  l=lic();n,a,_=start(lang+'-rss',l['key'],d.volume_new(lang+'-rss'),image);ready(n,a);pid=d.inspect(n)['State']['Pid'];status=pathlib.Path('/proc/'+str(pid)+'/status').read_text();performance[lang]['rss_kib']=int(re.search(r'VmRSS:\s+(\d+)',status).group(1));d.stop(n);print('PERFORMANCE '+lang+' '+json.dumps(performance[lang]),flush=True)
 case(lang,16,rss)
 # Release only this language's resources before building the next.
 for n in d.containers[:]:
  if n.startswith(PREFIX+lang+'-'):d.docker('rm','-f',n,check=False)
 for tag in d.images[:]:
  if tag.startswith(PREFIX+lang):d.docker('image','rm',tag,check=False)
 shutil.rmtree(context);disk()

def main():
 selected=[x for arg in sys.argv[1:] for x in arg.split(',')] or ['go','python','node','rust','java','csharp','php'];selected=['go','python','node','rust','java','csharp','php'] if selected==['all'] else selected;assert all(x in ('go','python','node','rust','java','csharp','php') for x in selected)
 disk();d.TMP=pathlib.Path(tempfile.mkdtemp(prefix=PREFIX,dir=ROOT.parent));proxy=None
 try:
  d.build('Dockerfile',d.IMAGE);d.api_start();d.state['user_id']=d.request('/api/v1/admin/users',{'name':'payload protected','email':'payload@example.invalid'})['id'];qa=h.certificates();proxy,endpoint=h.tls_proxy(qa)
  for lang in selected:suite(lang,qa,endpoint)
  print('PROTECTED_MATRIX_DONE 0',flush=True)
 except Exception as e:
  import traceback
  for frame in traceback.extract_tb(sys.exc_info()[2]):print('FAIL_LOCATION '+pathlib.Path(frame.filename).name+':'+str(frame.lineno)+' '+frame.name,flush=True)
  error=str(e) if isinstance(e,AssertionError) else type(e).__name__;print('PROTECTED_MATRIX_DONE 1; '+error[:240],flush=True)
  log=d.TMP/'failed-command.log'
  if log.exists():shutil.copy2(log,ROOT.parent/'payload-protected-build-failure.log')
  state_evidence={}
  for n in d.containers:
   if n.startswith(PREFIX) and n!=d.API:
    raw_state=d.docker('inspect',n,'--format','{{json .State}}',check=False)
    try:state=json.loads(raw_state)
    except (ValueError,TypeError):state={'unavailable':True}
    state_evidence[n]={'State':state,'RestartCount':d.docker('inspect',n,'--format','{{.RestartCount}}',check=False).strip(),'readiness_probes':READINESS_EVIDENCE.get(n,[])}
    text=d.docker('logs','--timestamps','--tail','200',n,check=False)
    for secret in d.SENSITIVE:text=text.replace(secret,'<redacted>')
    with (ROOT.parent/'payload-protected-runtime-failure.log').open('a') as out:out.write(n+'\n'+text+'\n')
  (ROOT.parent/'watermark-protected-failure-state.json').write_text(json.dumps(state_evidence,indent=2)+'\n')
  raise SystemExit(1)
 finally:
  persist()
  if proxy:proxy.shutdown();proxy.server_close()
  d.cleanup()
if __name__=='__main__':
 if sys.argv[1:]==['--self-test']:scan_self_test()
 else:main()
