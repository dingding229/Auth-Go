#!/usr/bin/env python3
"""Real protected FPM/Apache examples: 503 semantics and final seat cleanup."""
import importlib.util
import json
import pathlib
import shutil
import tempfile
import time
import socket
import urllib.request
ROOT=pathlib.Path(__file__).resolve().parent.parent
spec=importlib.util.spec_from_file_location('payload_matrix',ROOT/'scripts/test-protected-matrix.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
d=m.d;h=m.h
spec2=importlib.util.spec_from_file_location('fpm_wire',ROOT/'scripts/test-php-sealed.py');wire=importlib.util.module_from_spec(spec2);spec2.loader.exec_module(wire)
# wire owns a different module instance; its request() is a standalone FastCGI client.

def run(mode,qa,endpoint):
 m.disk();port=d.port();app=d.request('/api/v1/admin/applications',{'name':'payload '+mode,'heartbeat_interval':5,'next_check_in':1,'grace_hours':72});d.state['app']=app
 key=d.request('/api/v1/admin/applications/'+str(app['id'])+'/payload-keys',{},'POST');config=d.request('/api/v1/admin/applications/'+str(app['id'])+'/connection',{'url':endpoint})['config'];d.SENSITIVE.add(config)
 # Clone and patch listener ONLY in the private test context; trust constants stay compiled.
 original=m.inject_probe
 def inject(language,directory):
  original(language,directory)
  conf=directory/('php-fpm.conf' if mode=='php-fpm' else 'apache.conf');text=conf.read_text()
  if mode=='php-fpm':text=text.replace('0.0.0.0:9000','127.0.0.1:'+str(port))
  else:text=text.replace('Listen 8080','Listen 127.0.0.1:'+str(port))
  conf.write_text(text)
  entry=directory/'entrypoint.sh';entry.write_text(entry.read_text().replace('9000' if mode=='php-fpm' else '8080',str(port)))
 m.inject_probe=inject
 try:image,context=m.build(mode,config,key,qa)
 finally:m.inject_probe=original
 volume=d.volume_new(mode+'-cache');license=m.lic();name=m.PREFIX+mode+'-runtime';d.containers.append(name)
 args=['run','-d','--name',name,'--network=host','--memory=256m','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges:true','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','-v',volume+':/var/lib/authgo','-e','AUTHGO_LICENSE='+license['key'],image]
 m.disk();begin=time.monotonic();d.docker(*args)
 def listening():
  try:
   with socket.create_connection(('127.0.0.1',port),.2):return True
  except OSError:return False
 d.wait(listening,20,'protected SAPI not listening')
 def request():
  if mode=='php-fpm':return wire.request(port)
  try:
   with urllib.request.urlopen('http://127.0.0.1:'+str(port),timeout=10) as r:return r.status,json.load(r)
  except urllib.error.HTTPError as error:return error.code,json.load(error)
 for _ in range(6):
  status,body=request();assert status==200 and body.get('marker')==m.MARKER.decode(),'protected request failed'
 assert len(h.active_seats(license))==1,'request workers share more than one seat'
 print('PASS '+mode+' real six requests/core/one seat',flush=True)
 assert m.caches(volume),'no encrypted content cache'
 m.scan(['save',image]);m.scan_volume(volume);m.scan(['export',name])
 live=m.scan_live(name,volume);status,body=request();assert status==200 and body.get('marker')==m.MARKER.decode() and len(h.active_seats(license))==1
 print('PASS '+mode+' AUTHORIZED_LIVE '+json.dumps(live),flush=True)
 print('PASS '+mode+' no plaintext in nested image layers/volume/live upperdir/all rw tmpfs; valid core before/after',flush=True)
 info=d.inspect(name);assert info['HostConfig']['ReadonlyRootfs'] and 'ALL' in info['HostConfig']['CapDrop'] and info['Config']['User']=='65532:65532'
 print('PASS '+mode+' nonroot/readonly/dropALL/default seccomp',flush=True)
 d.stop_api()
 try:status,body=request();assert status==200 and body.get('marker')==m.MARKER.decode(),'request offline cache failed'
 finally:d.restore_api()
 print('PASS '+mode+' actual server outage retains signed grace',flush=True)
 d.request('/api/v1/admin/licenses/'+str(license['id'])+'/revoke',{},'POST');time.sleep(5.1)
 for _ in range(4):
  status,body=request();assert status==503 and body.get('code') in ('LICENSE_REVOKED','ACTIVATION_INVALID'),'request refusal not 503'
 assert d.running(name) and not m.caches(volume),'revocation killed SAPI or retained key'
 print('PASS '+mode+' revoke ->503 and clear key, workers remain alive',flush=True)
 d.docker('stop','-t','12',name)
 # Fresh valid SAPI: stop must promptly release without any mock request or DB edit.
 fresh=m.lic();d.docker('rm',name);d.containers.remove(name);name=m.PREFIX+mode+'-stop';d.containers.append(name);args[args.index('--name')+1]=name;args[args.index('-e')+1]='AUTHGO_LICENSE='+fresh['key'];d.docker(*args);d.wait(listening,20);status,body=request();assert status==200
 stop=time.monotonic();d.stop(name);d.wait(lambda:not h.active_seats(fresh),5,'SAPI shutdown did not release seat')
 print('PASS '+mode+' docker stop exit0/seat release '+str(round(time.monotonic()-stop,3))+'s',flush=True)
 print('PHP_MODE '+mode+' 6/6 PASS first-start-to-six-requests='+str(round(time.monotonic()-begin,3))+'s (includes scenario duration; not startup metric)',flush=True)
 for container in d.containers[:]:
  if container.startswith(m.PREFIX+mode):d.docker('rm','-f',container,check=False)
 d.docker('image','rm',image,check=False);shutil.rmtree(context)

def main():
 proxy=None;m.disk();d.TMP=pathlib.Path(tempfile.mkdtemp(prefix=m.PREFIX,dir=ROOT.parent))
 try:
  d.build('Dockerfile',d.IMAGE);d.api_start();d.state['user_id']=d.request('/api/v1/admin/users',{'name':'payload SAPI','email':'payload-sapi@example.invalid'})['id'];qa=h.certificates();proxy,endpoint=h.tls_proxy(qa)
  for mode in ('php-fpm','php-apache'):run(mode,qa,endpoint)
  print('PROTECTED_PHP_MODES_DONE 0',flush=True)
 except Exception as error:
  import sys,traceback
  for frame in traceback.extract_tb(sys.exc_info()[2]):print('FAIL_LOCATION '+pathlib.Path(frame.filename).name+':'+str(frame.lineno)+' '+frame.name,flush=True)
  if (d.TMP/'failed-command.log').exists():shutil.copy2(d.TMP/'failed-command.log',ROOT.parent/'payload-php-modes-build-failure.log')
  states={}
  for name in d.containers:
   if name in (d.API,d.API2):continue
   try:
    cfg=d.inspect(name);states[name]={'State':cfg['State'],'RestartCount':cfg.get('RestartCount')}
   except Exception as state_error:states[name]={'unavailable':type(state_error).__name__}
   text=d.docker('logs','--timestamps',name,check=False)
   for secret in d.SENSITIVE:text=text.replace(secret,'<redacted>')
   with (ROOT.parent/'payload-php-modes-runtime-failure.log').open('a') as out:out.write(name+'\n'+text+'\n')
  (ROOT.parent/'watermark-php-modes-failure-state.json').write_text(json.dumps(states,indent=2)+'\n')
  print('PROTECTED_PHP_MODES_DONE 1; '+(str(error) if isinstance(error,AssertionError) else type(error).__name__),flush=True);raise SystemExit(1)
 finally:
  if proxy:proxy.shutdown();proxy.server_close()
  d.cleanup()
if __name__=='__main__':main()
