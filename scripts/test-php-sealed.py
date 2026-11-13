#!/usr/bin/env python3
"""payload 8b: real PHP-FPM + opcache + HTTPS backend; server-only, named resources."""
import importlib.util
import json
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import traceback

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('protected_helpers', ROOT / 'scripts/test-protected-elf.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
d = p.d
PREFIX = 'authgo-php-sealed-' + str(os.getpid()) + '-'
d.PREFIX, d.API, d.API2, d.IMAGE = PREFIX, PREFIX+'api', PREFIX+'other-api', PREFIX+'server'
MARKER = b'AUTHGO_PHP_FPM_SECRET_CORE_8B'
proxy = None


def record(kind, data):
    return struct.pack('!BBHHBB', 1, kind, 1, len(data), 0, 0) + data


def pair(key, value):
    a, b = key.encode(), value.encode()
    def size(n):
        return bytes([n]) if n < 128 else struct.pack('!I', n | 0x80000000)
    return size(len(a)) + size(len(b)) + a + b


def request(port, action='ok'):
    params = {'SCRIPT_FILENAME':'/app/index.php', 'SCRIPT_NAME':'/index.php', 'REQUEST_METHOD':'GET',
              'QUERY_STRING':'action='+action, 'SERVER_PROTOCOL':'HTTP/1.1', 'SERVER_NAME':'localhost',
              'SERVER_PORT':'80', 'REMOTE_ADDR':'127.0.0.1', 'CONTENT_LENGTH':'0'}
    with socket.create_connection(('127.0.0.1', port), 5) as conn:
        conn.settimeout(20)
        conn.sendall(record(1, struct.pack('!HB5x', 1, 0)) + record(4, b''.join(pair(k,v) for k,v in params.items())) + record(4,b'') + record(5,b''))
        def exact(n):
            out=b''
            while len(out)<n:
                block=conn.recv(n-len(out))
                assert block, 'FastCGI unexpectedly closed'
                out+=block
            return out
        output=b''
        while True:
            version,kind,rid,length,padding,_=struct.unpack('!BBHHBB',exact(8))
            body=exact(length)
            if padding: exact(padding)
            if kind==6: output+=body
            if kind==3:
                assert struct.unpack('!I',body[:4])[0]==0, 'FastCGI app failed'
                break
    headers,body=output.split(b'\r\n\r\n',1)
    status=503 if b'Status: 503' in headers else 200
    return status,json.loads(body)


def scan_files(directory):
    for path in directory.rglob('*'):
        if path.is_file():
            assert MARKER not in path.read_bytes(), 'plaintext on writable disk'


def main():
    global proxy
    assert shutil.disk_usage(ROOT).free >= 10*1024**3, 'disk below 10GiB; stop without pruning'
    d.TMP=pathlib.Path(tempfile.mkdtemp(prefix=PREFIX,dir=ROOT.parent))
    runtime=PREFIX+'runtime'; image=PREFIX+'app'
    name=PREFIX+'fpm'; d.containers.append(name)
    try:
        cache=d.volume_new('cache')
        d.build('Dockerfile',d.IMAGE); d.api_start()
        d.state['user_id']=d.request('/api/v1/admin/users',{'name':'PHP sealed test','email':'php-sealed@example.invalid'})['id']
        app=d.request('/api/v1/admin/applications',{'name':'payload 8b PHP','heartbeat_interval':5,'next_check_in':1,'grace_hours':72})
        d.state['app']=app
        qa=p.certificates(); proxy,endpoint=p.tls_proxy(qa)
        key=d.request('/api/v1/admin/applications/'+str(app['id'])+'/payload-keys',{},'POST')
        config=d.request('/api/v1/admin/applications/'+str(app['id'])+'/connection',{'url':endpoint})['config']
        d.SENSITIVE.add(config)
        lic=d.license_new(1);d.SENSITIVE.add(lic['key'])
        context=d.TMP/'image';context.mkdir()
        shutil.copytree(ROOT/'sdk/php/src',context/'sdk')
        shutil.copy2(qa/'ca.crt',context/'ca.crt')
        core=context/'core';core.mkdir();(core/'lib').mkdir();(core/'Auto').mkdir()
        (core/'bootstrap.php').write_text('<?php require __DIR__."/lib/value.php"; return include "lib/relative.php";')
        (core/'lib/value.php').write_text('<?php $GLOBALS["core_marker"]="'+MARKER.decode()+'";')
        (core/'lib/relative.php').write_text('<?php return include __DIR__."/../answer.php";')
        (core/'answer.php').write_text('<?php return 42;')
        (core/'Auto/Thing.php').write_text('<?php namespace SealedFpm; final class Thing {public static function value(){return 73;}}')
        (core/'later.php').write_text('<?php return 99;')
        p.checked([str(ROOT/'bin/authgo-pack'),'--php','core='+str(core),'--out',str(context/'payload'),
                   '--public-key',key['public_key'],'--key-id',key['key_id'],'--app-key',app['app_key'],
                   '--version','1.0.0','--config',config],sensitive=(config,))
        assert not list(core.rglob('*.php')), 'pack must remove PHP sources'
        shutil.rmtree(core)
        # Both connection trust roots and version are literals compiled into the image.
        (context/'config.php').write_text('<?php const CONFIG='+json.dumps(config)+'; const VERSION="1.0.0";')
        (context/'index.php').write_text(r'''<?php
require '/app/sdk/Client.php'; require '/app/config.php';
parse_str($_SERVER['QUERY_STRING']??'', $query); $guard=null;
function cacheState() {
 $state=opcache_get_status(true);$sealed=0;$ordinary=0;
 foreach(($state['scripts']??[]) as $path=>$script){if(str_contains($path,'authgo-sealed:'))$sealed++;else $ordinary++;}
 return ['opcache'=>(bool)($state['opcache_enabled']??false),'ordinary'=>$ordinary,'sealed_cached'=>$sealed];
}
$before=cacheState();
if(($query['action']??'')==='opcache'){echo json_encode($before);return;}
try {
 $guard=AuthGo\Guard::start(['config'=>CONFIG,'version'=>VERSION]);
 $guard->installSealed('core');
 $n=require 'authgo-sealed://core/bootstrap.php';
 spl_autoload_register(static function($class){if($class==='SealedFpm\\Thing')require 'authgo-sealed://core/Auto/Thing.php';});
 $auto=SealedFpm\Thing::value();$reinstalled=false;
 if(($query['action']??'')==='closed') {
  $guard->close();$blocked=false;
  try {require 'authgo-sealed://core/later.php';} catch(Throwable $e){$blocked=true;}
  if(!$blocked)throw new RuntimeException('closed loader bypass');
 }
 if(($query['action']??'')==='reinstall') {
  $handle=fopen('authgo-sealed://core/later.php','rb');
  if(fread($handle,1)!=='<'||stream_get_meta_data($handle)['unread_bytes']<=0)throw new RuntimeException('buffer premise failed');
  $guard->close();if(is_resource($handle))throw new RuntimeException('buffered stream survived close');
  $guard=AuthGo\Guard::start(['config'=>CONFIG,'version'=>VERSION]);$guard->installSealed('core');
  if((require 'authgo-sealed://core/answer.php')!==42||SealedFpm\Thing::value()!==73)throw new RuntimeException('same-request reinstall failed');
  $reinstalled=true;
 }
 echo json_encode(['answer'=>$n,'auto'=>$auto,'pid'=>getmypid(),'sapi'=>PHP_SAPI,
  'opcache_before'=>$before['opcache'],'ordinary_before'=>$before['ordinary'],
  'file_cache_only'=>(bool)ini_get('opcache.file_cache_only'),'reinstalled'=>$reinstalled,
  'opcache_disabled'=>!filter_var(ini_get('opcache.enable'),FILTER_VALIDATE_BOOLEAN)&&!(opcache_get_status()['opcache_enabled']??false),
  'marker_ok'=>($GLOBALS['core_marker']??'')==='AUTHGO_PHP_FPM_SECRET_CORE_8B']);
} catch(Throwable $e) {http_response_code(503);echo json_encode(['code'=>$e instanceof AuthGo\Error?$e->errorCode:'INTERNAL']);}
''')
        # Marker in the unprotected test controller would invalidate the disk scan.
        index=(context/'index.php').read_text().replace("($GLOBALS['core_marker']??'')==='AUTHGO_PHP_FPM_SECRET_CORE_8B'", "hash('sha256',$GLOBALS['core_marker']??'')==='"+__import__('hashlib').sha256(MARKER).hexdigest()+"'")
        (context/'index.php').write_text(index)
        port=d.port();base_port=port
        (context/'fpm.conf').write_text('[global]\ndaemonize=no\nerror_log=/proc/self/fd/2\n[www]\nlisten=127.0.0.1:'+str(port)+'\npm=static\npm.max_children=2\nclear_env=no\ncatch_workers_output=yes\ndecorate_workers_output=no\nchdir=/app\nsecurity.limit_extensions=.php\n')
        (context/'opcache.ini').write_text('opcache.enable=1\nopcache.enable_cli=1\nopcache.validate_timestamps=0\nopcache.file_update_protection=0\nopcache.file_cache=/var/lib/authgo/opcache\nopcache.file_cache_only=0\ndisplay_errors=0\nlog_errors=1\n')
        (context/'Dockerfile.runtime').write_text('FROM php:8.1-fpm\nRUN docker-php-ext-install opcache\n')
        d.images.append(runtime)
        p.checked(['docker','build','--memory=768m','-f','Dockerfile.runtime','-t',runtime,'.'],context)
        (context/'Dockerfile').write_text('FROM '+runtime+'\nCOPY ca.crt /usr/local/share/ca-certificates/authgo-php-sealed.crt\nRUN update-ca-certificates && mkdir -p /var/lib/authgo/opcache && chown -R 65532:65532 /var/lib/authgo\nCOPY sdk/ /app/sdk/\nCOPY --chown=65532:65532 payload/ /opt/authgo/\nCOPY index.php config.php fpm.conf /app/\nCOPY opcache.ini /usr/local/etc/php/conf.d/zz-sealed.ini\nUSER 65532:65532\nENTRYPOINT ["php-fpm","--nodaemonize","--fpm-config","/app/fpm.conf"]\n')
        d.images.append(image)
        p.checked(['docker','build','--memory=768m','-t',image,'.'],context)
        assert shutil.disk_usage(ROOT).free >= 10*1024**3, 'disk below 10GiB before runtime'
        d.docker('run','-d','--name',name,'--network=host','--memory=192m','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges:true','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','-v',cache+':/var/lib/authgo','-e','AUTHGO_LICENSE='+lic['key'],image)
        def listening():
            try:
                with socket.create_connection(('127.0.0.1',port),.2):return True
            except OSError:return False
        d.wait(listening,15,'FPM did not listen')
        replies=[]
        for _ in range(6):
            status,body=request(port);assert status==200 and body['answer']==42 and body['auto']==73 and body['marker_ok'], 'FPM relative/autoload failed: status='+str(status)+' code='+str(body.get('code',''))
            assert body['sapi']=='fpm-fcgi' and body['opcache_before'] and body['ordinary_before']>0 and body['opcache_disabled'], 'per-request opcache safety failed: '+json.dumps({k:body.get(k) for k in ('sapi','opcache_before','ordinary_before','opcache_disabled')})
            replies.append(body)
        assert len({b['pid'] for b in replies})==2, 'did not exercise both FPM workers'
        assert len(p.active_seats(lic))==1, 'more than one floating seat'
        print('PASS real FPM 6 requests/2 workers, relative include/require/autoload, one seat',flush=True)
        status,stats=request(port,'opcache')
        assert status==200 and stats['opcache'] and stats['ordinary']>0 and stats['sealed_cached']==0, 'sealed code leaked to opcache'
        print('PASS opcache initially ON/validate_timestamps=0: disabled only for sealed requests; probe ordinary>0, sealed=0',flush=True)
        status,body=request(port,'closed');assert status==200, 'closed streams were loadable'
        print('PASS close prevents later include in same live FPM request',flush=True)
        status,body=request(port,'reinstall');assert status==200 and body['reinstalled'] and body['answer']==42 and body['auto']==73, 'same-request Guard A close/B reinstall or buffer revocation failed'
        print('PASS same FPM request: prefetched stream closed; Guard B reinstalls after A; compiled class remains',flush=True)
        cache_path=pathlib.Path(json.loads(d.docker('volume','inspect',cache))[0]['Mountpoint'])
        keys=list(cache_path.glob('authgo-payload-v[12]-*.cache'));assert keys,'missing real content key cache'
        assert list((cache_path/'opcache').rglob('*.bin')), 'disk file-cache was not exercised'
        assert not any('authgo-sealed' in str(path) for path in (cache_path/'opcache').rglob('*')), 'sealed scripts in disk file-cache'
        scan_files(cache_path)
        # Export the actual runtime writable layer and final image filesystem. The
        # context has no original core source; the test never runs extract-all.
        def scan_export(args):
            proc=subprocess.Popen(['docker',*args],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
            tail=b''
            try:
                while True:
                    block=proc.stdout.read(1048576)
                    if not block:break
                    assert MARKER not in tail+block, 'plaintext in container/image export'
                    tail=block[-len(MARKER):]
            except BaseException:
                proc.terminate();proc.wait();raise
            finally:
                proc.stdout.close()
            rc=proc.wait()
            assert rc==0, 'docker export/save failed'
        scan_export(['export',name]);scan_export(['save',image])
        print('PASS volume/opcache file-cache/writable filesystem/all image layers: no plaintext marker',flush=True)
        d.stop_api();time.sleep(1.1)
        status,body=request(port);assert status==200 and body['answer']==42, 'valid offline key cache not reused'
        d.docker('restart','-t','8',name);d.wait(listening,15)
        status,body=request(port);assert status==200, 'FPM restart grace failed'
        print('PASS backend offline + real FPM restart: signed grace and encrypted content cache',flush=True)
        d.restore_api();d.request('/api/v1/admin/licenses/'+str(lic['id'])+'/revoke',{},'POST');time.sleep(5.1)
        for _ in range(4):
            status,body=request(port);assert status==503 and body.get('code') in ('LICENSE_REVOKED','ACTIVATION_INVALID'), 'revoked worker reused opcache/sealed code'
        assert not list(cache_path.glob('authgo-payload-v[12]-*.cache')), 'authenticated refusal left content cache'
        assert d.running(name), 'refusal killed FPM'
        scan_files(cache_path)
        print('PASS authenticated revoke: 4 requests fail 503, cache cleared, FPM remains alive',flush=True)
        # A locked admin setting must fail before any content-key acquisition.
        d.docker('stop','-t','8',name)
        for mode in ('locked','file-cache-only'):
            port=d.port();name=PREFIX+mode;d.containers.append(name)
            volume=d.volume_new(mode);license=d.license_new(1);d.SENSITIVE.add(license['key'])
            config_file=d.TMP/(mode+'.conf')
            config_file.write_text((context/'fpm.conf').read_text().replace('listen=127.0.0.1:'+str(base_port),'listen=127.0.0.1:'+str(port)) + ('php_admin_flag[opcache.enable]=on\nphp_admin_value[disable_functions]=ini_set\n' if mode=='locked' else ''))
            config_file.chmod(0o644)
            args=['run','-d','--name',name,'--network=host','--memory=192m','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges:true','--tmpfs','/tmp:rw,noexec,nosuid,size=16m','-v',volume+':/var/lib/authgo','-v',str(config_file)+':/app/fpm.conf:ro','-e','AUTHGO_LICENSE='+license['key']]
            if mode=='file-cache-only':
                ini=d.TMP/'file-only.ini';ini.write_text((context/'opcache.ini').read_text().replace('opcache.file_cache_only=0','opcache.file_cache_only=1'));ini.chmod(0o644)
                args+=['-v',str(ini)+':/usr/local/etc/php/conf.d/zz-sealed.ini:ro']
            d.docker(*args,image);d.wait(listening,15)
            for _ in range(2):
                status,body=request(port)
                if mode=='locked':assert status==503 and body.get('code')=='PAYLOAD_INVALID', 'locked opcache was not rejected: '+str(status)+' '+str(body.get('code',''))
                else:assert status==200 and body['answer']==42 and body['auto']==73 and body['marker_ok'] and body['file_cache_only'] and body['opcache_disabled'], 'file-cache-only mode bypassed safety'
            path=pathlib.Path(json.loads(d.docker('volume','inspect',volume))[0]['Mountpoint'])
            if mode=='locked':assert not list(path.glob('authgo-payload-v[12]-*.cache')), 'locked opcache acquired content key'
            else:
                assert list((path/'opcache').rglob('*.bin')), 'file-cache-only had no ordinary cache entries'
                assert not any('authgo-sealed' in str(f) for f in (path/'opcache').rglob('*')), 'sealed opcode persisted in file-cache-only'
            scan_files(path)
            print('PASS '+mode+': '+('fail closed before unlock' if mode=='locked' else 'ordinary disk cache present; sealed opcode absent'),flush=True)
            d.docker('stop','-t','8',name)
        print('PHP_SEALED_DONE 0; 9/9 PASS',flush=True)
    except Exception:
        for frame in traceback.extract_tb(__import__('sys').exc_info()[2]):
            print('FAIL_LOCATION '+pathlib.Path(frame.filename).name+':'+str(frame.lineno)+' '+frame.name,flush=True)
        if d.docker('ps','-aq','--filter','name=^'+name+'$'):
            output=d.logs(name)
            for secret in d.SENSITIVE: output=output.replace(secret,'<redacted>')
            (ROOT.parent/'php-sealed-fpm-failure.log').write_text(output)
        log=d.TMP/'failed-command.log'
        if log.exists():shutil.copy2(log,ROOT.parent/'php-sealed-build-failure.log')
        raise
    finally:
        if proxy:proxy.shutdown();proxy.server_close()
        d.cleanup()


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('PHP_SEALED_DONE 1; '+type(exc).__name__+': '+str(exc)[:240],flush=True)
        raise SystemExit(1)
