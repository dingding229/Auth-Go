#!/usr/bin/env python3
"""Real-license/runtime-export watermark test with no mocked auth responses.
Test-only introspection is injected into isolated copies, NEVER public examples.
All seven languages execute serially; exact process state is retained before cleanup.
"""
import base64
import importlib.util
import pathlib
import sys
import os
import json
import shutil
import tempfile
import time
import re
import struct
import hashlib
import zipfile
import io
import urllib.request
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('watermark_matrix', ROOT/'scripts/test-protected-matrix.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
d, h = m.d, m.h
PREFIX = 'authgo-watermark-e2e-'+str(os.getpid())+'-'
m.PREFIX = d.PREFIX = PREFIX
d.API=PREFIX+'api'; d.API2=PREFIX+'other-api'; d.IMAGE=PREFIX+'server'
OUT=ROOT.parent/('watermark-e2e-'+str(os.getpid()))
OUT.mkdir()
RESULT={'status':'RUNNING','mock_auth':False,'languages':{},'failures':[]}
original_inject=m.inject_probe

def save():
    (OUT/'results.json').write_text(json.dumps(RESULT,ensure_ascii=False,indent=2)+'\n')

def inject(lang,directory):
    original_inject(lang,directory)
    if lang=='python':
        # Add an independent encrypted TEST module; do not rewrite original
        # core.response business logic to accommodate watermark semantics.
        (directory/'core/closure_fixture.py').write_text((ROOT/'tests/watermark/closures.py').read_text())
        build_file=directory/'build.py';build_file.write_text(build_file.read_text()+"\npy_compile.compile('/src/example/core/closure_fixture.py', cfile='/staging/core/closure_fixture.pyc', dfile='authgo-sealed://core/closure_fixture.py', doraise=True)\n")
        p=directory/'main.py'; text=p.read_text().replace('import signal','import marshal\nimport gc\nimport sys\nimport signal',1)
        text=text.replace('        import core\n','        import core\n        import core.closure_fixture as closure_fixture\n',1)
        text=text.replace('def do_GET(self):','''def do_GET(self):
                if self.path in ("/__watermark_dump", "/__watermark_dump_nested", "/__watermark_dump_outer", "/__watermark_dump_module"):
                    guard.require()
                    if self.path == "/__watermark_dump":
                        # This exact original business function has run via HTTP.
                        assert core.response(guard)["language"] == "python"
                        code = core.response.__code__
                    elif self.path == "/__watermark_dump_nested":
                        actual = closure_fixture.outer(3)
                        assert actual(4) == 7
                        code = actual.__code__
                        del actual
                    elif self.path == "/__watermark_dump_outer":
                        actual = closure_fixture.outer(3)
                        assert actual(4) == 7
                        code = closure_fixture.outer.__code__
                        del actual
                    else:
                        # Retain the old module export as explicit auxiliary evidence.
                        code = core.__loader__.get_code("core")
                        assert code is core.__loader__.get_code("core")
                    gc.collect()
                    body = marshal.dumps(code)
                    self.send_response(200); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
                    return''',1)
        p.write_text(text)
    elif lang=='node':
        p=directory/'main.mjs'; text=p.read_text().replace('const core = await guard.requireSealed("core");','const core = await guard.requireSealed("core"); globalThis.__authgo_watermark_executed_core = core;',1).replace('import http from','import inspector from "node:inspector";\nimport http from',1)
        text=text.replace('http.createServer((_, response) => {','''http.createServer(async (request, response) => {
      if (request.url === "/__watermark_dump") {
        guard.require();
        if(typeof globalThis.gc!=="function")throw new Error("test process GC unavailable");
        for(let i=0;i<4;i++)globalThis.gc();
        const session = new inspector.Session(); session.connect();
        const scripts = []; session.on("Debugger.scriptParsed", event => scripts.push(event.params));
        const post = (method, params={}) => new Promise((resolve,reject) => session.post(method,params,(e,v)=>e?reject(e):resolve(v)));
        try {
          await post("Debugger.enable");
          // The SDK first creates an UNEXECUTED vm.Script for grammar
          // validation. Its URL can equal _compile's actual executing script.
          // Use the exact already invoked exported function's V8 location,
          // never the first script with the same URL.
          const evaluated = await post("Runtime.evaluate", {expression:"globalThis.__authgo_watermark_executed_core",objectGroup:"watermark-runtime-export"});
          if (evaluated.result.type !== "function" || !evaluated.result.objectId) throw new Error("actual invoked core function missing");
          const props = await post("Runtime.getProperties", {objectId:evaluated.result.objectId,ownProperties:true});
          const location = props.internalProperties.find(row=>row.name === "[[FunctionLocation]]")?.value?.value;
          if (!location?.scriptId) throw new Error("actual function script location absent");
          const script = scripts.find(row => row.scriptId === location.scriptId);
          if (!script?.url.endsWith(".authgo-sealed-core.cjs")) throw new Error("actual function is not sealed core");
          const dumped = await post("Debugger.getScriptSource", {scriptId:location.scriptId});
          response.end(JSON.stringify({scriptSource:dumped.scriptSource,functionLocation:location,selectedURL:script.url,sameURLCandidates:scripts.filter(row=>row.url===script.url).map(row=>row.scriptId),method:"already-invoked exported function [[FunctionLocation]]"}));
          await post("Runtime.releaseObjectGroup", {objectGroup:"watermark-runtime-export"});
        } finally {session.disconnect();}
        return;
      }''',1)
        p.write_text(text)
    elif lang=='php':
        p=directory/'main.php'; text=p.read_text().replace('$stopping=false;', '$stopping=false; set_error_handler(static function($severity,$message){if(str_contains($message,"Constant __authgo_watermark_"))throw new ErrorException("watermark root constant collision",0,$severity);return false;});',1)
        text=text.replace('@fread($connection,1024);','''$request=@fread($connection,1024);
                    if (str_starts_with($request,"GET /__watermark_reinstall ")) {
                        $guard->close();
                        try {
                            $second=getenv('AUTHGO_TEST_SECOND_LICENSE');
                            if(!$second)throw new RuntimeException('missing second test license');
                            $guard=AuthGo\\start_guard(['config'=>CONFIG,'license'=>$second,'version'=>VERSION,'on_change'=>'change']);
                            $guard->installSealed('core');$core=require 'authgo-sealed://core/bootstrap.php';
                            $body=AuthGo\\Json::encode($core($guard));
                        } catch (Throwable $error) {
                            // Codes only: uncaught PHP stack arguments can expose
                            // a truncated license. Never log exception arguments.
                            $code=$error instanceof AuthGo\\Error?$error->errorCode:'watermark_REINSTALL_ERROR';
                            @fwrite($connection,"HTTP/1.1 503 Service Unavailable\r\nContent-Length: ".strlen($code)."\r\nConnection: close\r\n\r\n".$code);fclose($connection);continue;
                        }
                        @fwrite($connection,"HTTP/1.1 200 OK\r\nContent-Length: ".strlen($body)."\r\nConnection: close\r\n\r\n".$body);fclose($connection);continue;
                    }
                    if (str_starts_with($request,"GET /__watermark_dump_aux ")) {
                        $guard->require();
                        $reflection=new ReflectionFunction($core);
                        $constants=array_filter(get_defined_constants(),static fn($key)=>str_starts_with($key,'__authgo_watermark_'),ARRAY_FILTER_USE_KEY);
                        // Auxiliary VM reflection only. Never the main code export.
                        $body=serialize(['statics'=>$reflection->getStaticVariables(),'root_constants'=>$constants]);
                        @fwrite($connection,"HTTP/1.1 200 OK\r\nContent-Length: ".strlen($body)."\r\nConnection: close\r\n\r\n".$body);fclose($connection);continue;
                    }
                    if (str_starts_with($request,"GET /__watermark_dump ")) {
                        $guard->require();
                        // The VM closure has already served the core business request.
                        // Its actual opened_path identifies the exact installed mount,
                        // not a fresh decryption or a second resource copy.
                        gc_collect_cycles();
                        $reflection=new ReflectionFunction($core);
                        $executed=$reflection->getFileName();
                        if(!is_string($executed)||!str_starts_with($executed,'authgo-sealed://m-'))throw new RuntimeException('executed sealed identity missing');
                        $body=file_get_contents($executed);
                        if(!is_string($body)||!str_starts_with($body,'<?php'))throw new RuntimeException('executed core source missing');
                        @fwrite($connection,"HTTP/1.1 200 OK\\r\\nX-AuthGo-Executed-Path: ".$executed."\\r\\nX-AuthGo-Source-SHA256: ".hash('sha256',$body)."\\r\\nContent-Length: ".strlen($body)."\\r\\nConnection: close\\r\\n\\r\\n".$body);fclose($connection);continue;
                    }''',1)
        p.write_text(text)
    elif lang=='java':
        agent=(ROOT/'tests/watermark/Agent.java').read_text().replace('watermark.Business','Main').replace('watermark/Business','Main')
        (directory/'Agent.java').write_text(agent)
        p=directory/'build.sh'; text=p.read_text()+'''\nmkdir -p /out/agent
javac -d /out/agent /src/example/Agent.java
printf 'Premain-Class: watermarkprobe.Agent\\nCan-Retransform-Classes: true\\n' > /out/agent-manifest
jar --create --file /runtime-export-agent.jar --manifest /out/agent-manifest -C /out/agent .
''';p.write_text(text)
        p=directory/'Dockerfile';text=p.read_text().replace('COPY --from=build /launcher.jar','COPY --from=build /runtime-export-agent.jar /runtime-export-agent.jar\nCOPY --from=build /launcher.jar',1)
        text=text.replace('"java", "-XX:', '"java", "-javaagent:/runtime-export-agent.jar=/tmp", "-XX:',1);p.write_text(text)
    # m.build reads Dockerfile before this hook; account for that below.

m.inject_probe=inject
original_build=m.build

def build(lang,config,key,qa):
    # The CA is generated by h.certificates() inside d.TMP and must remain available
    # to the matrix builder until it has copied qa/ca.crt into its disposable context.
    qa=pathlib.Path(qa).resolve()
    assert (qa/'ca.crt').is_file(), 'temporary test CA was not generated'
    # Add the generated CA to the disposable build context and apply QA-only
    # Java agent/Node GC declarations via copytree, never to public examples.
    original_copy=shutil.copytree
    def copy(src,dst,*args,**kwargs):
        result=original_copy(src,dst,*args,**kwargs)
        if pathlib.Path(src)==ROOT/'examples/docker-protected':
            context=pathlib.Path(dst).parents[1]
            (context/'qa').mkdir(parents=True,exist_ok=True)
            shutil.copy2(qa/'ca.crt',context/'qa/ca.crt')
            if lang=='node':
                # QA image only. The production example has no GC/debug flag.
                p=pathlib.Path(dst)/'node/Dockerfile';text=p.read_text()
                assert text.count('ENTRYPOINT ["node", "/app/main.mjs"]')==1
                p.write_text(text.replace('ENTRYPOINT ["node", "/app/main.mjs"]','ENTRYPOINT ["node", "--expose-gc", "/app/main.mjs"]',1))
            elif lang=='java':
                p=pathlib.Path(dst)/'java/Dockerfile';text=p.read_text().replace('COPY --from=build /launcher.jar','COPY --from=build /runtime-export-agent.jar /runtime-export-agent.jar\nCOPY --from=build /launcher.jar',1)
                p.write_text(text.replace('"java", "-XX:', '"java", "-javaagent:/runtime-export-agent.jar=/tmp", "-XX:',1))
        return result
    shutil.copytree=copy
    try:return original_build(lang,config,key,qa)
    finally:shutil.copytree=original_copy

def raw_get(address,path):
    with urllib.request.urlopen('http://'+address+path,timeout=10) as response:
        assert response.status==200
        return response.read()

def pe_at(mem,start,tag):
    mem.seek(start);header=mem.read(4096)
    if header[:2]!=b'MZ':return None
    pe=struct.unpack_from('<I',header,0x3c)[0]
    if pe+256>len(header) or header[pe:pe+4]!=b'PE\0\0':return None
    n=struct.unpack_from('<H',header,pe+6)[0];opt=struct.unpack_from('<H',header,pe+20)[0];sec=pe+24+opt
    if not 1<=n<=16 or sec+40*n>len(header):return None
    hs=struct.unpack_from('<I',header,pe+24+60)[0];size=hs;sections=[]
    for i in range(n):
        vs,rva,raw,ptr=struct.unpack_from('<IIII',header,sec+40*i+8)
        if raw>16*1024**2 or ptr>16*1024**2 or rva>32*1024**2:return None
        size=max(size,ptr+raw);sections.append((rva,raw,ptr))
    if not 512<=size<=16*1024**2:return None
    mem.seek(start);flat=mem.read(size)
    # Flat LoadFromStream images use file offsets, NOT RVAs. Test that actual
    # PE image first: reading an unmapped RVA for a speculative mapped-layout
    # candidate must not discard an already valid flat image.
    if len(flat)==size and len(re.findall(re.escape(tag)+b'[0-9a-f]{64}',flat))>=8:
        return 'flat',flat
    candidates=[]
    rebuilt=bytearray(size);rebuilt[:hs]=header[:hs]
    for rva,raw,ptr in sections:
        mem.seek(start+rva);blob=mem.read(raw)
        if len(blob)!=raw:return None
        rebuilt[ptr:ptr+raw]=blob
    candidates.append(('mapped-rebuilt',bytes(rebuilt)))
    for kind,blob in candidates:
        if len(re.findall(re.escape(tag)+b'[0-9a-f]{64}',blob))>=8:return kind,blob
    return None

def export(lang,name,address,folder,tag):
    cfg=d.inspect(name);pid=cfg['State']['Pid'];assert cfg['State']['Running'] and pid>0
    evidence={'pid':pid,'state_before':cfg['State']}
    suffix={'go':'elf','rust':'elf','java':'class','csharp':'dll','python':'marshal','node':'cjs','php':'php'}[lang]
    target=folder/('runtime.'+suffix)
    if lang in ('go','rust'):
        exe='/proc/'+str(pid)+'/exe';assert 'memfd:authgo-main' in os.readlink(exe) or '(deleted)' in os.readlink(exe)
        blob=pathlib.Path(exe).read_bytes();assert len(blob)>=100*1024**2
        evidence['source']='live PID1 /proc/pid/exe sealed executable mapping'
    elif lang in ('python','node','php'):
        if lang=='php':
            with urllib.request.urlopen('http://'+address+'/__watermark_dump',timeout=10) as response:
                assert response.status==200
                blob=response.read();opened=response.headers.get('X-AuthGo-Executed-Path','');reported=response.headers.get('X-AuthGo-Source-SHA256','')
            assert re.fullmatch(r'authgo-sealed://m-[0-9a-f]{32}/bootstrap\.php',opened),'actual executed mount identity missing'
            assert reported==hashlib.sha256(blob).hexdigest(),'actual stream bytes/hash mismatch'
            evidence['actual_executed_opened_path']=opened;evidence['actual_stream_source_sha256']=reported
        else:blob=raw_get(address,'/__watermark_dump')
        if lang=='node':
            packet=json.loads(blob);blob=packet.pop('scriptSource').encode();evidence['V8_function_identity']=packet
        evidence['source']={'python':'exact already invoked original core.response.__code__ after GC; not only module code','node':'V8 Debugger.getScriptSource of loaded sealed CommonJS module','php':'actual already-executed ReflectionFunction opened_path read through the live Guard-owned authgo-sealed mount; no decrypt/reinstall'}[lang]
        if lang=='python':
            extra=[]
            for kind,url in [('actual-closure','/__watermark_dump_nested'),('actual-outer','/__watermark_dump_outer'),('auxiliary-module','/__watermark_dump_module')]:
                packet=raw_get(address,url);sub=folder/kind;sub.mkdir();p=sub/'runtime.marshal';p.write_bytes(packet)
                assert packet.count(tag.encode())>=8,'actual invoked Python '+kind+' lost slots'
                extra.append({'kind':kind,'file':str(p),'sha256':hashlib.sha256(packet).hexdigest(),'bytes':len(packet),'actual_function_or_module':True,'after_GC':True})
            evidence['additional_exports']=extra
        if lang=='php':
            assert m.MARKER in blob and b'return static function' in blob and b'AuthGo\\Guard' in blob,'not the complete actual business source'
            auxiliary=raw_get(address,'/__watermark_dump_aux');(folder/'auxiliary.zend-statics').write_bytes(auxiliary)
            evidence['auxiliary_VM_snapshot']={'file':'auxiliary.zend-statics','not_complete_code':True,'bytes':len(auxiliary),'sha256':hashlib.sha256(auxiliary).hexdigest()}

    elif lang=='java':
        temp=pathlib.Path('/proc/'+str(pid)+'/root/tmp');(temp/'agent-trigger').write_text('export after real business HTTP response\n')
        d.wait(lambda:(temp/'agent-done').exists() or (temp/'agent-error').exists(),20,'runtime retransform timeout')
        assert not (temp/'agent-error').exists(),'runtime agent export failed'
        blob=(temp/'agent-runtime.class').read_bytes();evidence['source']='Instrumentation.retransformClasses AFTER actual loaded Main served business HTTP'
    else:
        maps=pathlib.Path('/proc/'+str(pid)+'/maps').read_text();(folder/'runtime-maps.log').write_text(maps);found=None
        with open('/proc/'+str(pid)+'/mem','rb',buffering=0) as mem:
            for line in maps.splitlines():
                parts=line.split(maxsplit=5)
                if not parts[1].startswith('r') or len(parts)>5 and parts[5].startswith(('/usr/share/dotnet','/usr/lib','/lib')):continue
                lo,hi=[int(x,16) for x in parts[0].split('-')]
                if hi-lo>128*1024**2:continue
                for start in range(lo,hi,4096):
                    try:found=pe_at(mem,start,tag.encode())
                    except (OSError,struct.error,ValueError):continue
                    if found:evidence['mapping']=line;evidence['location']=hex(start);break
                if found:break
        assert found,'actual runtime PE image containing 8 watermarks absent'
        kind,blob=found;evidence['source']='exact live dotnet PID mapped PE, '+kind
    assert tag.encode() in blob,'runtime export has no target software tag'
    target.write_bytes(blob)
    if lang=='php':
        lint_name=PREFIX+'php-lint-'+hashlib.sha256(str(folder).encode()).hexdigest()[:10]
        d.containers.append(lint_name)
        lint=subprocess.run(['docker','run','--name',lint_name,'--memory=256m','--cpus=1','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges:true','-v',str(target)+':/export.php:ro','php:8.1-cli','php','-l','/export.php'],capture_output=True,text=True)
        lint_state=d.inspect(lint_name)['State'];(folder/'source-lint.log').write_text(lint.stdout+lint.stderr)
        evidence['actual_export_syntax_validation']={'exit':lint.returncode,'State':lint_state,'source_sha256':hashlib.sha256(blob).hexdigest()}
        (folder/'source-lint-state.json').write_text(json.dumps(lint_state,indent=2)+'\n')
        assert lint.returncode==0 and lint_state['ExitCode']==0 and not lint_state['OOMKilled'],'actual exported PHP source failed syntax validation'
        d.docker('rm',lint_name)
    evidence.update(bytes=len(blob),sha256=hashlib.sha256(blob).hexdigest(),state_after=d.inspect(name)['State'])
    assert evidence['state_after']['Running'] and evidence['state_after']['Pid']==pid
    m.ready(name,address)
    (folder/'export.json').write_text(json.dumps(evidence,indent=2)+'\n')
    return target

def trace(path,tag):
    p=subprocess.run(['docker','run','--rm','--name',PREFIX+'trace','--network=none','--memory=512m','--read-only','--cap-drop=ALL','-v',str(OUT)+':/evidence:ro',m.TOOLS,'trace','--tag',tag,'/evidence/'+str(path.relative_to(OUT))],capture_output=True,text=True)
    (path.parent/(path.name+'.trace.json')).write_text(p.stdout)
    assert p.returncode==0,'actual CLI trace failed rc='+str(p.returncode)+' '+p.stderr[:120]
    return json.loads(p.stdout)

def found_trace(result):
    # CLI JSON uses same status/values object as browser scan result.
    assert result.get('status')=='found',json.dumps(result)[:240]
    return result['watermark']

def variants(path,tag):
    blob=path.read_bytes();pattern=re.compile(re.escape(tag.encode())+b'[0-9a-f]{64}')
    matches=list(pattern.finditer(blob));assert len(matches)>=8,'fewer than 8 retained actual runtime slots'
    damaged=bytearray(blob)
    for match in matches[:len(matches)//2]:damaged[match.start()]=ord('!')
    half=path.with_name('half-damaged.'+path.suffix.lstrip('.'));half.write_bytes(damaged)
    inner=io.BytesIO()
    with zipfile.ZipFile(inner,'w',compression=zipfile.ZIP_DEFLATED) as z:z.writestr('runtime/'+path.name,blob)
    zip_path=path.with_name('runtime-nested.jar')
    with zipfile.ZipFile(zip_path,'w',compression=zipfile.ZIP_DEFLATED) as z:z.writestr('BOOT-INF/lib/runtime.jar',inner.getvalue())
    return [path,half,zip_path],len(matches)

def retain_states():
    states={}
    for name in d.containers:
        if not name.startswith(PREFIX):continue
        try:
            cfg=d.inspect(name);states[name]={'State':cfg['State'],'RestartCount':cfg.get('RestartCount'),'readiness':m.READINESS_EVIDENCE.get(name,[])}
            if name in (d.API,d.API2):
                states[name]['test_fault_events']=d.logs(name).count('watermark_WATERMARK_AFTER_SIGNATURE_MUTATION')
                text=''
            else:text=d.docker('logs','--timestamps',name,check=False)
            for secret in d.SENSITIVE:text=text.replace(secret,'<redacted>')
            text=re.sub(r'AUTH-[A-Z0-9-]+','<redacted-license-prefix>',text)
            (OUT/(name+'.log')).write_text(text)
        except Exception as e:states[name]={'unavailable':type(e).__name__}
    (OUT/'container-states.json').write_text(json.dumps(states,indent=2)+'\n')

def build_fault_instrumented_backend():
    # Isolated COPY of production backend. The only extra behavior is a
    # parent-controlled test flag: mutate watermark AFTER signing, BEFORE the
    # original gateway AEAD. No SDK/TLS/config/authentication changes or mock DB.
    context=d.TMP/'fault-backend';context.mkdir()
    # The production root build now embeds the real frontend in this test copy too.
    shutil.copy2(ROOT/'Dockerfile',context/'Dockerfile')
    shutil.copy2(ROOT/'.dockerignore',context/'.dockerignore')
    shutil.copytree(ROOT/'web',context/'web',ignore=shutil.ignore_patterns('node_modules','dist','.env','.env.*','coverage','test-results'))
    shutil.copytree(ROOT/'server',context/'server',ignore=shutil.ignore_patterns('bin','obj','data','*.db','*.db-*'))
    (context/'sdk').mkdir();shutil.copytree(ROOT/'sdk/go',context/'sdk/go')
    path=context/'server/internal/client/http.go';original=path.read_text()
    anchor='\tc.Header("Cache-Control", "no-store")'
    assert original.count(anchor)==1 and original.count('"mime"')==1
    hook='''	// TEST COPY ONLY: a valid value changed after the original signature.
	if _, testErr := os.Stat("/data/watermark-watermark-tamper"); testErr == nil {
		if value, ok := body.Data["watermark"].(string); ok {
			replacement := strings.Repeat("2a", 32)
			if value == replacement { replacement = strings.Repeat("2b", 32) }
			body.Data["watermark"] = replacement
			s.log.Info("watermark_WATERMARK_AFTER_SIGNATURE_MUTATION")
		}
	}
'''
    modified=original.replace('\t"mime"', '\t"mime"\n\t"os"\n\t"strings"', 1).replace(anchor,hook+anchor,1);path.write_text(modified)
    (OUT/'instrumented-backend.json').write_text(json.dumps({'mock_auth':False,'fixture_copy_only':True,'normal_sign_and_AEAD_unchanged':True,'original_sha256':hashlib.sha256(original.encode()).hexdigest(),'fixture_sha256':hashlib.sha256(modified.encode()).hexdigest(),'hook':hook},indent=2)+'\n')
    d.images.append(d.IMAGE)
    h.checked(['docker','build','--memory=1536m','-f','Dockerfile','-t',d.IMAGE,'.'],context)
    shutil.rmtree(context)

BROWSER_CASES=[]
def suite(lang,qa,endpoint):
    m.disk();item={'status':'RUNNING','cases':[]};RESULT['languages'][lang]=item;save()
    app=d.request('/api/v1/admin/applications',{'name':'watermark real memory '+lang,'heartbeat_interval':5,'next_check_in':1,'grace_hours':72});d.state['app']=app
    key=d.request('/api/v1/admin/applications/'+str(app['id'])+'/payload-keys',{},'POST')
    config=d.request('/api/v1/admin/applications/'+str(app['id'])+'/connection',{'url':endpoint})['config'];d.SENSITIVE.add(config)
    tag_record=d.request('/api/v1/admin/applications/'+str(app['id'])+'/watermark-tags')['items'][0]
    tag, key_id = tag_record['tag'], tag_record['key_id']
    image,context=build(lang,config,key,qa);item['image']=d.docker('image','inspect',image,'--format','{{.Id}}').strip()
    watermarks=[]
    for i in range(2):
        lic=m.lic();vol=d.volume_new(lang+'-license'+str(i));folder=OUT/lang/str(i);folder.mkdir(parents=True)
        name,address,begin=m.start(lang+'-license'+str(i),lic['key'],vol,image)
        m.ready(name,address);startup=round(time.monotonic()-begin,4)
        path=export(lang,name,address,folder,tag)
        assert lic['key'].encode() not in path.read_bytes(),'export exposed plaintext license code'
        runtime_paths=[path]
        if lang=='python':runtime_paths.extend(folder/kind/'runtime.marshal' for kind in ('actual-closure','actual-outer','auxiliary-module'))
        wm=None;code_counts={};main_count=None
        for code_path in runtime_paths:
            assert lic['key'].encode() not in code_path.read_bytes(),'actual code export exposed plaintext license code'
            paths,count=variants(code_path,tag);code_counts[str(code_path.relative_to(folder))]=count
            if main_count is None:main_count=count
            for variant in paths:
                result=trace(variant,tag);value=found_trace(result)
                expected=count-count//2 if variant.name.startswith('half-damaged.') else count
                assert result['complete'] and result['count']==expected and result['slots']==expected,'actual CLI slot count mismatch'
                if wm is not None:assert value==wm
                wm=value
                source=d.request('/api/v1/admin/applications/'+str(app['id'])+'/watermark-trace',{'watermark':value})
                assert source['found'] and source['license_id']==lic['id'] and not source.get('is_trial',False),'real license trace mismatch'
                BROWSER_CASES.append({'file':str(variant),'app_id':app['id'],'license_id':lic['id'],'watermark':value,'tag':tag,'key_id':key_id,'language':lang,'variant':str(variant.relative_to(folder)),'is_trial':False,'expected_consistent_slots':expected,'expected_total_slots':expected})
        count=main_count
        if lang=='php':
            auxiliary=(folder/'auxiliary.zend-statics').read_bytes()
            assert auxiliary.count((tag+wm).encode())>=8,'actual VM root constants lost this license watermark'
        watermarks.append(wm);assert len(m.caches(vol))==1,'missing authenticated v2 cache'
        # Exact same volume/instance and image, restart with actual backend disconnected.
        d.stop(name);d.stop_api()
        try:
            d.docker('start',name);m.ready(name,address)
            off=folder/'offline';off.mkdir();offpath=export(lang,name,address,off,tag)
            assert found_trace(trace(offpath,tag))==wm,'offline-cache restart lost/replaced watermark'
            d.stop(name)
        finally:d.restore_api()
        # Corrupt only ciphertext/authentication tag while retaining valid cache syntax.
        cache=m.caches(vol)[0];original_cache=cache.read_bytes();prefix,encoded=original_cache.split(b'.',1)
        raw=bytearray(base64.urlsafe_b64decode(encoded+b'='*((-len(encoded))%4)));raw[-1]^=1
        cache.write_bytes(prefix+b'.'+base64.urlsafe_b64encode(raw).rstrip(b'='));d.stop_api()
        try:
            d.docker('start',name);d.ended(name,77,seconds=35)
            (folder/'tampered-cache-state.json').write_text(json.dumps(d.inspect(name)['State'],indent=2)+'\n')
        finally:d.restore_api()
        item['cases'].append({'license_id':lic['id'],'slots':count,'actual_code_exports':code_counts,'watermark':wm,'startup_seconds':startup,'same_image':True,'no_plain_license':True,'damage_half':True,'nested_zip':True,'offline_restart':True,'cache_ciphertext_tamper_rejected':True})
        print('PASS watermark_REAL '+lang+' license'+str(i)+' slots='+str(count)+' offline=PASS',flush=True);save()
    assert watermarks[0]!=watermarks[1],'two licenses shared a watermark'
    # Rotate without rebuilding: the original key remains searchable.
    d.request('/api/v1/admin/applications/'+str(app['id'])+'/payload-keys',{},'POST')
    assert any(row['tag']==tag and row['key_id']==key['key_id'] for row in d.request('/api/v1/admin/applications/'+str(app['id'])+'/watermark-tags')['items'])
    assert d.request('/api/v1/admin/applications/'+str(app['id'])+'/watermark-trace',{'watermark':watermarks[0]})['license_id']==item['cases'][0]['license_id']
    item['old_key_rotation_trace']=True
    # Exact valid post-signature mutation of real backend response, cold cache.
    flag=m.mountpath(d.state['data_volume'])/'watermark-watermark-tamper'
    before=d.logs(d.API).count('watermark_WATERMARK_AFTER_SIGNATURE_MUTATION')
    flag.write_text('test-only fault injection\n');flag.chmod(0o444)
    tamper_lic=m.lic();tamper_vol=d.volume_new(lang+'-signature-tamper')
    try:
        tamper_name,tamper_address,_=m.start(lang+'-signature-tamper',tamper_lic['key'],tamper_vol,image)
        # The native stub preserves the pre-existing recoverable-error cache
        # policy: after signature rejection its cold fallback reports missing
        # cached material. SDK unit tests separately require exact signature code.
        expected_code='SDK_CACHE_UNAVAILABLE' if lang in ('go','rust') else 'SDK_RESPONSE_SIGNATURE_INVALID'
        d.ended(tamper_name,77,text=expected_code,seconds=35)
        assert not m.caches(tamper_vol) and m.request(tamper_address)[0]!=200
        assert d.logs(d.API).count('watermark_WATERMARK_AFTER_SIGNATURE_MUTATION')==before+1,'fault hook was not applied exactly once'
        (OUT/lang/'signature-tamper-state.json').write_text(json.dumps(d.inspect(tamper_name)['State'],indent=2)+'\n')
    finally:flag.unlink(missing_ok=True)
    # The SAME image/license/volume succeeds after removing only the fault.
    d.docker('start',tamper_name);m.ready(tamper_name,tamper_address);d.stop(tamper_name)
    item['real_signed_watermark_tamper']={'signed_response_rejection_verified_by_SDK_tests':True,'visible_process_error':expected_code,'exit_code':77,'cold_payload_cache':True,'positive_control_same_image':True,'fixture_fault_hook_not_production':True}
    print('PASS watermark_REAL '+lang+' real-backend post-signature watermark mutation rejected/control=PASS',flush=True)
    d.request('/api/v1/admin/applications/'+str(app['id'])+'/trial',{'trial_enabled':True,'trial_days':14},'PATCH')
    vol=d.volume_new(lang+'-trial');name,address,_=m.start(lang+'-trial','',vol,image)
    m.ready(name,address);folder=OUT/lang/'trial';folder.mkdir();path=export(lang,name,address,folder,tag)
    trial_trace=trace(path,tag);wm=found_trace(trial_trace);source=d.request('/api/v1/admin/applications/'+str(app['id'])+'/watermark-trace',{'watermark':wm})
    assert source['found'] and source['is_trial'] and source['license_id']>0 and source.get('sources'),'trial origin missing'
    assert not m.caches(vol),'trial cached payload key/watermark'
    BROWSER_CASES.append({'file':str(path),'app_id':app['id'],'license_id':source['license_id'],'watermark':wm,'tag':tag,'key_id':key_id,'language':lang,'variant':path.name,'is_trial':True,'expected_consistent_slots':trial_trace['count'],'expected_total_slots':trial_trace['slots']})
    item['trial']={'license_id':source['license_id'],'sources':source['sources'],'no_cache':True,'watermark':wm}
    d.stop(name);d.stop_api()
    try:d.docker('start',name);d.ended(name,77,seconds=35);assert not m.caches(vol)
    finally:d.restore_api()
    print('PASS watermark_REAL '+lang+' trial-source/no-cache/offline-reject',flush=True)
    if lang=='php':
        first=m.lic();second=m.lic();volume=d.volume_new('php-guard-switch')
        name,address,_=m.start('php-guard-switch',first['key'],volume,image,{'AUTHGO_TEST_SECOND_LICENSE':second['key']})
        m.ready(name,address);pid=d.inspect(name)['State']['Pid']
        repeated=json.loads(raw_get(address,'/__watermark_reinstall'))
        assert repeated['marker']==m.MARKER.decode() and d.inspect(name)['State']['Pid']==pid,'same-process Guard close/install lost core'
        assert not h.active_seats(first) and len(h.active_seats(second))==1
        folder=OUT/lang/'guard-switch';folder.mkdir();path=export(lang,name,address,folder,tag)
        value=found_trace(trace(path,tag));source=d.request('/api/v1/admin/applications/'+str(app['id'])+'/watermark-trace',{'watermark':value})
        assert source['found'] and source['license_id']==second['id'],'new Guard reused old watermark'
        item['same_process_guard_close_reinstall']={'same_PID':pid,'license_A':first['id'],'license_B':second['id'],'B_watermark_correct':True,'no_duplicate_warning':True};d.stop(name)
        print('PASS watermark_REAL php Guard A close -> Guard B install/execute same PID and correct B watermark',flush=True)
    item['status']='PASS';save()
    # Keep images until all real browsers finish; remove context containing compile-time config.
    shutil.rmtree(context)
    m.disk()

def build_frontend():
    # The browser stage serves web/dist directly; build it with the same locked
    # Node toolchain as CI, while keeping node_modules in a named cache volume.
    volume=PREFIX+'web-nodemod';d.volumes.append(volume);d.docker('volume','create',volume)
    name=PREFIX+'web-build';d.containers.append(name)
    d.docker('run','--rm','--name',name,'--memory=1536m','--cpus=2',
             '-v',str(ROOT)+':/src','-v',volume+':/src/web/node_modules',
             '-w','/src/web','node:22-alpine','sh','-ec','npm ci && npm run build')

def main():
    selected=sys.argv[1:] or ['go','python','node','rust','java','csharp','php']
    assert all(x in ('go','python','node','rust','java','csharp','php') for x in selected)
    m.disk();d.TMP=pathlib.Path(tempfile.mkdtemp(prefix=PREFIX,dir=ROOT.parent));proxy=None
    try:
        build_fault_instrumented_backend();d.api_start();d.SENSITIVE.add(d.state['token']);d.state['user_id']=d.request('/api/v1/admin/users',{'name':'watermark runtime customer','email':'watermark@example.invalid'})['id'];qa=h.certificates();proxy,endpoint=h.tls_proxy(qa)
        for lang in selected:suite(lang,qa,endpoint)
        # Test browser talks to the actual running backend; token stays in temp env,
        # never results/logs and never in source config. No intercepted API routes.
        (OUT/'browser-inputs.json').write_text(json.dumps(BROWSER_CASES,indent=2)+'\n')
        build_frontend()
        env={**os.environ,'AUTHGO_E2E_API':d.state['base'],'AUTHGO_E2E_TOKEN':d.state['token'],'AUTHGO_E2E_OUT':str(OUT)}
        browser=PREFIX+'browser';d.containers.append(browser)
        subprocess.run(['docker','run','--rm','--name',browser,'--network=host','--memory=1536m','--cpus=2','--shm-size=256m','--cap-drop=ALL','--security-opt=no-new-privileges:true',
            '-e','AUTHGO_E2E_API','-e','AUTHGO_E2E_TOKEN','-e','AUTHGO_E2E_OUT','-v',str(ROOT)+':'+str(ROOT)+':ro','-v',str(OUT)+':'+str(OUT),
            'mcr.microsoft.com/playwright:v1.56.1-noble','bash','-lc',
            'mkdir -p /tmp/authgo-watermark-playwright && cd /tmp/authgo-watermark-playwright && npm install --ignore-scripts --no-audit --no-fund --package-lock=false --no-save playwright@1.56.1 && AUTHGO_PLAYWRIGHT=/tmp/authgo-watermark-playwright/node_modules/playwright/index.mjs node '+str(ROOT/'web/scripts/test-watermark-e2e.mjs')],env=env,check=True)
        RESULT['status']='PASS';print('watermark_RUNTIME_E2E_DONE 0 '+str(OUT),flush=True)
    except Exception as e:
        import traceback
        frames=[{'file':pathlib.Path(f.filename).name,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(sys.exc_info()[2])]
        detail=str(e) if isinstance(e,AssertionError) else type(e).__name__
        for secret in d.SENSITIVE:detail=detail.replace(secret,'<redacted>')
        RESULT['status']='FAIL';RESULT['failures'].append({'error':detail[:800],'frames':frames});print('watermark_RUNTIME_E2E_DONE 1 '+detail[:400]+' '+str(OUT),flush=True)
        raise SystemExit(1)
    finally:
        failure=d.TMP/'failed-command.log'
        if failure.exists():
            text=failure.read_text()
            for secret in d.SENSITIVE:text=text.replace(secret,'<redacted>')
            (OUT/'failed-build-command.log').write_text(text)
        retain_states();save()
        if proxy:proxy.shutdown();proxy.server_close()
        d.cleanup()
if __name__=='__main__':main()
