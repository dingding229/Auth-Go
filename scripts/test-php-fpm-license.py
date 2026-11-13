"""Real FPM/nginx test, imported only by the named Docker test harness."""
from concurrent.futures import ThreadPoolExecutor
import json
import pathlib
import re
import secrets
import time
import urllib.request
import urllib.error


def suite(h):
    print("LANGUAGE php-fpm: real PHP-FPM + nginx", flush=True)
    h.build("Dockerfile", h.IMAGE); h.api_start()
    h.state["app"] = h.request("/api/v1/admin/applications", {"name":"FPM容器测试","heartbeat_interval":5,"next_check_in":30,"grace_hours":72})
    h.state["user_id"] = h.request("/api/v1/admin/users", {"name":"FPM测试","email":"fpm@example.invalid"})["id"]
    config = h.request("/api/v1/admin/applications/"+str(h.state["app"]["id"])+"/connection", {"url":h.state["base"]})["config"]
    h.build("examples/docker/php-fpm/Dockerfile",h.APP_IMAGE,config)
    clock_image=h.PREFIX+"fpm-clock"; h.build("scripts/fixtures/docker-clock-php-fpm.Dockerfile",clock_image,config)
    nginx_image=h.PREFIX+"fpm-nginx"; h.build("examples/docker/php-fpm/Dockerfile.nginx",nginx_image)
    # Competitor is another FPM container; no CLI helper/gate/extra SDK involved.
    services=[]
    def fpm_listening(port):
        # A running container is not an accepting FastCGI server. Probe only
        # transport readiness, never retry/mask an authorization HTTP failure.
        try:
            with __import__('socket').create_connection(("127.0.0.1",port),timeout=.3):return True
        except OSError:return False
    def start(label,lic,image=None,volume=None,transient=False):
        fp=h.port();web=h.port();vol=volume or h.volume_new("fpm-"+label)
        fpm=h.PREFIX+label+"-fpm";nginx=h.PREFIX+label+"-nginx";project=h.PREFIX+label
        h.containers.extend([fpm,nginx])
        if lic["key"]:h.SENSITIVE.add(lic["key"])
        tmp=h.TMP/(label+".json")
        # A unique loopback-only listener for each host-networked FPM test.
        conf=(h.ROOT/"examples/docker/php-fpm/php-fpm.conf").read_text().replace("0.0.0.0:9000","127.0.0.1:"+str(fp))
        # Non-root FPM can read this immutable test listener file.
        conf_file=h.TMP/(label+"-fpm.conf");conf_file.write_text(conf);conf_file.chmod(0o644)
        base={"read_only":True,"cap_drop":["ALL"],"security_opt":["no-new-privileges:true"],"network_mode":"host","tmpfs":["/tmp:rw,noexec,nosuid,size=16m"]}
        if transient: base["tmpfs"].append("/var/lib/authgo:rw,nosuid,noexec,size=16m,uid=65532,gid=65532,mode=0700")
        obj={"services":{
            "fpm":dict(base,image=image or h.APP_IMAGE,container_name=fpm,mem_limit="128m",environment={"AUTHGO_LICENSE":lic["key"]},volumes=([vol+":/var/lib/authgo"] if not transient else [])+[str(conf_file)+":/app/php-fpm.conf:ro"]),
            "web":dict(base,image=nginx_image,container_name=nginx,mem_limit="64m",entrypoint=["/bin/sh","-c","sed 's/listen 8080;/listen 127.0.0.1:"+str(web)+";/; s/fpm:9000/127.0.0.1:"+str(fp)+"/;' /app/nginx.conf > /tmp/nginx.conf; exec nginx -c /tmp/nginx.conf -g 'daemon off;'"]),
        },"volumes":{vol:{"external":True}}}
        tmp.write_text(json.dumps(obj));h.docker("compose","-p",project,"-f",str(tmp),"up","-d","--no-build")
        services.append((tmp,project))
        def listening():
            try:
                with __import__('socket').create_connection(("127.0.0.1",web),timeout=.3):return True
            except OSError:return False
        h.wait(listening,10,"nginx未监听")
        # Avoid racing nginx against FPM's separate process initialization.
        h.wait(lambda:"ready to handle connections" in h.logs(fpm) and fpm_listening(fp),10,"FPM未就绪")
        return {"fpm":fpm,"nginx":nginx,"base":"http://127.0.0.1:"+str(web),"volume":vol,"fpm_port":fp}
    def get(s,path="/"):
        try:
            with urllib.request.urlopen(s["base"]+path,timeout=12) as r:return r.status,json.load(r)
        except urllib.error.HTTPError as e:
            raw=e.read()
            try:doc=json.loads(raw)
            except ValueError:doc={"code":"NON_JSON"}
            return e.code,doc
    def good(s,status=None):
        code,data=get(s);assert code==200,(code,data.get("code"));
        if status:assert data["status"]==status,data
        return data
    def bad(s,code):
        status,data=get(s);assert status==503 and data.get("code")==code,(status,data)
        assert h.running(s["fpm"]) and h.running(s["nginx"]),"FPM拒绝不应退出容器"
    def live(lic):
        now=time.time()
        def future(value):return value and __import__('datetime').datetime.fromisoformat(value.replace('Z','+00:00')).timestamp()>now
        return [r for r in h.activations(lic) if r["kind"]=="floating" and r["status"]=="active" and not r.get("offline_at") and future(r.get("lease_expires_at"))]
    def count(lic):return h.request("/api/v1/admin/verify-logs?license_id="+str(lic["id"])+"&page_size=100")["total"]
    lic=h.license_new(1);s=start("primary",lic)
    def valid():
        good(s,"online");assert len(live(lic))==1
        for name in (s["fpm"],s["nginx"]):
            info=h.inspect(name);assert info["Config"]["User"] not in ("","root","0")
            assert info["HostConfig"]["ReadonlyRootfs"] and "ALL" in info["HostConfig"]["CapDrop"]
            assert "no-new-privileges:true" in info["HostConfig"]["SecurityOpt"]
        assert all(not row.get("instance_session") for row in h.activations(lic)),"FPM不能发送进程session"
    h.case(1,"FPM有效授权/安全配置/一个席位",valid)
    def concurrent():
        # Fresh volume => all four workers race the very first activation.
        other=h.license_new(1);target=start("concurrent",other)
        with ThreadPoolExecutor(max_workers=16) as pool:
            replies=list(pool.map(lambda _:good(target),range(24)))
        assert len({r["pid"] for r in replies})>=2,"没有覆盖多个FPM worker"
        h.wait(lambda:count(other)>=1,5,"缺少验证日志")
        time.sleep(.3)
        assert count(other)==1,"缓存锁没有合并并发联网请求"
        assert len(live(other))==1
    h.case(2,"FPM多worker并发/仅一次联网/无INSTANCE_REPLACED",concurrent)
    def idle():
        time.sleep(11);assert not live(lic),"空闲租约未释放容量"
        good(s,"online");assert len(live(lic))==1
        time.sleep(11);assert not live(lic)
        competitor=start("competitor",lic);good(competitor)
        bad(s,"FLOATING_LIMIT_REACHED")
    h.case(3,"FPM空闲租约回收/有空位重新竞争/满额拒绝",idle)
    h.patch_app(next_check_in=1)
    def revoked():
        l=h.license_new();target=start("revoked",l);good(target)
        h.request("/api/v1/admin/licenses/"+str(l["id"])+"/revoke",{},"POST");time.sleep(1.1)
        bad(target,"ACTIVATION_INVALID")
        # Encrypted cache inspector is test-only and prints booleans, not secrets.
        script='require "/app/sdk/Client.php";require "/app/authgo-build.php";$c=new AuthGo\\Client(CONFIG);$r=new ReflectionProperty($c,"state");$v=$r->getValue($c);echo json_encode(["refused"=>$v["refused"]??false,"ticket_empty"=>empty($v["ticket"])]);'
        doc=json.loads(h.docker("exec",target["fpm"],"php","-r",script));assert doc=={"refused":True,"ticket_empty":True}
    h.case(4,"FPM吊销返回503/明确原因/清缓存不退出",revoked)
    def disabled():
        l=h.license_new();target=start("disabled",l);good(target)
        v=h.request("/api/v1/admin/applications/"+str(h.state["app"]["id"])+"/versions",{"version":"1.0.0","changelog":"test"})
        h.request("/api/v1/admin/versions/"+str(v["id"]),{"disabled":True},"PATCH");time.sleep(1.1)
        bad(target,"VERSION_DISABLED");h.request("/api/v1/admin/versions/"+str(v["id"]),{"disabled":False},"PATCH")
    h.case(5,"FPM禁用版本返回503",disabled)
    outage=h.license_new();o=start("outage",outage);good(o)
    expired=h.license_new();clock=start("clock",expired,clock_image);good(clock)
    assert get(clock,"/__test/session")== (200,{"has_session":False}),"FPM实际请求体不应带instance_session"
    empty_lic=h.license_new();empty=start("empty",empty_lic)
    def outage_case():
        h.stop_api();time.sleep(1.1);good(o,"grace")
        h.docker("restart","-t","8",o["fpm"]);h.wait(lambda:h.running(o["fpm"]) and fpm_listening(o["fpm_port"]),10,"重启后的FPM未开始监听")
        good(o,"grace")
        good(clock,"grace")
        with urllib.request.urlopen(clock["base"]+"/__test/advance",timeout=5) as r:assert r.read()==b"advanced"
        bad(clock,"SDK_GRACE_EXPIRED")
    h.case(6,"FPM停服缓存继续服务/重启宽限/耗尽503",outage_case)
    h.case(7,"FPM空卷且主服务不可达返回503",lambda:bad(empty,"SDK_NETWORK_ERROR"))
    def apache():
        # Original seven FPM cases above remain unchanged; the API is stopped by case 6.
        h.restore_api();h.patch_app(next_check_in=30)
        image=h.PREFIX+"apache";h.build("examples/docker/php-apache/Dockerfile",image,config)
        other=h.license_new(1);web=h.port();vol=h.volume_new("apache")
        name=h.PREFIX+"apache";h.containers.append(name);h.SENSITIVE.add(other["key"])
        conf=(h.ROOT/"examples/docker/php-apache/apache.conf").read_text().replace("Listen 8080","Listen 127.0.0.1:"+str(web))
        conf_file=h.TMP/"apache.conf";conf_file.write_text(conf);conf_file.chmod(0o644)
        h.docker("run","-d","--name",name,"--network","host","--memory=128m","--read-only",
                 "--cap-drop","ALL","--security-opt","no-new-privileges:true",
                 "--tmpfs","/tmp:rw,noexec,nosuid,size=16m","-v",vol+":/var/lib/authgo",
                 "-v",str(conf_file)+":/app/apache.conf:ro","-e","AUTHGO_LICENSE="+other["key"],image)
        def listening():
            try:
                with __import__('socket').create_connection(("127.0.0.1",web),timeout=.3):return True
            except OSError:return False
        h.wait(listening,10,"Apache未监听")
        modules=h.docker("exec",name,"apache2","-f","/app/apache.conf","-M")
        assert "php_module" in modules and "mpm_prefork_module" in modules,"必须是真实mod_php prefork"
        info=h.inspect(name);assert info["Config"]["User"]=="65532:65532"
        assert info["HostConfig"]["ReadonlyRootfs"] and "ALL" in info["HostConfig"]["CapDrop"]
        assert "no-new-privileges:true" in info["HostConfig"]["SecurityOpt"]
        target={"base":"http://127.0.0.1:"+str(web)}
        with ThreadPoolExecutor(max_workers=16) as pool:
            replies=list(pool.map(lambda _:good(target,"online"),range(24)))
        assert len({r["pid"] for r in replies})>=2,"没有覆盖多个Apache进程"
        h.wait(lambda:count(other)>=1,5,"缺少验证日志");time.sleep(.3)
        assert count(other)==1,"Apache缓存锁没有合并并发联网请求"
        assert len(live(other))==1,"Apache必须只占一个席位"
        # instance_session is intentionally absent from admin JSON. Inspect the actual
        # database read-only, returning counts only, rather than asserting a missing key.
        inspector=h.PREFIX+"apache-db";h.containers.append(inspector)
        script='import sqlite3,json; c=sqlite3.connect("file:/data/authgo.db?mode=ro",uri=True); rows=c.execute("SELECT instance_session FROM activations WHERE license_id=?",('+str(other["id"])+',)).fetchall(); print(json.dumps({"rows":len(rows),"with_session":sum(bool(r[0]) for r in rows)}))'
        doc=json.loads(h.docker("run","--rm","--name",inspector,"--memory=64m","--network","none",
                     "--user","65532:65532","--read-only","--cap-drop","ALL",
                     "--security-opt","no-new-privileges:true","-v",h.PREFIX+"data:/data:ro",
                     "python:3.13-alpine","python","-c",script))
        assert doc["rows"]>=1 and doc["with_session"]==0,"Apache激活记录不能有instance_session"
        # Neither SDK nor embedded config is inside DocumentRoot.
        for path in ("/authgo-build.php","/sdk/Client.php"):
            assert get(target,path)[0]==404,"Apache暴露了程序配置或SDK"
        h.request("/api/v1/admin/licenses/"+str(other["id"])+"/revoke",{},"POST")
        time.sleep(5.1)  # the signed heartbeat interval; no shortened test-only schedule
        status,data=get(target)
        assert status==503 and data.get("code")=="ACTIVATION_INVALID",(status,data)
        assert h.running(name),"Apache拒绝应返回503而不能退出容器"
    h.case(8,"Apache真实mod_php/多进程200/一席位/无session/一次联网/吊销503不退出",apache)
    # Containers are always removed by the caller's named-resource cleanup.

    import importlib.util
    spec=importlib.util.spec_from_file_location("authgo_trial_cases",h.ROOT/"scripts/trial-docker-cases.py")
    trial_cases=importlib.util.module_from_spec(spec);spec.loader.exec_module(trial_cases)
    trial_cases.fpm(h,start,good,bad)
