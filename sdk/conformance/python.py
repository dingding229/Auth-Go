import sys, json, tempfile, pathlib, time, ssl

sys.path.insert(0, str(pathlib.Path(__file__).parents[1] / "python"))
import authgo

client = None
result = None
update = None
clock = [time.time()]
for line in sys.stdin:
    try:
        p = json.loads(line)
        op = p["op"]
        out = {"code": "OK"}
        if op == "init":
            clock[0] = p.get("time", time.time())
            client = authgo.Client(
                p["config"],
                fingerprint=None if p.get("automatic") else p.get("fingerprint", "a" * 64),
                cache_dir=p.get("cache_dir") or tempfile.mkdtemp(),
                version="" if p.get("unversioned") else p.get("version", "1.0.0"),
                clock=lambda: clock[0],
            )
            out["status"] = "ready"
        elif op == "clock":
            clock[0] += p["seconds"]
        elif op == "guard_check":
            result=client._guard_check(p.get("key", ""));out["status"]=result.status
        elif op == "trial_info": out["is_trial"]=result.is_trial
        elif op in ["check", "activate", "verify", "heartbeat"]:
            result = (
                getattr(client, op)(p["key"])
                if op in ["check", "activate"]
                else getattr(client, op)()
            )
            out["status"] = result.status
        elif op == "release_seat": client.release_seat()
        elif op == "entitlement": out.update(maintenance_until=result.maintenance_until, latest_entitled_version=result.latest_entitled_version)
        elif op == "validate": client.validate(result.ticket())
        elif op == "identity": out["fingerprint"] = client.fp
        elif op == "cache_warning": out["cache_warning"] = bool(result.cache_warning)
        elif op == "deactivate":
            client.deactivate()
        elif op == "announcements":
            out["count"] = len(client.announcements())
        elif op == "check_update":
            update = client.check_update(p.get("version", "1.0.0"))
            out.update(
                available=update["available"],
                version=update.get("version", ""),
                docker_image=update.get("docker_image", ""),
                docker_pull=update.get("docker_pull", ""),
            )
        else:
            raise Exception("unsupported operation")
    except authgo.Error as e:
        if e.cause is not None:
            print(
                type(e.cause).__name__ + ": " + str(e.cause),
                file=sys.stderr,
                flush=True,
            )
        out = {"code": e.code}
        if e.latest_version: out["latest_version"] = e.latest_version
        if e.code == "MAINTENANCE_EXPIRED": out["latest_entitled_version"] = e.latest_entitled_version
    except Exception as e:
        out = {"code": "RUNNER_ERROR", "detail": type(e).__name__}
    print(json.dumps(out), flush=True)
