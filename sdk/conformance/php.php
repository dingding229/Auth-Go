<?php
require __DIR__ . "/../php/src/Client.php";
use AuthGo\Client;
use AuthGo\Error;
use AuthGo\Json;
$client = null;
$result = null;
$update = null;
$clock = time();
while (($line = fgets(STDIN)) !== false) {
    $out = ["code" => "OK"];
    try {
        $p = json_decode($line, true, 512, JSON_THROW_ON_ERROR);
        switch ($p["op"]) {
            case "init":
                $cert = null;
                $clock = $p["time"] ?? time();
                $client = new Client($p["config"], [
                    "fingerprint" => ($p["automatic"]??false)?null:($p["fingerprint"]??str_repeat("a",64)),
                    "cache_dir" =>
                        $p["cache_dir"] ??
                        sys_get_temp_dir() .
                            "/authgo-" .
                            bin2hex(random_bytes(8)),
                    "version" => ($p["unversioned"]??false)?"":($p["version"]??"1.0.0"),
                    "clock" => function () use (&$clock) {
                        return $clock;
                    },
                    "transport" => function (
                        $url,
                        $body,
                        $headers,
                        $timeout,
                        $limit,
                    ) use ($cert) {
                        return Client::http(
                            $url,
                            $body,
                            $headers,
                            $timeout,
                            $limit,
                            $cert,
                        );
                    },
                ]);
                $out["status"] = "ready";
                break;
            case "clock":
                $clock += $p["seconds"];
                break;
            case "check":
            case "activate":
                $op = $p["op"];
                $result = $client->$op($p["key"]);
                $out["status"] = $result->status;
                break;
            case "verify":
            case "heartbeat":
                $op = $p["op"];
                $result = $client->$op();
                $out["status"] = $result->status;
                break;
            case "guard_check":$result=$client->check(($p["key"]??"")!==""?$p["key"]:$client->guardTrialKey());$out["status"]=$result->status;break;
            case "trial_info":$out["is_trial"]=$result->isTrial;break;
            case "release_seat": $client->releaseSeat();break;
            case "entitlement": $out["maintenance_until"]=$result->maintenanceUntil;$out["latest_entitled_version"]=$result->latestEntitledVersion;break;
            case "validate": $client->validate($result->ticket());break;
            case "identity": $field=new \ReflectionProperty($client,"fp");$out["fingerprint"]=$field->getValue($client);break;
            case "cache_warning": $out["cache_warning"]=$result->cacheWarning!==null;break;
            case "deactivate":
                $client->deactivate();
                break;
            case "announcements":
                $out["count"] = count($client->announcements());
                break;
            case "check_update":
                $update = $client->checkUpdate($p["version"] ?? "1.0.0");
                $out["available"] = $update["available"];
                $out["version"] = $update["version"] ?? "";
                $out["docker_image"] = $update["docker_image"] ?? ""; $out["docker_pull"] = $update["docker_pull"] ?? "";
                break;
            default:
                throw new \Exception("unsupported");
        }
    } catch (Error $e) {
        $out = ["code" => $e->errorCode];
        if($e->latestVersion!=="")$out["latest_version"]=$e->latestVersion;
        if($e->errorCode==="MAINTENANCE_EXPIRED")$out["latest_entitled_version"]=$e->latestEntitledVersion;
    } catch (\Throwable $e) {
        $out = ["code" => "RUNNER_ERROR", "detail" => get_class($e)];
    }
    echo json_encode($out) . "\n";
    fflush(STDOUT);
}
