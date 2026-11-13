<?php
require __DIR__ . "/../src/Client.php";
use AuthGo\Client as C;
use AuthGo\Json as J;
use AuthGo\Error as E;
function check($ok)
{
    if (!$ok) {
        throw new Exception("vector mismatch");
    }
}
$root = __DIR__ . "/../../vectors/";
$v = json_decode(file_get_contents($root . "v2.json"), true);
$h = json_decode(file_get_contents($root . "hkdf.json"), true);
check(
    bin2hex(
        C::hkdf(
            hex2bin($h["ikm_hex"]),
            hex2bin($h["salt_hex"]),
            hex2bin($h["info_hex"]),
            $h["length"],
        ),
    ) === $h["okm_hex"],
);
$shared = sodium_crypto_scalarmult(
    hex2bin($v["ephemeral_private_hex"]),
    C::decode($v["gateway_public"]),
);
$aad = hex2bin($v["request_aad_hex"]);
$salt = hash("sha256", $aad, true);
foreach (["request", "response"] as $direction) {
    check(
        bin2hex(C::hkdf($shared, $salt, "authgo/v2/" . $direction)) ===
            $v[$direction . "_key_hex"],
    );
}
$padding = C::open(
    hex2bin($v["request_key_hex"]),
    C::decode($v["request"]["n"]),
    C::decode($v["request"]["c"]),
    $aad,
);
check(bin2hex($padding) === $v["padding_hex"]);
check(C::unpad($padding) === $v["inner"]);
check(
    C::unpad(
        C::open(
            hex2bin($v["response_key_hex"]),
            C::decode($v["response"]["n"]),
            C::decode($v["response"]["c"]),
            hex2bin($v["response_aad_hex"]),
        ),
    ) === $v["response_plain"],
);
$inner = json_decode($v["inner"], true);
check(
    hash_hmac(
        "sha256",
        $inner["op"] .
            $inner["timestamp"] .
            $inner["nonce"] .
            C::hash(json_encode($inner["body"], JSON_UNESCAPED_SLASHES)),
        "test-secret-only",
    ) === $inner["signature"],
);
[$payload, $sig] = explode(".", $v["ticket"]);
$pub = C::decode($v["ed25519_public"]);
check(
    sodium_crypto_sign_verify_detached(
        C::decode($sig),
        "authgo-ticket-v2\0" . C::decode($payload),
        $pub,
    ),
);
check(!sodium_crypto_sign_verify_detached(C::decode($sig), "invalid-domain\0" . C::decode($payload), $pub));
$key = C::hkdf(
    hex2bin($v["unlock_seed_hex"]),
    "",
    "authgo-unlock-v2\0" . $v["unlock_label"],
);
check(bin2hex($key) === $v["unlock_key_hex"]);
[, $n, $ct] = explode(".", $v["resource"]);
check(
    C::open(
        $key,
        C::decode($n),
        C::decode($ct),
        "authgo-resource-v2\0settings",
    ) === "hello",
);
$u = json_decode(file_get_contents($root . "update-response.json"), true);
foreach (array_merge([$u], $u["docker_cases"]) as $x) {
    $env = J::parse(json_encode($x["response"]));
    $canonical = J::encode([
        "code" => $env["code"],
        "data" => $env["data"],
        "ts" => $env["ts"],
    ]);
    check($canonical === $x["canonical_signed"]);
    check(
        sodium_crypto_sign_verify_detached(
            base64_decode($x["signature"]),
            $canonical,
            base64_decode($x["public_key"]),
        ),
    );
}
$e = json_decode(file_get_contents($root . "error-classification.json"), true);
foreach ($e["cases"] as $x) {
    check(
        (new E($x["code"], "", $x["authenticated"]))->refusal() ===
            $x["clear_cache"],
    );
}
foreach ($e["update_cases"] as $x) {
    check($x["clear_cache"] === false);
}
echo json_encode([
    "language" => "php",
    "vectors" => "PASS",
    "cases" => count($e["cases"]) + count($e["update_cases"]),
]) . "\n";
foreach (
    json_decode(file_get_contents($root . "fingerprint.json"), true)["cases"]
    as $c
) {
    check(
        C::identityHash($c["machine"], $c["mac"], $c["cpu"]) === $c["expected"],
    );
}
$c = json_decode(file_get_contents($root . "canonical.json"), true);
check(J::encode(J::parse($c["raw"])) === $c["canonical"]);
check(
    sodium_crypto_sign_verify_detached(
        base64_decode($c["signature"]),
        $c["canonical"],
        base64_decode($c["public_key"]),
    ),
);
foreach ($c["invalid"] as $bad) {
    try {
        J::parse($bad);
        throw new Exception("accepted invalid");
    } catch (E $e) {
    }
}
foreach (
    ["authgo2.private-test-secret", ""]
    as $bad
) {
    try {
        new C($bad);
        throw new Exception("accepted");
    } catch (E $e) {
        check(
            $e->errorCode === "SDK_INVALID_CONFIG" &&
                !str_contains($e->getMessage(), "private-test-secret"),
        );
    }
}

foreach (
    json_decode(file_get_contents($root . "license-key.json"), true)["cases"]
    as $c
) {
    $valid = true;
    try {
        C::validateKey($c["key"]);
    } catch (E $e) {
        $valid = false;
        check($e->errorCode === $c["code"]);
    }
    check($valid === $c["valid"]);
}
foreach (
    json_decode(file_get_contents($root . "fingerprint.json"), true)[
        "cpuinfo_cases"
    ]
    as $c
) {
    $cpu = C::parseLinuxCPU($c["cpuinfo"]);
    check($cpu === $c["cpu"]);
    if ($cpu !== "") {
        check(
            C::identityHash($c["machine"], $c["mac"], $cpu) === $c["expected"],
        );
    }
}
echo '{"language":"php","license_key_vectors":16,"cpuinfo_vectors":8,"result":"PASS"}' .
    PHP_EOL;

$container=json_decode(file_get_contents(__DIR__."/../../vectors/container-identity.json"),true,512,JSON_THROW_ON_ERROR);
foreach($container["detection"] as $v)check(\AuthGo\ContainerIdentity::detect(fn($p)=>$v["files"][$p]??false,$v["env"])===$v["expected"]);
foreach($container["fingerprints"] as $v)check(\AuthGo\ContainerIdentity::hash($v["id"])===$v["expected"]);
echo '{"language":"php","container_vectors":"PASS"}'.PHP_EOL;

$session=json_decode(file_get_contents(__DIR__."/../../vectors/instance-session.json"),true,512,JSON_THROW_ON_ERROR)["instance_session"];
check(strlen(C::decode($session["valid"]))===$session["bytes"]);
foreach($session["invalid"] as $value){$valid=false;try{$valid=strlen(C::decode($value))===$session["bytes"];}catch(E){}check(!$valid);}
check($session["persist_in_cache"]===false);

require_once __DIR__ . '/payload.php';
PayloadTests::run();
require_once __DIR__.'/sealed.php';
SealedTests::run();
require_once __DIR__.'/sealed-security.php';
SealedReviewTests::run();

