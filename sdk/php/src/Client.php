<?php
declare(strict_types=1);
namespace AuthGo;

/** Internal SAPI classification; only CLI owns a persistent process session. */
function isPersistentRuntime(string $sapi = PHP_SAPI): bool
{
    return $sapi === "cli";
}

final class Error extends \RuntimeException
{
    public string $errorCode;
    public bool $authenticated;
    public string $latestVersion = "";
    public string $latestEntitledVersion = "";
    public function __construct(
        string $code,
        string $message = "",
        bool $authenticated = false,
        ?\Throwable $cause = null,
    ) {
        $this->errorCode = $code;
        $this->authenticated = $authenticated;
        parent::__construct(
            $code . ($message !== "" ? ": " . $message : ""),
            0,
            $cause,
        );
    }
    public function refusal(): bool
    {
        return $this->authenticated &&
            !in_array($this->errorCode, Client::TEMPORARY, true);
    }
}
final class JsonNumber
{
    public function __construct(public string $raw) {}
}
final class Json
{
    public static function parse(string $s): mixed
    {
        $i = 0;
        $len = strlen($s);
        $ws = function () use (&$i, $s, $len) {
            while ($i < $len && str_contains(" \t\r\n", $s[$i])) {
                $i++;
            }
        };
        $read = function (int $depth = 0) use (
            &$read,
            &$i,
            $s,
            $len,
            $ws,
        ): mixed {
            if ($depth > 100) {
                throw new \Exception("depth");
            }
            $ws();
            $c = $s[$i] ?? "";
            if ($c === '"') {
                $start = $i++;
                while ($i < $len) {
                    if ($s[$i++] === "\\") {
                        $i++;
                        continue;
                    }
                    if ($s[$i - 1] === '"') {
                        return json_decode(
                            substr($s, $start, $i - $start),
                            true,
                            512,
                            JSON_THROW_ON_ERROR,
                        );
                    }
                }
                throw new \Exception("string");
            }
            if ($c === "{" || $c === "[") {
                $obj = $c === "{";
                $out = $obj ? new \ArrayObject() : [];
                $close = $obj ? "}" : "]";
                $i++;
                $ws();
                if (($s[$i] ?? "") === $close) {
                    $i++;
                    return $out;
                }
                while (true) {
                    if ($obj) {
                        $ws();
                        if (($s[$i] ?? "") !== '"') {
                            throw new \Exception("key");
                        }
                        $key = $read($depth + 1);
                        $ws();
                        if (
                            ($s[$i++] ?? "") !== ":" ||
                            $out->offsetExists($key)
                        ) {
                            throw new \Exception("duplicate");
                        }
                        $out[$key] = $read($depth + 1);
                    } else {
                        $out[] = $read($depth + 1);
                    }
                    $ws();
                    if (($s[$i] ?? "") === $close) {
                        $i++;
                        return $out;
                    }
                    if (($s[$i++] ?? "") !== ",") {
                        throw new \Exception("comma");
                    }
                }
            }
            if (
                !preg_match(
                    "/\G(true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/A",
                    $s,
                    $m,
                    0,
                    $i,
                )
            ) {
                throw new \Exception("value");
            }
            $i += strlen($m[0]);
            return match ($m[0]) {
                "true" => true,
                "false" => false,
                "null" => null,
                default => new JsonNumber($m[0]),
            };
        };
        try {
            $out = $read();
            $ws();
            if ($i !== $len) {
                throw new \Exception("trailing");
            }
            return $out;
        } catch (\Throwable) {
            throw new Error("SDK_RESPONSE_INVALID", "JSON无效");
        }
    }
    public static function encode(mixed $v): string
    {
        if ($v instanceof JsonNumber) {
            return $v->raw;
        }
        if ($v instanceof \ArrayObject) {
            $a = $v->getArrayCopy();
            ksort($a, SORT_STRING);
            $p = [];
            foreach ($a as $k => $x) {
                $p[] = self::encode((string) $k) . ":" . self::encode($x);
            }
            return "{" . implode(",", $p) . "}";
        }
        if (is_array($v)) {
            if (array_is_list($v)) {
                return "[" .
                    implode(",", array_map([self::class, "encode"], $v)) .
                    "]";
            }
            return self::encode(new \ArrayObject($v));
        }
        return str_replace(
            ["\\u003C", "\\u003E"],
            ["\\u003c", "\\u003e"],
            json_encode(
                $v,
                JSON_THROW_ON_ERROR |
                    JSON_UNESCAPED_UNICODE |
                    JSON_UNESCAPED_SLASHES |
                    JSON_HEX_TAG |
                    JSON_HEX_AMP,
            ),
        );
    }
    public static function num(mixed $n): float|int
    {
        return $n instanceof JsonNumber
            ? (float) $n->raw
            : (is_numeric($n)
                ? 0 + $n
                : 0);
    }
}
final class Result
{
    public bool $offline;
    public mixed $features;
    public string $availability;
    public ?string $cacheWarning;
    public float $heartbeatInterval;
    public bool $isTrial;
    public ?string $maintenanceUntil;
    public string $latestEntitledVersion;
    public function __construct(
        private Client $client,
        public mixed $data,
        private string $proof = "",
        private string $seed = "",
        public string $status = "online",
        private float $end = INF,
        public string $reason = "",
    ) {
        $this->cacheWarning=$client->cacheWarning;
        $this->heartbeatInterval=$client->guardHeartbeat($data);
        $this->isTrial=(bool)($data["is_trial"]??false);
        $this->availability = $status;
        $this->offline = $status !== "online";
        $this->maintenanceUntil=$data["maintenance_until"]??null;
        $this->latestEntitledVersion=$data["latest_entitled_version"]??"";
        $this->features = $data["features"] ?? new \ArrayObject();
    }
    /** @internal */
    public function snapshot(): self {
        $r=clone $this; $r->data=Json::parse(Json::encode($this->data));
        $r->features=$r->data["features"]??new \ArrayObject(); return $r;
    }
    /** @internal */
    public function usableUntil(): float {return $this->end;}
    public function ticket(): string
    {
        return $this->proof;
    }
}
final class ContainerIdentity {
    public static array $replaced = [], $memory = [];
    private static string $session = "";
    private static int $pid = 0;
    public static function session(): string {if(self::$pid!==getmypid()){self::$pid=getmypid();self::$session=Client::b64(random_bytes(16));}return self::$session;}
    public static function detect(?callable $read=null, ?array $env=null): bool {
        $read ??= fn($p)=>@file_get_contents($p);$env ??= getenv();
        if(in_array($env["AUTHGO_CONTAINER"]??"",["0","1"],true))return $env["AUTHGO_CONTAINER"]==="1";
        foreach(["/.dockerenv","/run/.containerenv"] as $p)if($read($p)!==false)return true;
        $raw=$read("/proc/1/cgroup");foreach(["docker","containerd","kubepods","libpod"] as $x)if(is_string($raw)&&str_contains($raw,$x))return true;return false;
    }
    public static function hash(string $id): string {return hash("sha256","authgo/instance/v1\0".$id);}
    public static function load(string $dir): array {
        try {
            if($dir==="")throw new \Exception();
            if(!is_dir($dir)&&!@mkdir($dir,0700,true)&&!is_dir($dir))throw new \Exception();
            $target=$dir."/instance-id";
            if(!file_exists($target)){
                $temp=$dir."/.instance-".Client::b64(random_bytes(16));$f=@fopen($temp,"x+b");if(!$f)throw new \Exception();
                try{
                    try{chmod($temp,0600);$value=bin2hex(random_bytes(32));if(fwrite($f,$value)!==64||!fflush($f))throw new \Exception();if(function_exists("fsync"))fsync($f);}finally{fclose($f);}
                    if(!@link($temp,$target)&&!file_exists($target))throw new \Exception();
                }finally{@unlink($temp);}
            }
            $raw=@file_get_contents($target);if(is_link($target)||!is_file($target)||(fileperms($target)&0777)!==0600||!is_string($raw)||!preg_match('/^[0-9a-f]{64}$/D',$raw))throw new \Exception();
            return [$raw,false];
        }catch(\Throwable){return [self::$memory[getmypid()."\0".$dir]??=bin2hex(random_bytes(32)),true];}
    }
}
final class Client
{
    public const TEMPORARY = [
        "INTERNAL_ERROR",
        "RATE_LIMITED",
        "REPLAY_DETECTED",
        "TIMESTAMP_INVALID",
        "SIGNATURE_INVALID",
        "INVALID_REQUEST",
        "PAYLOAD_INVALID",
    ];
    private mixed $config;
    private string $public;
    private string $gateway;
    private string $endpoint;
    private string $fp;
    private string $file;
    private string $aad;
    private string $cacheKey;
    private \ArrayObject $state;
    private string $onlineTicket = "", $offlineTicket = "";
    private float $offlineUntil = 0;
    private bool $memoryCache = false;
    private bool $payloadReady = false, $payloadNoCache = false;
    private PayloadCache $payloadCache;
    private int $guardLockDepth = 0;
    public ?string $cacheWarning = null;
    private float $onlineUntil = 0;
    private float $requestBudget = 10;
    public function __construct(string $config, private array $options = [])
    {
        try {
            if (
                strlen($config) > 32768 ||
                !str_starts_with($config, "authgo2.")
            ) {
                throw new \Exception();
            }
            $c = Json::parse(self::decode(substr($config, 8)));
            if (
                !($c instanceof \ArrayObject) ||
                array_diff(array_keys($c->getArrayCopy()), [
                    "url",
                    "app_key",
                    "app_secret",
                    "public_key",
                    "gateway_key",
                                    ])
            ) {
                throw new \Exception();
            }
            foreach (
                ["url", "app_key", "app_secret", "public_key", "gateway_key"]
                as $k
            ) {
                if (!isset($c[$k]) || !is_string($c[$k]) || $c[$k] === "") {
                    throw new \Exception();
                }
            }
            self::url($c["url"], false);
            $this->public = base64_decode($c["public_key"], true);
            $this->gateway = self::decode($c["gateway_key"]);
            if (
                strlen($this->public) !== 32 ||
                base64_encode($this->public) !== $c["public_key"] ||
                strlen($this->gateway) !== 32
            ) {
                throw new \Exception();
            }
            $this->config = $c;
            $this->endpoint = rtrim($c["url"], "/");
            if (!str_ends_with($this->endpoint, "/api/v1/client")) {
                $this->endpoint .= "/api/v1/client";
            }
        } catch (\Throwable) {
            throw new Error("SDK_INVALID_CONFIG", "请在后台重新复制接入配置");
        }
        $container=ContainerIdentity::detect();
        $home = getenv("HOME") ?: getenv("USERPROFILE");
        $root =
            PHP_OS_FAMILY === "Windows"
                ? (getenv("LOCALAPPDATA") ?:
                $home . "/AppData/Local")
                : (PHP_OS_FAMILY === "Darwin"
                    ? $home . "/Library/Caches"
                    : (getenv("XDG_CACHE_HOME") ?:
                    $home . "/.cache"));
        $envDir=getenv("AUTHGO_CACHE_DIR");
        $envId=getenv("AUTHGO_INSTANCE_ID");
        $dir=$options["cache_dir"]??(($envDir!==false&&$envDir!=="")?$envDir:($container?"/var/lib/authgo":$root."/authgo/".self::hash($c["app_key"])));
        $this->memoryCache=$dir==="";
        if(isset($options["fingerprint"]))$this->fp=strtolower($options["fingerprint"]);
        elseif($envId!==false&&$envId!=="")$this->fp=ContainerIdentity::hash($envId);
        elseif($container){[$id,$memory]=ContainerIdentity::load($dir);$this->fp=ContainerIdentity::hash($id);$this->memoryCache=$memory;if($memory)$this->cacheWarning="此实例重启后是新实例，没有断连宽限";}
        else $this->fp=self::fingerprint();
        if(!preg_match('/^[a-f0-9]{64}$/D',$this->fp))throw new Error("SDK_INVALID_CONFIG");
        $this->aad =
            "authgo/php/cache/v2\0" .
            $this->endpoint .
            "\0" .
            $c["app_key"] .
            "\0" .
            $this->fp;
        $this->cacheKey = self::hkdf(
            $c["app_secret"],
            hash("sha256", $this->aad, true),
            "authgo/multi/cache/key",
        );
        $this->payloadCache = new PayloadCache($dir,$this->endpoint,$c["app_key"],$this->fp,$this->public);
        $this->file = $dir . "/" . self::hash($this->aad) . ".cache";
        $this->state = new \ArrayObject();
        $this->guardReload();
    }
    /** @internal Reload only while holding the FPM guard cache lock. */
    public function guardReload(): void
    {
        $this->state = new \ArrayObject();
        clearstatcache(true,$this->file);
        try {
            if (
                !$this->memoryCache && is_file($this->file) &&
                filesize($this->file) <= 16 * 1024 * 1024
            ) {
                $raw = file_get_contents($this->file);
                $s = Json::parse(
                    self::open(
                        $this->cacheKey,
                        substr($raw, 0, 12),
                        substr($raw, 12),
                        $this->aad,
                    ),
                );
                if ($s instanceof \ArrayObject) {
                    $this->state = $s;
                }
            }
        } catch (\Throwable) {
        }
    }
    public function now(): float
    {
        return isset($this->options["clock"])
            ? $this->options["clock"]()
            : microtime(true);
    }
    public static function hash(string $b): string
    {
        return hash("sha256", $b);
    }
    public static function b64(string $b): string
    {
        return rtrim(strtr(base64_encode($b), "+/", "-_"), "=");
    }
    public static function decode(string $s): string
    {
        $b = base64_decode(strtr($s, "-_", "+/"), true);
        if ($b === false || self::b64($b) !== $s) {
            throw new Error("SDK_RESPONSE_INVALID");
        }
        return $b;
    }
    public static function hkdf(
        string $ikm,
        string $salt,
        string $info,
        int $len = 32,
    ): string {
        return hash_hkdf("sha256", $ikm, $len, $info, $salt);
    }
    public static function seal(
        string $k,
        string $n,
        string $b,
        string $aad,
    ): string {
        if (strlen($n) !== 12) {
            throw new Error("SDK_RESPONSE_INVALID");
        }
        $tag = "";
        $ct = openssl_encrypt(
            $b,
            "aes-256-gcm",
            $k,
            OPENSSL_RAW_DATA,
            $n,
            $tag,
            $aad,
            16,
        );
        if ($ct === false) {
            throw new Error("SDK_RESPONSE_INVALID");
        }
        return $ct . $tag;
    }
    public static function open(
        string $k,
        string $n,
        string $b,
        string $aad,
    ): string {
        if (strlen($k) !== 32 || strlen($n) !== 12 || strlen($b) < 16) {
            throw new Error("SDK_RESPONSE_INVALID");
        }
        $p = openssl_decrypt(
            substr($b, 0, -16),
            "aes-256-gcm",
            $k,
            OPENSSL_RAW_DATA,
            $n,
            substr($b, -16),
            $aad,
        );
        if ($p === false) {
            throw new Error("SDK_RESPONSE_INVALID");
        }
        return $p;
    }
    public static function pad(string $b): string
    {
        $n = max(4096, (int) ceil((strlen($b) + 4) / 512) * 512);
        return pack("N", strlen($b)) . $b . random_bytes($n - 4 - strlen($b));
    }
    public static function unpad(string $b): string
    {
        if (strlen($b) < 4) {
            throw new Error("SDK_RESPONSE_INVALID");
        }
        $n = unpack("N", substr($b, 0, 4))[1];
        if (
            !$n ||
            $n + 4 > strlen($b) ||
            strlen($b) !== max(4096, (int) ceil(($n + 4) / 512) * 512)
        ) {
            throw new Error("SDK_RESPONSE_INVALID");
        }
        return substr($b, 4, $n);
    }
    private static function url(string $url, bool $https): void
    {
        $u = parse_url($url);
        if (
            !$u ||
            !isset($u["host"]) ||
            isset($u["user"]) ||
            isset($u["pass"]) ||
            (!$https && isset($u["query"])) ||
            isset($u["fragment"]) ||
            (!$https && str_contains($u["path"] ?? "", "%")) ||
            preg_match('#/(\.|\.\.)(/|$)#', $u["path"] ?? "") ||
            (($u["scheme"] ?? "") !== "https" &&
                ($https ||
                    ($u["scheme"] ?? "") !== "http" ||
                    !in_array(
                        $u["host"],
                        ["localhost", "127.0.0.1", "[::1]"],
                        true,
                    )))
        ) {
            throw new Error("SDK_INVALID_CONFIG");
        }
    }
    public static function identityHash(
        string $machine,
        string $mac,
        string $cpu,
    ): string {
        $machine = strtolower(trim($machine));
        $mac = strtolower(str_replace("-", ":", trim($mac)));
        $cpu = strtolower(preg_replace("/\s+/u", " ", trim($cpu)));
        if (
            !$machine ||
            !$cpu ||
            !preg_match(
                '/^[a-f0-9]{2}(:[a-f0-9]{2}){5}(:[a-f0-9]{2}){0,2}$/D',
                $mac,
            )
        ) {
            throw new Error("SDK_FINGERPRINT_UNAVAILABLE");
        }
        return self::hash(
            "authgo/fingerprint/v1\0" . $machine . "\0" . $mac . "\0" . $cpu,
        );
    }
    private static function command(array $args): string
    {
        $descriptors = [1 => ["pipe", "w"], 2 => ["pipe", "w"]];
        $p = proc_open($args, $descriptors, $pipes);
        if (!is_resource($p)) {
            throw new Error("SDK_FINGERPRINT_UNAVAILABLE");
        }
        stream_set_blocking($pipes[1], false);
        $out = "";
        $start = microtime(true);
        while (proc_get_status($p)["running"]) {
            if (microtime(true) - $start > 3) {
                proc_terminate($p);
                throw new Error("SDK_FINGERPRINT_UNAVAILABLE");
            }
            $out .= stream_get_contents($pipes[1]);
            usleep(10000);
        }
        $out .= stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($p);
        return trim($out);
    }
    public static function validateKey(string $key): void
    {
        $alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
        $p = explode("-", $key);
        if (count($p) !== 5 || strlen($p[0]) < 1 || strlen($p[0]) > 16) {
            throw new Error("INVALID_LICENSE_KEY");
        }
        foreach ($p as $i => $v) {
            if ($i > 0 && strlen($v) !== 5) {
                throw new Error("INVALID_LICENSE_KEY");
            }
            foreach (str_split($v) as $c) {
                if (strpos($alphabet, $c) === false) {
                    throw new Error("INVALID_LICENSE_KEY");
                }
            }
        }
        $check = strlen($p[0]) % 32;
        foreach (
            str_split($p[0] . $p[1] . $p[2] . $p[3] . substr($p[4], 0, 4))
            as $c
        ) {
            $check = ($check * 17 + strpos($alphabet, $c)) % 32;
        }
        if ($p[4][4] !== $alphabet[$check]) {
            throw new Error("INVALID_LICENSE_KEY");
        }
    }
    public static function parseLinuxCPU(string $raw): string
    {
        $lines = explode("\n", $raw);
        foreach ($lines as $line) {
            $f = explode(":", $line, 2);
            if (
                count($f) === 2 &&
                in_array(
                    trim($f[0]),
                    ["model name", "Hardware", "cpu model"],
                    true,
                ) &&
                trim($f[1]) !== ""
            ) {
                return trim($f[1]);
            }
        }
        $implementer = $part = $uarch = "";
        $seen = $done = false;
        foreach ($lines as $line) {
            if (trim($line) === "" && $seen) {
                $done = true;
            }
            $f = explode(":", $line, 2);
            if (count($f) !== 2) {
                continue;
            }
            $k = trim($f[0]);
            $v = trim($f[1]);
            if ($k === "uarch" && $uarch === "") {
                $uarch = $v;
            }
            if (!$done) {
                if ($k === "CPU implementer") {
                    $seen = true;
                    if ($implementer === "") {
                        $implementer = strtolower(
                            preg_replace("/\s+/", "", $v),
                        );
                    }
                }
                if ($k === "CPU part") {
                    $seen = true;
                    if ($part === "") {
                        $part = strtolower(preg_replace("/\s+/", "", $v));
                    }
                }
            }
        }
        return $implementer !== "" && $part !== ""
            ? "arm:" . $implementer . ":" . $part
            : $uarch;
    }

    public static function fingerprint(): string
    {
        try {
            $items = [];
            $preferred = "";
            if (PHP_OS_FAMILY === "Linux") {
                $machine =
                    @file_get_contents("/etc/machine-id") ?:
                    file_get_contents("/var/lib/dbus/machine-id");
                $cpu = self::parseLinuxCPU(file_get_contents("/proc/cpuinfo"));
                foreach (
                    explode("\n", file_get_contents("/proc/net/route"))
                    as $line
                ) {
                    $f = preg_split("/\s+/", trim($line));
                    if (($f[1] ?? "") === "00000000") {
                        $preferred = $f[0];
                        break;
                    }
                }
                foreach (glob("/sys/class/net/*") as $p) {
                    if (hexdec(trim(file_get_contents($p . "/flags"))) & 8) {
                        continue;
                    }
                    $mac = trim(file_get_contents($p . "/address"));
                    if (trim(str_replace(":", "", $mac), "0") === "") {
                        continue;
                    }
                    $items[] = [
                        "index" => (int) file_get_contents($p . "/ifindex"),
                        "name" => basename($p),
                        "mac" => $mac,
                        "up" =>
                            (bool) (hexdec(
                                trim(file_get_contents($p . "/flags")),
                            ) & 1),
                    ];
                }
            } elseif (PHP_OS_FAMILY === "Darwin") {
                $raw = self::command([
                    "/usr/sbin/ioreg",
                    "-rd1",
                    "-c",
                    "IOPlatformExpertDevice",
                ]);
                preg_match('/"IOPlatformUUID"\s*=\s*"([^"]+)"/', $raw, $m);
                $machine = $m[1];
                $cpu = self::command([
                    "/usr/sbin/sysctl",
                    "-n",
                    "machdep.cpu.brand_string",
                ]);
                if (!$cpu) {
                    $cpu = self::command([
                        "/usr/sbin/sysctl",
                        "-n",
                        "hw.model",
                    ]);
                }
                $raw = self::command(["/sbin/route", "-n", "get", "default"]);
                preg_match("/interface:\s*(\S+)/", $raw, $m);
                $preferred = $m[1] ?? "";
                $raw = self::command(["/sbin/ifconfig", "-a", "-v"]);
                $index = 0;
                foreach (preg_split('/\n(?=\S)/', $raw) as $block) {
                    preg_match("/index\s+(\d+)/", $block, $ni);
                    $index = (int) ($ni[1] ?? 0);
                    preg_match("/^(\S+):/", $block, $name);
                    if (preg_match("/ether\s+([a-f0-9:]+)/", $block, $mac)) {
                        $items[] = [
                            "index" => $index,
                            "name" => $name[1],
                            "mac" => $mac[1],
                            "up" => str_contains(
                                explode("\n", $block)[0],
                                "UP",
                            ),
                        ];
                    }
                }
            } elseif (PHP_OS_FAMILY === "Windows") {
                $root = getenv("SystemRoot") ?: "C:\\Windows";
                $reg = $root . '\\System32\\reg.exe';
                $raw = self::command([
                    $reg,
                    "query",
                    "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
                    "/v",
                    "MachineGuid",
                    "/reg:64",
                ]);
                preg_match("/MachineGuid\s+REG_SZ\s+(.+)/", $raw, $m);
                $machine = $m[1];
                $raw = self::command([
                    $reg,
                    "query",
                    'HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0',
                    "/v",
                    "ProcessorNameString",
                ]);
                preg_match("/ProcessorNameString\s+REG_SZ\s+(.+)/", $raw, $m);
                $cpu = $m[1];
                $ps =
                    $root .
                    '\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
                $preferred = self::command([
                    $ps,
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty InterfaceIndex",
                ]);
                $rows = json_decode(
                    self::command([
                        $ps,
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        "ConvertTo-Json -Compress -InputObject @(Get-NetAdapter -IncludeHidden | Select-Object ifIndex,MacAddress,Status)",
                    ]),
                    true,
                );
                foreach ($rows as $v) {
                    if ($v["MacAddress"]) {
                        $items[] = [
                            "index" => $v["ifIndex"],
                            "name" => (string) $v["ifIndex"],
                            "mac" => $v["MacAddress"],
                            "up" => $v["Status"] === "Up",
                        ];
                    }
                }
            } else {
                throw new \Exception();
            }
            usort($items, fn($a, $b) => $a["index"] <=> $b["index"]);
            $chosen = null;
            foreach ($items as $v) {
                if (
                    $v["name"] === $preferred ||
                    (string) $v["index"] === $preferred
                ) {
                    $chosen = $v;
                    break;
                }
            }
            if (!$chosen) {
                foreach ($items as $v) {
                    if ($v["up"]) {
                        $chosen = $v;
                        break;
                    }
                }
            }
            $chosen ??= $items[0];
            return self::identityHash($machine, $chosen["mac"], $cpu);
        } catch (\Throwable) {
            throw new Error(
                "SDK_FINGERPRINT_UNAVAILABLE",
                "请提供 fingerprint 覆盖",
            );
        }
    }
    private function save(): void
    {
        if($this->memoryCache)return;
        $dir = dirname($this->file);
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new Error("SDK_CACHE_UNAVAILABLE");
        }
        $n = random_bytes(12);
        $raw =
            $n .
            self::seal(
                $this->cacheKey,
                $n,
                Json::encode($this->state),
                $this->aad,
            );
        $tmp = $dir . "/" . self::b64(random_bytes(12)) . ".tmp";
        $f = @fopen($tmp, "x+b");
        if (!$f) {
            throw new Error("SDK_CACHE_UNAVAILABLE");
        }
        chmod($tmp, 0600);
        try {
            if (fwrite($f, $raw) !== strlen($raw) || !fflush($f)) {
                throw new Error("SDK_CACHE_UNAVAILABLE");
            }
            if (function_exists("fsync")) {
                fsync($f);
            }
        } finally {
            fclose($f);
        }
        if (!rename($tmp, $this->file)) {
            throw new Error("SDK_CACHE_UNAVAILABLE");
        }
    }
    public static function http(
        string $url,
        ?string $body = null,
        array $headers = [],
        float $timeout = 10,
        int $limit = 5242880,
        ?string $caFile = null,
    ): array {
        $lines = [];
        foreach ($headers as $k => $v) {
            $lines[] = $k . ": " . $v;
        }
        $context = stream_context_create([
            "http" => [
                "method" => $body === null ? "GET" : "POST",
                "content" => $body ?? "",
                "header" => implode("\r\n", $lines),
                "timeout" => $timeout,
                "follow_location" => 0,
                "ignore_errors" => true,
            ],
            "ssl" => array_merge(
                ["verify_peer" => true, "verify_peer_name" => true],
                $caFile ? ["cafile" => $caFile] : [],
            ),
        ]);
        $start = microtime(true);
        error_clear_last();
        $f = @fopen($url, "rb", false, $context);
        if (!$f) {
            $last = error_get_last();
            throw new Error(
                preg_match("/SSL|certificate|crypto/i", $last["message"] ?? "")
                    ? "SDK_RESPONSE_INVALID"
                    : "SDK_NETWORK_ERROR",
            );
        }
        // Classify a non-success HTTP status before reading its body, like Go.
        // In particular, an empty keep-alive 502 is not a transport timeout.
        $early = stream_get_meta_data($f)["wrapper_data"] ?? [];
        $earlyStatus = 0;
        $earlyHeaders = [];
        foreach ($early as $line) {
            if (preg_match("#^HTTP/\\S+ (\\d+)#", $line, $m)) $earlyStatus = (int)$m[1];
            elseif (str_contains($line, ":")) {[$name,$value] = explode(":",$line,2);$earlyHeaders[strtolower($name)] = trim($value);}
        }
        if ($earlyStatus !== 200 && $earlyStatus !== 206) {fclose($f);return [$earlyStatus,$earlyHeaders,""];}
        $data = "";
        while (!feof($f)) {
            $remaining = $timeout - (microtime(true) - $start);
            if ($remaining <= 0) {
                fclose($f);
                throw new Error("SDK_NETWORK_ERROR");
            }
            stream_set_timeout(
                $f,
                (int) $remaining,
                (int) (($remaining - (int) $remaining) * 1000000),
            );
            $chunk = fread($f, min(65536, $limit + 1 - strlen($data)));
            if ($chunk === false || microtime(true) - $start > $timeout) {
                fclose($f);
                throw new Error("SDK_NETWORK_ERROR");
            }
            $data .= $chunk;
            if (strlen($data) > $limit) {
                fclose($f);
                throw new Error("SDK_RESPONSE_INVALID");
            }
        }
        $meta = stream_get_meta_data($f);
        fclose($f);
        $response = $meta["wrapper_data"] ?? [];
        $status = 0;
        $hs = [];
        foreach ($response as $line) {
            if (preg_match("#^HTTP/\S+ (\d+)#", $line, $m)) {
                $status = (int) $m[1];
            } elseif (str_contains($line, ":")) {
                [$k, $v] = explode(":", $line, 2);
                $hs[strtolower($k)] = trim($v);
            }
        }
        return [$status, $hs, $data];
    }
    private function saveWarning(): void {if(!$this->memoryCache)$this->cacheWarning=null;try{$this->save();}catch(Error){$this->cacheWarning="无法保存本地缓存，重启后没有断连宽限";}}
    private function revokeCache(): void
    {
        $this->payloadReady=false;$this->clearPayloadKeys();
        $this->state["ticket"] = "";
        $this->state["seed"] = "";
        $this->state["refused"] = true;
        try {
            $this->save();
        } catch (Error) {
            if (!$this->memoryCache && is_file($this->file)) {
                @unlink($this->file);
            }
        }
    }
    private function body(): array
    {
        $body = [
            "license_key" => $this->state["key"] ?? "",
            "activation_token" => $this->state["token"] ?? "",
            "device_fingerprint" => $this->fp,
            "client_version" => $this->options["version"] ?? "",
            "hostname" => substr(gethostname() ?: "", 0, 128),
            "os" => self::osName(),
        ];
        // Request workers share a container, not a process session.
        if (isPersistentRuntime()) $body["instance_session"] = ContainerIdentity::session();
        return $body;
    }
    private function request(string $op, ?array $body = null): array
    {
        $challenge = self::b64(random_bytes(32));
        $nonce = self::b64(random_bytes(32));
        $ts = (string) (int) $this->now();
        if ($body !== null) {
            $body["challenge"] = $challenge;
        }
        $raw = $body === null ? "" : Json::encode($body);
        $sig = hash_hmac(
            "sha256",
            $op . $ts . $nonce . self::hash($raw),
            $this->config["app_secret"],
        );
        $inner = Json::encode([
            "app_key" => $this->config["app_key"],
            "op" => $op,
            "timestamp" => $ts,
            "nonce" => $nonce,
            "signature" => $sig,
            "body" => $body,
        ]);
        $private = random_bytes(32);
        $ep = self::b64(sodium_crypto_scalarmult_base($private));
        $shared = "";
        try {
            $shared = sodium_crypto_scalarmult($private, $this->gateway);
        } catch (\Throwable) {
            throw new Error("SDK_RESPONSE_INVALID");
        }
        $k = substr(self::hash($this->gateway), 0, 16);
        $aad = "authgo-gateway-v2\0" . $k . "\0" . $ep;
        $salt = hash("sha256", $aad, true);
        $n = random_bytes(12);
        $ct = self::seal(
            self::hkdf($shared, $salt, "authgo/v2/request"),
            $n,
            self::pad($inner),
            $aad,
        );
        $packet = [
            "v" => 2,
            "k" => $k,
            "e" => $ep,
            "n" => self::b64($n),
            "c" => self::b64($ct),
        ];
        $transport = $this->options["transport"] ?? [self::class, "http"];
        [$status, , $raw] = $transport(
            $this->endpoint . "/gateway",
            Json::encode($packet),
            ["Content-Type" => "application/json"],
            $this->requestBudget,
            2097152,
        );
        if ($status !== 200) {
            throw new Error("SDK_RESPONSE_INVALID");
        }
        try {
            $outer = Json::parse($raw);
            if (
                !($outer instanceof \ArrayObject) ||
                count($outer) !== 2 ||
                !isset($outer["n"]) ||
                !isset($outer["c"])
            ) {
                throw new Error("SDK_RESPONSE_INVALID");
            }
            $env = Json::parse(
                self::unpad(
                    self::open(
                        self::hkdf($shared, $salt, "authgo/v2/response"),
                        self::decode($outer["n"]),
                        self::decode($outer["c"]),
                        $aad .
                            "\0" .
                            self::hash($packet["n"] . "." . $packet["c"]),
                    ),
                ),
            );
        } catch (\Throwable) {
            throw new Error("SDK_RESPONSE_INVALID");
        }
        try {
            $signature = base64_decode($env["signature"], true);
            $data = Json::encode([
                "code" => $env["code"],
                "data" => $env["data"],
                "ts" => $env["ts"],
            ]);
            if (
                !$signature ||
                base64_encode($signature) !== $env["signature"] ||
                !sodium_crypto_sign_verify_detached(
                    $signature,
                    $data,
                    $this->public,
                )
            ) {
                throw new \Exception();
            }
        } catch (\Throwable) {
            throw new Error("SDK_RESPONSE_SIGNATURE_INVALID");
        }
        if (
            $env["nonce"] !== $nonce ||
            $env["data"]["request_nonce"] !== $nonce
        ) {
            throw new Error("SDK_RESPONSE_NONCE_INVALID");
        }
        if (abs(Json::num($env["ts"]) - $this->now()) > 300) {
            throw new Error("SDK_RESPONSE_TIMESTAMP_INVALID");
        }
        if ($env["code"] !== "OK") {
            $error=new Error($env["code"], "服务器拒绝请求", true);$error->latestVersion=$env["data"]["latest_version"]??"";$error->latestEntitledVersion=$env["data"]["latest_entitled_version"]??"";throw $error;
        }
        return [$env["data"], $challenge];
    }
    private function grant(string $ticket): mixed
    {
        try {
            $p = explode(".", $ticket);
            if (count($p) !== 2) {
                throw new \Exception();
            }
            $raw = self::decode($p[0]);
            if (
                !sodium_crypto_sign_verify_detached(
                    self::decode($p[1]),
                    "authgo-ticket-v2\0" . $raw,
                    $this->public,
                )
            ) {
                throw new \Exception();
            }
            $g = Json::parse($raw);
            if (
                Json::num($g["v"]) !== 2.0 ||
                $g["app_key"] !== $this->config["app_key"] ||
                $g["status"] !== "active" ||
                Json::num($g["license_id"]) <= 0 ||
                $g["device_hash"] !== self::hash($this->fp) ||
                strlen(self::decode($g["challenge"])) !== 32 ||
                Json::num($g["next_check_in"]) < 1 ||
                Json::num($g["next_check_in"]) > 86400
            ) {
                throw new \Exception();
            }
            return $g;
        } catch (\Throwable) {
            throw new Error("SDK_RESPONSE_SIGNATURE_INVALID", "票据无效");
        }
    }
    private static function date(mixed $s): float
    {
        return $s === null
            ? INF
            : (float) (new \DateTimeImmutable($s))->format("U.u");
    }
    private static function compareSeq(mixed $a, mixed $b): int
    {
        $a = $a instanceof JsonNumber ? $a->raw : (string) $a;
        $b = $b instanceof JsonNumber ? $b->raw : (string) $b;
        if (
            !preg_match('/^[1-9][0-9]*$/D', $a) ||
            !preg_match('/^(0|[1-9][0-9]*)$/D', $b)
        ) {
            throw new \Exception();
        }
        return strlen($a) <=> strlen($b) ?: strcmp($a, $b);
    }
    private function valid(mixed $g): void
    {
        $now = $this->now();
        if ($now + 300 < Json::num($this->state["observed"] ?? 0)) {
            throw new Error("SDK_CLOCK_ROLLBACK");
        }
        if (isset($g["starts_at"]) && $now < self::date($g["starts_at"])) {
            throw new Error("LICENSE_NOT_STARTED");
        }
        if ($now >= self::date($g["expires_at"])) {
            throw new Error("LICENSE_EXPIRED");
        }
    }
    public function validate(string $ticket): mixed
    {
        $this->ensureInstance();
        $g = $this->grant($ticket);
        if ($this->state["refused"] ?? false) {
            throw new Error("SDK_NOT_ACTIVATED");
        }
        $this->valid($g);
        if($g["floating"]&&(!isset($g["lease_expires_at"])||$this->now()>=self::date($g["lease_expires_at"]))&&!($ticket===$this->offlineTicket&&$this->now()<$this->offlineUntil))throw new Error("LEASE_EXPIRED");
        if (
            $this->now() < self::date($g["grace_until"]) ||
            ($ticket === $this->onlineTicket &&
                $this->now() < $this->onlineUntil)
        ) {
            return $g;
        }
        if ($this->now() >= self::date($g["grace_until"])) {
            throw new Error("SDK_GRACE_EXPIRED");
        }
        return $g;
    }
    private function fallback(Error $cause): Result
    {
        try {
            if (
                ($this->state["refused"] ?? false) ||
                !($this->state["ticket"] ?? "")
            ) {
                throw new \Exception();
            }
            $g = $this->grant($this->state["ticket"]);
            $seed = self::decode($this->state["seed"] ?? "");
            if (self::hash($seed) !== $g["unlock_hash"]) {
                throw new \Exception();
            }
        } catch (\Throwable) {
            throw $cause;
        }
        if($g["is_trial"]??false)throw new Error("SDK_GRACE_EXPIRED","试用需要稳定联网");
        if ($this->now() + 300 < Json::num($this->state["observed"] ?? 0)) {
            throw new Error("SDK_CLOCK_ROLLBACK");
        }
        $this->state["observed"] = max(
            (int) $this->now(),
            Json::num($this->state["observed"] ?? 0),
        );
        $this->save();
        $this->valid($g);
        $this->state["observed"] = max(
            (int) $this->now(),
            Json::num($this->state["observed"] ?? 0),
        );
        $this->saveWarning();
        $end=min(self::date($g["grace_until"]),self::date($g["expires_at"]));
        $this->offlineTicket=$this->state["ticket"];$this->offlineUntil=$end;
        $this->saveWarning();
        if ($this->now() < $end) {
            return new Result(
                $this,
                $g,
                $this->state["ticket"],
                $seed,
                "grace",
                $end,
                (string) $cause,
            );
        }
        throw new Error("SDK_GRACE_EXPIRED", "", false, $cause);
    }
    private function validGrantTime(mixed $g): void
    {
        try {
            $now = $this->now();
            if (isset($g["starts_at"]) && $now < self::date($g["starts_at"])) {
                throw new Error("LICENSE_NOT_STARTED");
            }
            if ($now >= self::date($g["expires_at"])) {
                throw new Error("LICENSE_EXPIRED");
            }
            if (
                $g["floating"] &&
                (!isset($g["lease_expires_at"]) ||
                    $now >= self::date($g["lease_expires_at"]))
            ) {
                throw new Error("LEASE_EXPIRED");
            }
        } catch (Error $e) {
            throw $e;
        } catch (\Throwable) {
            throw new Error("SDK_RESPONSE_INVALID");
        }
    }
    private function authorization(string $op, ?string $key = null): ?Result
    {
        return $this->payloadLocked(function() use($op,$key): ?Result {
            try {
                $result=$this->authorize($op,$key);
                if($op==="deactivate"){$this->payloadReady=false;$this->clearPayloadKeys();}
                elseif($result!==null)$this->recordPayloadResult($result);
                return $result;
            }catch(Error $error){if($error->refusal()){$this->payloadReady=false;$this->clearPayloadKeys();}throw $error;}
        });
    }
    private function authorize(string $op, ?string $key = null): ?Result
    {
        if ($key !== null) {
            self::validateKey($key);
        }
        $this->ensureInstance($op==="activate"?$key:null);
        if($op==="verify"&&($this->state["ticket"]??"")){try{$cached=$this->grant($this->state["ticket"]);if($cached["floating"]&&$this->now()>=self::date($cached["lease_expires_at"]))$op="heartbeat";}catch(Error){}}
        $previous = clone $this->state;
        if ($op === "activate") {
            if ($key !== ($this->state["key"] ?? null)) {
                $old = $this->state;
                $this->state = new \ArrayObject();
                foreach (["observed", "trial_key"] as $k) {
                    if (isset($old[$k])) {
                        $this->state[$k] = $old[$k];
                    }
                }
            }
            $this->state["key"] = $key;
        } elseif (!($this->state["token"] ?? "")) {
            throw new Error("SDK_NOT_ACTIVATED");
        }
        try {
            $input = $this->body();
            if($op==="deactivate")unset($input["instance_session"]);
            if ($op === "activate") {
                $input["activation_token"] = "";
            }
            [$d, $ch] = $this->request($op, $input);
            if ($op === "deactivate") {
                if (!($d["deactivated"] ?? false)) {
                    throw new Error("SDK_RESPONSE_INVALID");
                }
                $this->state["ticket"] = "";
                $this->state["seed"] = "";
                $this->state["token"] = "";
                $this->state["refused"] = true;
                $this->save();
                return null;
            }
            $g = $this->grant($d["ticket"]);
            $this->validGrantTime($g);
            if (
                Json::encode($g["license_id"]) !==
                    Json::encode($d["license_id"]) ||
                Json::encode($g["next_check_in"]) !==
                    Json::encode($d["next_check_in"])
            ) {
                throw new Error("SDK_RESPONSE_INVALID");
            }
            $seed = self::decode($d["unlock_seed"]);
            if ($g["challenge"] !== $ch) {
                throw new Error("SDK_RESPONSE_NONCE_INVALID");
            }
            if (abs(self::date($g["issued_at"]) - $this->now()) > 300) {
                throw new Error("SDK_RESPONSE_TIMESTAMP_INVALID");
            }
            if (
                strlen($seed) !== 32 ||
                self::hash($seed) !== $g["unlock_hash"]
            ) {
                throw new Error("SDK_RESPONSE_SIGNATURE_INVALID");
            }
            $this->state["refused"] = false;
            $this->state["observed"] = max(
                (int) $this->now(),
                self::date($g["issued_at"]),
            );
            if ($op === "activate") {
                if (
                    !preg_match(
                        '/^act_[A-Za-z0-9_-]{43}$/D',
                        $d["activation_token"] ?? "",
                    )
                ) {
                    throw new Error("SDK_RESPONSE_INVALID");
                }
                $this->state["token"] = $d["activation_token"];
            }
            $this->state["heartbeat_interval"] = $this->heartbeatValue($g, $d["heartbeat_interval"]??0);
            $this->state["ticket"] = $d["ticket"];
            unset($this->state["status"], $this->state["availability"], $this->state["guard"]);
            $this->state["seed"] = $d["unlock_seed"];
            $this->offlineTicket="";$this->offlineUntil=0;
            $this->onlineTicket = $d["ticket"];
            $this->onlineUntil = $this->now() + Json::num($g["next_check_in"]);
            $this->saveWarning();
            $this->validate($d["ticket"]);
            return new Result(
                $this,
                $g,
                $d["ticket"],
                $seed,
                "online",
                min(
                    max(self::date($g["grace_until"]), $this->onlineUntil),
                    self::date($g["expires_at"]),
                    $g["floating"] ? self::date($g["lease_expires_at"]) : INF,
                ),
            );
        } catch (Error $e) {
            if($e->authenticated&&$e->errorCode==="INSTANCE_REPLACED"){$this->state=$previous;ContainerIdentity::$replaced[$this->instanceKey($op==="activate"?$key:null)]=true;$this->offlineUntil=$this->onlineUntil=0;throw $e;}
            if ($op === "activate" && ($previous["key"] ?? null) !== $key) {
                $this->state = $previous;
                throw $e;
            }
            if ($op === "activate" && $e->refusal()) {
                $this->state["token"] = "";
                $this->revokeCache();
                throw $e;
            }
            if (in_array($op, ["verify", "heartbeat"], true)) {
                $this->onlineUntil = 0;
                if ($e->refusal()) {
                    $this->revokeCache();
                    throw $e;
                }
                return $this->fallback($e);
            }
            throw $e;
        } catch (\Throwable $cause) {
            if ($op === "activate" && ($previous["key"] ?? null) !== $key) {
                $this->state = $previous;
            }
            $error = new Error("SDK_RESPONSE_INVALID", "", false, $cause);
            if (in_array($op, ["verify", "heartbeat"], true)) {
                $this->onlineUntil = 0;
                return $this->fallback($error);
            }
            throw $error;
        }
    }
    private function heartbeatValue(mixed $data, mixed $cached=0): float {
        $value=Json::num($cached);
        if($value>=1 && $value<=3600)return (float)$value;
        if($data["floating"]??false) {
            $span=self::date($data["lease_expires_at"]??null)-self::date($data["issued_at"]??null);
            if(is_finite($span)&&$span>0)return max(1,min(3600,ceil($span/2)));
        }
        return max(1,min(3600,Json::num($data["next_check_in"]??1)));
    }
    /** @internal */
    public function guardHeartbeat(mixed $data): float {return $this->heartbeatValue($data,$this->state["heartbeat_interval"]??0);}
    /** @internal No SDK signal handler or subprocess is needed for close. */
    public function guardRelease(): void {
        $old=$this->requestBudget;$this->requestBudget=5;
        try {$this->releaseSeat();} finally {$this->requestBudget=$old;}
    }
    /** @internal A cache file lock spans reload, local validation, I/O and save. */
    public function guardLocked(callable $action): mixed {
        if($this->guardLockDepth>0 || $this->memoryCache)return $action();
        $f=@fopen($this->file.".guard.lock","c");
        if(!$f)throw new Error("SDK_CACHE_UNAVAILABLE");
        @chmod($this->file.".guard.lock",0600);
        try {
            if(!flock($f,LOCK_EX))throw new Error("SDK_CACHE_UNAVAILABLE");
            $this->guardLockDepth++;
            try{$this->guardReload();return $action();}finally{$this->guardLockDepth--;}
        } finally {flock($f,LOCK_UN);fclose($f);}
    }
    /** @internal Restore only evidence from the authenticated encrypted cache. */
    public function guardTrialKey(): string {
        $key=$this->state["trial_key"]??"";
        if($key==="") {
            [$data,$challenge]=$this->request("trial",["device_fingerprint"=>$this->fp]);
            if(($data["challenge"]??"")!==$challenge)throw new Error("SDK_RESPONSE_NONCE_INVALID");
            $key=$data["license_key"]??"";self::validateKey($key);
            $this->state["trial_key"]=$key;$this->saveWarning();
        }
        return $key;
    }
    public function guardCached(string $key): ?array {
        $m=$this->state["guard"]??null;$ticket=$this->state["ticket"]??"";
        if(!$m||!$ticket||($this->state["refused"]??false)||($this->state["key"]??"")!==$key||($m["proof"]??"")!==self::hash($ticket))return null;
        try {
            $g=$this->grant($ticket);$this->valid($g);
            $seed=self::decode($this->state["seed"]??"");
            if(self::hash($seed)!==$g["unlock_hash"])return null;
            $this->onlineTicket=$ticket;
            $this->onlineUntil=min(Json::num($m["online_until"]??0),self::date($g["issued_at"])+Json::num($g["next_check_in"])+300);
            $status=(string)($m["status"]??"");
            $end=isset($m["until"])?(float)Json::num($m["until"]):INF;
            if($status==="grace") {
                $this->offlineTicket=$ticket;
                $this->offlineUntil=min($end,self::date($g["expires_at"]),self::date($g["grace_until"]));
                $end=$this->offlineUntil;
            }
            if(in_array($status,["online","grace"],true)) {$this->validate($ticket);} else return null;
            $result=new Result($this,$g,$ticket,$seed,$status,$end,(string)($m["reason"]??""));
            $this->recordPayloadResult($result);
            return [$result,(float)Json::num($m["verify_at"]),(float)Json::num($m["heartbeat_at"])];
        } catch(Error) {return null;}
    }
    /** @internal The proof remains the signed ticket, never these scheduling fields. */
    public function guardPersist(Result $result,float $verify,float $heartbeat): void {
        $this->state["observed"]=max((int)$this->now(),Json::num($this->state["observed"]??0));
        $this->state["guard"]=["proof"=>self::hash($result->ticket()),"status"=>$result->status,"until"=>is_finite($result->usableUntil())?$result->usableUntil():null,"reason"=>$result->reason,"online_until"=>$this->onlineUntil,"verify_at"=>$verify,"heartbeat_at"=>$heartbeat];
        if($result->status!=="online")$this->save();else $this->saveWarning();
    }
    /** @internal Share the request worker lock; CLI execution is already synchronous. */
    private function payloadLocked(callable $action): mixed
    {
        if(isPersistentRuntime()||$this->guardLockDepth>0||$this->memoryCache)return $action();
        $entered=false;
        try{return $this->guardLocked(function() use($action,&$entered): mixed {$entered=true;return $action();});}
        catch(Error $error){if(!$entered&&$error->errorCode==="SDK_CACHE_UNAVAILABLE")return $action();throw $error;}
    }
    private function recordPayloadResult(Result $result): void
    {
        $g=$this->grant($result->ticket());$this->payloadReady=true;
        $this->payloadNoCache=(bool)($g["is_trial"]??false)||self::date($g["grace_until"])<=self::date($g["issued_at"]);
        if($this->payloadNoCache)$this->clearPayloadKeys();
    }
    private function payloadCacheDisabled(?Result $result): bool
    {
        return $this->payloadNoCache||$this->memoryCache||$result===null||$result->isTrial||$result->status==="offline";
    }
    public function savePayloadKey(Payload $payload,Result $result,string $key): void
    {
        $this->payloadLocked(function() use($payload,$result,$key): void {
            $p=$payload->validated();
            try{if(!$this->payloadCacheDisabled($result))$this->payloadCache->save($p,$this->grant($result->ticket()),$this->now(),false,$key);}catch(\Throwable){}
        });
    }
    public function loadPayloadKey(Payload $payload,Result $result): string
    {
        return $this->payloadLocked(function() use($payload,$result): string {
            $p=$payload->validated();if($this->payloadCacheDisabled($result))throw new Error("SDK_CACHE_UNAVAILABLE");
            return $this->payloadCache->load($p,$this->grant($result->ticket()),$this->now());
        });
    }
    public function clearPayloadKeys(): void {$this->payloadLocked(function(): void {$this->payloadCache->clear($this->memoryCache);});}
    private function payloadCachedResult(): Result
    {
        $ticket=$this->state["ticket"];$g=$this->grant($ticket);$seed=self::decode($this->state["seed"]??"");
        if(strlen($seed)!==32||self::hash($seed)!==($g["unlock_hash"]??null))throw new Error("SDK_RESPONSE_SIGNATURE_INVALID");
        if(isset($g["starts_at"])&&$this->now()<self::date($g["starts_at"]))throw new Error("LICENSE_NOT_STARTED");
        if($this->now()>=self::date($g["expires_at"]??null))throw new Error("LICENSE_EXPIRED");
        return new Result($this,$g,$ticket,$seed);
    }
    private function payloadFreshResult(mixed $data,string $challenge,Result $previous): Result
    {
        try {
            if(!$data instanceof \ArrayObject)throw new Error("SDK_RESPONSE_INVALID");
            $keys=array_keys($data->getArrayCopy());
            if(array_diff(["license_id","status","expires_at","features","next_check_in","grace_until","heartbeat_interval","satisfied_methods","ticket","unlock_seed"],$keys))throw new Error("SDK_RESPONSE_INVALID");
            $g=$this->grant($data["ticket"]);$id=Payload::integer($data["license_id"]);$heartbeat=Payload::integer($data["heartbeat_interval"]);$methods=$data["satisfied_methods"];
            if(!isset($g["issued_at"],$g["grace_until"])||isset($g["is_trial"])&&!is_bool($g["is_trial"])||str_starts_with($id,"-")||$id==="0"||Payload::compare($id,"9223372036854775807")>0||
                $id!==Payload::integer($g["license_id"])||$data["status"]!=="active"||!$data["features"] instanceof \ArrayObject||
                Payload::integer($data["next_check_in"])!==Payload::integer($g["next_check_in"])||str_starts_with($heartbeat,"-")||$heartbeat==="0"||Payload::compare($heartbeat,"3600")>0||!is_array($methods))throw new Error("SDK_RESPONSE_INVALID");
            foreach($methods as $method)if(!is_string($method)||!in_array($method,["KEY","FLOATING"],true))throw new Error("SDK_RESPONSE_INVALID");
            if(!in_array("KEY",$methods,true)||count(array_unique($methods,SORT_STRING))!==count($methods)||in_array("FLOATING",$methods,true)&&!isset($data["lease_expires_at"])||!isset($data["grace_until"]))throw new Error("SDK_RESPONSE_INVALID");
            self::date($data["grace_until"]);$periods=clone $data;$periods["floating"]=in_array("FLOATING",$methods,true);$this->validGrantTime($periods);
            if(abs(self::date($g["issued_at"])-$this->now())>300)throw new Error("SDK_RESPONSE_TIMESTAMP_INVALID");
            $seed=self::decode($data["unlock_seed"]);
            if(strlen($seed)!==32||self::hash($seed)!==$g["unlock_hash"]||$g["challenge"]!==$challenge||$id!==Payload::integer($previous->data["license_id"]))throw new Error("SDK_RESPONSE_INVALID");
            return new Result($this,$g,$data["ticket"],$seed);
        }catch(Error $error){if($error->errorCode==="PAYLOAD_INVALID")throw new Error("SDK_RESPONSE_INVALID");throw $error;}
        catch(\Throwable){throw new Error("SDK_RESPONSE_INVALID");}
    }
    private function payloadFailure(Payload $payload,Result $result,Error $error): string
    {
        if($error->refusal()) {
            $this->payloadReady=false;$this->clearPayloadKeys();
            if($error->errorCode==="INSTANCE_REPLACED"){ContainerIdentity::$replaced[$this->instanceKey()]=true;$this->onlineUntil=$this->offlineUntil=0;}
            else $this->revokeCache();throw $error;
        }
        try{return $this->loadPayloadKey($payload,$result);}catch(Error){throw $error;}
    }
    /** The caller owns the returned 32-byte content key and must sodium_memzero it after use. */
    public function unlockPayload(Payload $payload): string
    {
        $material=$this->unlockPayloadMaterial($payload);
        if(strlen($material)===32)return $material;
        try{return substr($material,0,32);}finally{sodium_memzero($material);}
    }
    /** @internal K32||signed WM32 for the current payload. */
    public function unlockPayloadMaterial(Payload $payload): string
    {
        return $this->payloadLocked(function() use($payload): string {
            if(!$this->payloadReady||($this->state["refused"]??false)||!($this->state["ticket"]??"")||isset(ContainerIdentity::$replaced[$this->instanceKey()]))throw new Error("SDK_NOT_ACTIVATED");
            $p=$payload->validated();if($p->appKey!==$this->config["app_key"])throw Payload::invalid();
            $previous=$this->payloadCachedResult();
            if($this->now()+300<Json::num($this->state["observed"]??0))throw new Error("SDK_CLOCK_ROLLBACK");
            if($this->offlineTicket===$previous->ticket()&&$this->onlineUntil===0.0)return $this->loadPayloadKey($p,$previous);
            $private=random_bytes(32);
            try {
                $body=array_intersect_key($this->body(),array_flip(["license_key","activation_token","device_fingerprint","instance_session"]));
                $body["payload"]=$p->toObject();$body["ephemeral_public_key"]=self::b64(sodium_crypto_scalarmult_base($private));
                try{[$data,$challenge]=$this->request("payload.unlock",$body);}catch(Error $error){return $this->payloadFailure($p,$previous,$error);}
                catch(\Throwable){return $this->payloadFailure($p,$previous,new Error("SDK_RESPONSE_INVALID"));}
                // Fresh grant or unwrap failures never silently use an old cached key.
                $fresh=$this->payloadFreshResult($data,$challenge,$previous);$g=$fresh->data;
                if($fresh->isTrial||self::date($g["grace_until"])<=self::date($g["issued_at"])){$this->payloadNoCache=true;$this->clearPayloadKeys();}
                if($p->v===2){$wm=PayloadWatermark::response($data["watermark"]??null);sodium_memzero($wm);}
                $wrapped=[];$keys=array_keys($data->getArrayCopy());
                foreach(["e","n","c"] as $field){if(!in_array($field,$keys,true)||$data[$field]!==null&&!is_string($data[$field]))return $this->payloadFailure($p,$previous,new Error("SDK_RESPONSE_INVALID"));$wrapped[$field]=$data[$field]??"";}
                $key=$p->unwrap($wrapped,$private,self::decode($challenge));
                if($p->v===2){$wm=PayloadWatermark::response($data["watermark"]??null);try{$material=$key.$wm;sodium_memzero($key);$key=$material;}finally{sodium_memzero($wm);}}
                $this->savePayloadKey($p,$fresh,$key);return $key;
            }finally{sodium_memzero($private);}
        });
    }
    public function check(string $key): Result
    {
        return $this->payloadLocked(fn(): Result => $this->authorization(
            $key === ($this->state["key"] ?? "") && ($this->state["token"] ?? "") ? "verify" : "activate", $key,
        ));
    }
    public function activate(string $key): Result
    {
        return $this->authorization("activate", $key);
    }
    public function verify(): Result
    {
        return $this->authorization("verify");
    }
    public function heartbeat(): Result
    {
        return $this->authorization("heartbeat");
    }
    private function instanceKey(?string $key=null): string {return $this->endpoint."\0".$this->config["app_key"]."\0".$this->fp."\0".$this->config["public_key"]."\0".($key??($this->state["key"]??""))."\0".ContainerIdentity::session();}
    private function ensureInstance(?string $key=null): void {if(isset(ContainerIdentity::$replaced[$this->instanceKey($key)]))throw new Error("INSTANCE_REPLACED");}
    public function releaseSeat(): void {$this->payloadLocked(function(): void {$this->releaseSeatUnlocked();});}
    private function releaseSeatUnlocked(): void {
        if(!($this->state["ticket"]??"")||!$this->grant($this->state["ticket"])["floating"])return;
        try{$this->request("release-seat",$this->body());}catch(Error $e){
            if($e->refusal()){$this->payloadReady=false;$this->clearPayloadKeys();}
            if($e->authenticated&&$e->errorCode==="INSTANCE_REPLACED"){ContainerIdentity::$replaced[$this->instanceKey()]=true;$this->offlineUntil=$this->onlineUntil=0;}
            elseif($e->refusal())$this->revokeCache();throw $e;
        }
    }
    public function deactivate(): void
    {
        $this->authorization("deactivate");
    }
    public function announcements(): array
    {
        return $this->request("announcement")[0]["items"];
    }
    public function checkUpdate(string $current): mixed
    {
        if (!($this->state["token"] ?? "")) {
            throw new Error("SDK_NOT_ACTIVATED");
        }
        $body = $this->body();
        $body["current_version"] = $current;
        $body["client_version"] = $current;
        $d = $this->request("update.check", $body)[0];
        foreach ($d as $key => $_) if (!in_array($key,["available", "docker_image", "docker_pull", "version", "changelog", "mandatory", "published_at", "maintenance_until", "latest_entitled_version", "renewal_required"],true)) unset($d[$key]);
        return $d;
    }
    private static function osName(): string
    {
        return match (PHP_OS_FAMILY) {
            "Windows" => "windows",
            "Darwin" => "darwin",
            default => "linux",
        };
    }
}

require_once __DIR__ . "/Payload.php";
require_once __DIR__ . "/PayloadCache.php";
require_once __DIR__ . "/PayloadWatermark.php";
require_once __DIR__ . "/Sealed.php";
require_once __DIR__ . "/Guard.php";
