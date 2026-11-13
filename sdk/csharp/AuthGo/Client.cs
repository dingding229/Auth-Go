using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace AuthGo;

public sealed class AuthGoException(
    string code,
    bool authenticated = false,
    Exception? cause = null
) : Exception(code + (code == "SDK_INVALID_CONFIG" ? ": 请在后台重新复制接入配置" : ""), cause)
{
    public string Code { get; } = code;
    public string LatestVersion { get; internal set; } = "";
    public string LatestEntitledVersion { get; internal set; } = "";
    internal bool Authenticated => authenticated;
    internal bool Refusal => authenticated && !Client.Temporary.Contains(Code);
}

public sealed class ClientOptions
{
    public string? Fingerprint { get; set; }
    public string? CacheDir { get; set; }
    public string Version { get; set; } = "";
    public Func<DateTimeOffset> Clock { get; set; } = () => DateTimeOffset.UtcNow;
    public HttpClient? HttpClient { get; set; }
}

public sealed class Result
{
    readonly Client client;
    readonly string proof;
    readonly byte[] seed;
    readonly double end;
    readonly string? warning;
    readonly bool snapshot;
    public JsonObject Data { get; }
    public string? MaintenanceUntil => Data["maintenance_until"]?.GetValue<string>();
    public string LatestEntitledVersion => Data["latest_entitled_version"]?.GetValue<string>() ?? "";
    public string Status { get; }
    public string Availability => Status;
    public bool Offline => Status != "online";
    public bool IsTrial => Data["is_trial"]?.GetValue<bool>() ?? false;
    public string Reason { get; }
    public string? CacheWarning => snapshot ? warning : client.CacheWarning;
    public JsonNode? Features => Data["features"];
    public double HeartbeatInterval { get; private set; }
    internal double UsableUntil => end;
    Result(Result other) {
        client=other.client;Data=(JsonObject)other.Data.DeepClone();proof=other.proof;
        seed=other.seed.ToArray();warning=other.CacheWarning;snapshot=true;Status=other.Status;end=other.end;Reason=other.Reason;HeartbeatInterval=other.HeartbeatInterval;
    }
    internal Result Snapshot() => new(this);

    internal Result(
        Client c,
        JsonObject d,
        string t,
        byte[] s,
        string status,
        double until,
        string reason = ""
    )
    {
        client = c;
        warning = c.CacheWarning;
        Data = (JsonObject)d.DeepClone();
        HeartbeatInterval = c.GuardHeartbeat(d);
        proof = t;
        seed = s.ToArray();
        Status = status;
        end = until;
        Reason = reason;
    }

    public string Ticket() => proof;

}

public sealed class Client
{
    public static readonly HashSet<string> Temporary =
    [
        "INTERNAL_ERROR",
        "RATE_LIMITED",
        "REPLAY_DETECTED",
        "TIMESTAMP_INVALID",
        "SIGNATURE_INVALID",
        "INVALID_REQUEST",
        "PAYLOAD_INVALID",
    ];
    readonly JsonObject config;
    readonly byte[] publicKey,
        gateway,
        aad,
        cacheKey;
    readonly string endpoint,
        fp,
        file;
    readonly ClientOptions options;
    readonly HttpClient http;
    JsonObject state = new();
    readonly object gate = new();
    double onlineUntil;
    string onlineTicket = "", offlineTicket = "";
    double offlineUntil;
    bool memoryCache;
    bool payloadReady, payloadNoCache;
    internal readonly PayloadCache PayloadCache;
    public string? CacheWarning { get; private set; }
    internal double GuardHeartbeat(JsonObject grant) => Heartbeat(grant,N(state,"heartbeat_interval"));
    static double Heartbeat(JsonObject grant,double cached) {
        if(cached>=1 && cached<=3600) return cached;
        if(B(grant,"floating")) return Math.Clamp(Math.Ceiling((Date(grant["lease_expires_at"])-Date(grant["issued_at"]))/2),1,3600);
        return Math.Clamp(N(grant,"next_check_in"),1,3600);
    }
    internal double Now => options.Clock().ToUnixTimeMilliseconds() / 1000.0;

    public static byte[] Bytes(string s) => Encoding.UTF8.GetBytes(s);

    public static string B64(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Decode(string s)
    {
        try
        {
            if (s.Any(c => !(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_')))
                throw new Exception();
            var b = Convert.FromBase64String(
                s.Replace('-', '+').Replace('_', '/') + new string('=', (4 - s.Length % 4) % 4)
            );
            if (B64(b) != s)
                throw new Exception();
            return b;
        }
        catch
        {
            throw new AuthGoException("SDK_RESPONSE_INVALID");
        }
    }

    static byte[] Standard(string s)
    {
        var raw = Convert.FromBase64String(s);
        if (Convert.ToBase64String(raw) != s)
            throw new AuthGoException("SDK_RESPONSE_INVALID");
        return raw;
    }

    public static string Hash(byte[] b) =>
        Convert.ToHexString(SHA256.HashData(b)).ToLowerInvariant();

    public static byte[] Hkdf(byte[] ikm, byte[] salt, byte[] info, int length = 32) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, length, salt, info);

    public static byte[] Seal(byte[] key, byte[] n, byte[] raw, byte[] context)
    {
        try
        {
            var ct = new byte[raw.Length];
            var tag = new byte[16];
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(n, raw, ct, tag, context);
            return [.. ct, .. tag];
        }
        catch
        {
            throw new AuthGoException("SDK_RESPONSE_INVALID");
        }
    }

    public static byte[] Open(byte[] key, byte[] n, byte[] ct, byte[] context)
    {
        try
        {
            if (ct.Length < 16 || n.Length != 12)
                throw new Exception();
            var raw = new byte[ct.Length - 16];
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(n, ct.AsSpan(0, raw.Length), ct.AsSpan(raw.Length), raw, context);
            return raw;
        }
        catch
        {
            throw new AuthGoException("SDK_RESPONSE_INVALID");
        }
    }

    public static bool VerifySignature(byte[] key, byte[] raw, byte[] sig)
    {
        try
        {
            var v = new Ed25519Signer();
            v.Init(false, new Ed25519PublicKeyParameters(key));
            v.BlockUpdate(raw);
            return v.VerifySignature(sig);
        }
        catch
        {
            return false;
        }
    }

    public static byte[] Shared(byte[] privateKey, byte[] publicKey)
    {
        var result = new byte[32];
        new X25519PrivateKeyParameters(privateKey).GenerateSecret(
            new X25519PublicKeyParameters(publicKey),
            result,
            0
        );
        return result;
    }

    public static byte[] Pad(byte[] raw)
    {
        var n = Math.Max(4096, ((raw.Length + 4 + 511) / 512) * 512);
        var b = RandomNumberGenerator.GetBytes(n);
        BinaryPrimitives.WriteUInt32BigEndian(b, (uint)raw.Length);
        raw.CopyTo(b, 4);
        return b;
    }

    public static byte[] Unpad(byte[] b)
    {
        if (b.Length < 4)
            throw new AuthGoException("SDK_RESPONSE_INVALID");
        var n = BinaryPrimitives.ReadUInt32BigEndian(b);
        if (n == 0 || n + 4 > b.Length || b.Length != Math.Max(4096, ((n + 4 + 511) / 512) * 512))
            throw new AuthGoException("SDK_RESPONSE_INVALID");
        return b.AsSpan(4, (int)n).ToArray();
    }

    static readonly JsonSerializerOptions JsonOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    static int CompareKeys(string a, string b)
    {
        var x = a.EnumerateRunes().Select(c => c.Value).ToArray();
        var y = b.EnumerateRunes().Select(c => c.Value).ToArray();
        for (int i = 0; i < Math.Min(x.Length, y.Length); i++)
            if (x[i] != y[i])
                return x[i].CompareTo(y[i]);
        return x.Length.CompareTo(y.Length);
    }

    static string Quote(string value)
    {
        var b = new StringBuilder("\"");
        for (int i = 0; i < value.Length; i++)
        {
            char c = value[i];
            switch (c)
            {
                case '\"':
                    b.Append("\\\"");
                    break;
                case '\\':
                    b.Append("\\\\");
                    break;
                case '\n':
                    b.Append("\\n");
                    break;
                case '\r':
                    b.Append("\\r");
                    break;
                case '\t':
                    b.Append("\\t");
                    break;
                case '\b':
                    b.Append("\\b");
                    break;
                case '\f':
                    b.Append("\\f");
                    break;
                case '<':
                    b.Append("\\u003c");
                    break;
                case '>':
                    b.Append("\\u003e");
                    break;
                case '&':
                    b.Append("\\u0026");
                    break;
                case '\u2028':
                    b.Append("\\u2028");
                    break;
                case '\u2029':
                    b.Append("\\u2029");
                    break;
                default:
                    if (c < 32)
                        b.Append("\\u" + ((int)c).ToString("x4"));
                    else if (char.IsHighSurrogate(c))
                    {
                        if (i + 1 >= value.Length || !char.IsLowSurrogate(value[i + 1]))
                            throw new AuthGoException("SDK_RESPONSE_INVALID");
                        b.Append(c).Append(value[++i]);
                    }
                    else if (char.IsLowSurrogate(c))
                        throw new AuthGoException("SDK_RESPONSE_INVALID");
                    else
                        b.Append(c);
                    break;
            }
        }
        return b.Append('"').ToString();
    }

    public static string Canonical(JsonNode? v)
    {
        if (v?.GetValueKind() == JsonValueKind.String)
            return Quote(v.GetValue<string>());
        if (v is JsonObject o)
            return "{"
                + string.Join(
                    ",",
                    o.OrderBy(x => x.Key, Comparer<string>.Create(CompareKeys))
                        .Select(x => Canonical(JsonValue.Create(x.Key)) + ":" + Canonical(x.Value))
                )
                + "}";
        if (v is JsonArray a)
            return "[" + string.Join(",", a.Select(Canonical)) + "]";
        return (v?.ToJsonString(JsonOptions) ?? "null")
            .Replace("<", "\\u003c")
            .Replace(">", "\\u003e")
            .Replace("&", "\\u0026")
            .Replace("\u2028", "\\u2028")
            .Replace("\u2029", "\\u2029");
    }

    public static JsonNode Parse(byte[] raw)
    {
        try
        {
            using var doc = JsonDocument.Parse(raw, new JsonDocumentOptions { MaxDepth = 100 });
            void Check(JsonElement e)
            {
                if (e.ValueKind == JsonValueKind.Object)
                {
                    var keys = new HashSet<string>();
                    foreach (var p in e.EnumerateObject())
                    {
                        if (!keys.Add(p.Name))
                            throw new Exception();
                        Check(p.Value);
                    }
                }
                else if (e.ValueKind == JsonValueKind.Array)
                    foreach (var v in e.EnumerateArray())
                        Check(v);
                else if (e.ValueKind == JsonValueKind.String)
                {
                    var s = e.GetString()!;
                    for (var i = 0; i < s.Length; i++)
                        if (char.IsSurrogate(s[i]))
                        {
                            if (
                                !char.IsHighSurrogate(s[i])
                                || i + 1 >= s.Length
                                || !char.IsLowSurrogate(s[++i])
                            )
                                throw new Exception();
                        }
                }
            }
            Check(doc.RootElement);
            return JsonNode.Parse(raw)!;
        }
        catch
        {
            throw new AuthGoException("SDK_RESPONSE_INVALID");
        }
    }

    static string S(JsonNode? o, string k) => o?[k]?.GetValue<string>() ?? "";

    static double N(JsonNode? o, string k) =>
        o?[k] is JsonNode v
            ? double.Parse(v.ToJsonString(), System.Globalization.CultureInfo.InvariantCulture)
            : 0;

    static bool B(JsonNode? o, string k) => o?[k]?.ToJsonString() == "true";

    static double Date(JsonNode? v) =>
        v == null
            ? double.PositiveInfinity
            : DateTimeOffset
                .Parse(v.GetValue<string>(), System.Globalization.CultureInfo.InvariantCulture)
                .ToUnixTimeMilliseconds() / 1000.0;

    static JsonObject Object(params (string, object?)[] pairs)
    {
        var obj = new JsonObject();
        foreach (var (k, v) in pairs)
            obj[k] = v is JsonNode node ? node.DeepClone() : JsonSerializer.SerializeToNode(v);
        return obj;
    }

    public Client(string configuration, ClientOptions? settings = null)
    {
        options = settings ?? new();
        try
        {
            if (configuration.Length > 32768 || !configuration.StartsWith("authgo2."))
                throw new Exception();
            config = (JsonObject)Parse(Decode(configuration[8..]));
            if (
                config.Any(p =>
                    !new[]
                    {
                        "url",
                        "app_key",
                        "app_secret",
                        "public_key",
                        "gateway_key",
                                            }.Contains(p.Key)
                )
            )
                throw new Exception();
            foreach (var k in new[] { "url", "app_key", "app_secret", "public_key", "gateway_key" })
                if (S(config, k) == "")
                    throw new Exception();
            var u = new Uri(S(config, "url"));
            ValidUrl(u, false);
            publicKey = Standard(S(config, "public_key"));
            gateway = Decode(S(config, "gateway_key"));
            if (publicKey.Length != 32 || gateway.Length != 32)
                throw new Exception();
            endpoint = S(config, "url").TrimEnd('/');
            if (!endpoint.EndsWith("/api/v1/client"))
                endpoint += "/api/v1/client";
        }
        catch
        {
            throw new AuthGoException("SDK_INVALID_CONFIG");
        }
        var container = ContainerIdentity.Detect();
        var root =
            OperatingSystem.IsWindows()
                ? Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)
            : OperatingSystem.IsMacOS()
                ? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    "Library",
                    "Caches"
                )
            : Environment.GetEnvironmentVariable("XDG_CACHE_HOME")
                ?? Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".cache"
                );
        var envDir=Environment.GetEnvironmentVariable("AUTHGO_CACHE_DIR");
        var cache=options.CacheDir ?? (!string.IsNullOrEmpty(envDir)?envDir:container?"/var/lib/authgo":Path.Combine(root,"authgo",Hash(Bytes(S(config,"app_key")))));
        var envId=Environment.GetEnvironmentVariable("AUTHGO_INSTANCE_ID");memoryCache=cache=="";
        if(options.Fingerprint!=null)fp=options.Fingerprint.ToLowerInvariant();
        else if(!string.IsNullOrEmpty(envId))fp=ContainerIdentity.Hash(envId);
        else if(container){var identity=ContainerIdentity.Load(cache);fp=ContainerIdentity.Hash(identity.Item1);memoryCache=identity.Item2;if(memoryCache)CacheWarning="此实例重启后是新实例，没有断连宽限";}
        else fp=Fingerprint();
        if(!System.Text.RegularExpressions.Regex.IsMatch(fp,"^[a-f0-9]{64}$"))throw new AuthGoException("SDK_INVALID_CONFIG");
        aad = Bytes("authgo/csharp/cache/v2\0" + endpoint + "\0" + S(config, "app_key") + "\0" + fp);
        cacheKey = Hkdf(
            Bytes(S(config, "app_secret")),
            SHA256.HashData(aad),
            Bytes("authgo/multi/cache/key")
        );
        PayloadCache = new PayloadCache(cache, endpoint, S(config, "app_key"), fp, publicKey);
        file = Path.Combine(cache, Hash(aad) + ".cache");
        http =
            options.HttpClient
            ?? new HttpClient(new HttpClientHandler { AllowAutoRedirect = false })
            {
                Timeout = Timeout.InfiniteTimeSpan,
            };
        try
        {
            if (!memoryCache && File.Exists(file))
            {
                if(new FileInfo(file).Length>16*1024*1024)throw new AuthGoException("SDK_CACHE_INVALID");
                var raw = File.ReadAllBytes(file);
                if (raw.Length > 16 * 1024 * 1024)
                    throw new Exception();
                state = (JsonObject)Parse(Open(cacheKey, raw[..12], raw[12..], aad));
            }
        }
        catch
        {
            state = new();
        }
    }

    static void ValidUrl(Uri u, bool secure)
    {
        if (
            !u.IsAbsoluteUri
            || u.UserInfo != ""
            || !secure && u.Query != ""
            || u.Fragment != ""
            || u.Scheme != "https" && (secure || u.Scheme != "http" || !u.IsLoopback)
        )
            throw new Exception();
    }

    void Save()
    {
        if(memoryCache)return;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            var tmp = file + "." + B64(RandomNumberGenerator.GetBytes(12));
            var n = RandomNumberGenerator.GetBytes(12);
            using (
                var f = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None)
            )
            {
                if (!OperatingSystem.IsWindows())
                    File.SetUnixFileMode(tmp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                f.Write([.. n, .. Seal(cacheKey, n, Bytes(Canonical(state)), aad)]);
                f.Flush(true);
            }
            File.Move(tmp, file, true);
        }
        catch
        {
            throw new AuthGoException("SDK_CACHE_UNAVAILABLE");
        }
    }

    static string Command(string exe, params string[] args)
    {
        var p = new ProcessStartInfo(exe)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var a in args)
            p.ArgumentList.Add(a);
        using var process = Process.Start(p) ?? throw new Exception();
        var task = process.StandardOutput.ReadToEndAsync();
        if (!process.WaitForExit(3000))
        {
            process.Kill(true);
            throw new Exception();
        }
        if (process.ExitCode != 0)
            throw new Exception();
        return task.GetAwaiter().GetResult().Trim();
    }

    public static string IdentityHash(string machine, string mac, string cpu)
    {
        mac = mac.Trim().ToLowerInvariant().Replace('-', ':');
        cpu = string.Join(" ", cpu.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
            .ToLowerInvariant();
        if (
            machine.Trim() == ""
            || cpu == ""
            || !System.Text.RegularExpressions.Regex.IsMatch(
                mac,
                "^[0-9a-f]{2}(:[0-9a-f]{2}){5}(:[0-9a-f]{2}){0,2}$"
            )
        )
            throw new AuthGoException("SDK_FINGERPRINT_UNAVAILABLE");
        return Hash(
            Bytes(
                "authgo/fingerprint/v1\0"
                    + machine.Trim().ToLowerInvariant()
                    + "\0"
                    + mac
                    + "\0"
                    + cpu
            )
        );
    }

    public static void ValidateKey(string key)
    {
        const string alphabet="23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
        var p=key.Split('-');
        if(p.Length!=5||p[0].Length<1||p[0].Length>16)throw new AuthGoException("INVALID_LICENSE_KEY");
        for(var i=0;i<p.Length;i++){if(i>0&&p[i].Length!=5)throw new AuthGoException("INVALID_LICENSE_KEY");foreach(var c in p[i])if(!alphabet.Contains(c))throw new AuthGoException("INVALID_LICENSE_KEY");}
        var check=p[0].Length%32;
        foreach(var c in p[0]+p[1]+p[2]+p[3]+p[4][..4])check=(check*17+alphabet.IndexOf(c))%32;
        if(p[4][4]!=alphabet[check])throw new AuthGoException("INVALID_LICENSE_KEY");
    }
    public static string ParseLinuxCPU(string raw)
    {
        var lines=raw.Split('\n');
        foreach(var line in lines){var f=line.Split(':',2);if(f.Length==2&&new[]{"model name","Hardware","cpu model"}.Contains(f[0].Trim())&&f[1].Trim()!="")return f[1].Trim();}
        string implementer="",part="",uarch="";bool seen=false,done=false;
        foreach(var line in lines){if(string.IsNullOrWhiteSpace(line)&&seen)done=true;var f=line.Split(':',2);if(f.Length!=2)continue;var k=f[0].Trim();var v=f[1].Trim();
            if(k=="uarch"&&uarch=="")uarch=v;
            if(!done){if(k=="CPU implementer"){seen=true;if(implementer=="")implementer=string.Concat(v.Where(c=>!char.IsWhiteSpace(c))).ToLowerInvariant();}if(k=="CPU part"){seen=true;if(part=="")part=string.Concat(v.Where(c=>!char.IsWhiteSpace(c))).ToLowerInvariant();}}
        }
        return implementer!=""&&part!=""?"arm:"+implementer+":"+part:uarch;
    }

    public static string Fingerprint()
    {
        try
        {
            string machine,
                cpu,
                preferred = "";
            if (OperatingSystem.IsLinux())
            {
                machine = File.Exists("/etc/machine-id")
                    ? File.ReadAllText("/etc/machine-id")
                    : File.ReadAllText("/var/lib/dbus/machine-id");
                cpu = ParseLinuxCPU(File.ReadAllText("/proc/cpuinfo"));
                preferred =
                    File.ReadLines("/proc/net/route")
                        .Select(s => s.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries))
                        .FirstOrDefault(s => s.Length > 3 && s[1] == "00000000")
                        ?[0] ?? "";
            }
            else if (OperatingSystem.IsMacOS())
            {
                var raw = Command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice");
                machine = System
                    .Text.RegularExpressions.Regex.Match(
                        raw,
                        "\"IOPlatformUUID\"\\s*=\\s*\"([^\"]+)\""
                    )
                    .Groups[1]
                    .Value;
                try
                {
                    cpu = Command("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string");
                }
                catch
                {
                    cpu = Command("/usr/sbin/sysctl", "-n", "hw.model");
                }
                try
                {
                    preferred = System
                        .Text.RegularExpressions.Regex.Match(
                            Command("/sbin/route", "-n", "get", "default"),
                            "interface:\\s*(\\S+)"
                        )
                        .Groups[1]
                        .Value;
                }
                catch { }
            }
            else if (OperatingSystem.IsWindows())
            {
                var root = Environment.GetEnvironmentVariable("SystemRoot") ?? "C:\\Windows";
                var reg = Path.Combine(root, "System32", "reg.exe");
                machine = System
                    .Text.RegularExpressions.Regex.Match(
                        Command(
                            reg,
                            "query",
                            "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
                            "/v",
                            "MachineGuid",
                            "/reg:64"
                        ),
                        "MachineGuid\\s+REG_SZ\\s+(.+)"
                    )
                    .Groups[1]
                    .Value;
                cpu = System
                    .Text.RegularExpressions.Regex.Match(
                        Command(
                            reg,
                            "query",
                            "HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                            "/v",
                            "ProcessorNameString"
                        ),
                        "ProcessorNameString\\s+REG_SZ\\s+(.+)"
                    )
                    .Groups[1]
                    .Value;
                preferred = Command(
                    Path.Combine(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty InterfaceIndex"
                );
            }
            else
                throw new Exception();
            var nics = NetworkInterface
                .GetAllNetworkInterfaces()
                .Where(n =>
                    n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                    && n.GetPhysicalAddress().GetAddressBytes().Any(b => b != 0)
                )
                .Select(n =>
                    (nic: n, index: n.GetIPProperties().GetIPv4Properties()?.Index ?? int.MaxValue)
                )
                .OrderBy(n => n.index)
                .ToList();
            var match = nics.FirstOrDefault(n =>
                n.nic.Name == preferred || n.index.ToString() == preferred
            );
            var chosen =
                match.nic
                ?? nics.FirstOrDefault(n => n.nic.OperationalStatus == OperationalStatus.Up).nic
                ?? nics[0].nic;
            return IdentityHash(
                machine,
                string.Join(
                    ":",
                    chosen.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("x2"))
                ),
                cpu
            );
        }
        catch
        {
            throw new AuthGoException("SDK_FINGERPRINT_UNAVAILABLE");
        }
    }

    void SaveWarning(){if(!memoryCache)CacheWarning=null;try{Save();}catch(AuthGoException){CacheWarning="无法保存本地缓存，重启后没有断连宽限";}}
    void RevokeCache()
    {
        payloadReady = false; ClearPayloadKeys();
        state["ticket"] = "";
        state["seed"] = "";
        state["refused"] = true;
        try
        {
            Save();
        }
        catch (AuthGoException)
        {
            try
            {
                File.Delete(file);
            }
            catch (IOException) { }
        }
    }

    JsonObject Body() =>
        Object(
            ("instance_session", ContainerIdentity.Session),
            ("license_key", S(state, "key")),
            ("activation_token", S(state, "token")),
            ("device_fingerprint", fp),
            ("client_version", options.Version),
            ("hostname", Environment.MachineName),
            ("os", OSName)
        );

    static string OSName =>
        OperatingSystem.IsWindows() ? "windows"
        : OperatingSystem.IsMacOS() ? "darwin"
        : "linux";
    static string Arch =>
        RuntimeInformation.ProcessArchitecture == Architecture.Arm64 ? "arm64" : "amd64";

    byte[] Fetch(
        string url,
        byte[]? body,
        double seconds,
        int limit,
        out HttpResponseMessage response
    )
    {
        try
        {
            using var cancel = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
            var req = new HttpRequestMessage(body == null ? HttpMethod.Get : HttpMethod.Post, url);
            if (body != null)
            {
                req.Content = new ByteArrayContent(body);
                req.Content.Headers.ContentType = new("application/json");
            }
            response = http.Send(req, HttpCompletionOption.ResponseHeadersRead, cancel.Token);
            if (response.StatusCode != HttpStatusCode.OK)
                throw new AuthGoException("SDK_RESPONSE_INVALID");
            using var registration = cancel.Token.Register(response.Dispose);
            using var stream = response.Content.ReadAsStream(cancel.Token);
            using var memory = new MemoryStream();
            var b = new byte[65536];
            int n;
            while ((n = stream.Read(b)) > 0)
            {
                if (memory.Length + n > limit)
                    throw new AuthGoException("SDK_RESPONSE_INVALID");
                memory.Write(b, 0, n);
                cancel.Token.ThrowIfCancellationRequested();
            }
            return memory.ToArray();
        }
        catch (AuthGoException)
        {
            throw;
        }
        catch (Exception e)
        {
            throw new AuthGoException(
                e.InnerException is System.Security.Authentication.AuthenticationException
                    ? "SDK_RESPONSE_INVALID"
                    : "SDK_NETWORK_ERROR",
                false,
                e
            );
        }
    }

    (JsonObject, string) Request(string op, JsonObject? body = null)
    {
        var challenge = B64(RandomNumberGenerator.GetBytes(32));
        var nonce = B64(RandomNumberGenerator.GetBytes(32));
        var ts = ((long)Now).ToString();
        if (body != null)
            body["challenge"] = challenge;
        var raw = body == null ? [] : Bytes(Canonical(body));
        var signature = Convert
            .ToHexString(
                HMACSHA256.HashData(
                    Bytes(S(config, "app_secret")),
                    Bytes(op + ts + nonce + Hash(raw))
                )
            )
            .ToLowerInvariant();
        var inner = Object(
            ("app_key", S(config, "app_key")),
            ("op", op),
            ("timestamp", ts),
            ("nonce", nonce),
            ("signature", signature),
            ("body", body)
        );
        JsonObject env;
        try
        {
            var privateKey = new X25519PrivateKeyParameters(new SecureRandom());
            var ep = B64(privateKey.GeneratePublicKey().GetEncoded());
            var shared = new byte[32];
            privateKey.GenerateSecret(new X25519PublicKeyParameters(gateway), shared, 0);
            var k = Hash(gateway)[..16];
            var context = Bytes("authgo-gateway-v2\0" + k + "\0" + ep);
            var salt = SHA256.HashData(context);
            var n = RandomNumberGenerator.GetBytes(12);
            var ct = Seal(
                Hkdf(shared, salt, Bytes("authgo/v2/request")),
                n,
                Pad(Bytes(Canonical(inner))),
                context
            );
            var packet = Object(("v", 2), ("k", k), ("e", ep), ("n", B64(n)), ("c", B64(ct)));
            var outer = (JsonObject)Parse(
                Fetch(endpoint + "/gateway", Bytes(Canonical(packet)), 10, 2097152, out var res)
            );
            res.Dispose();
            if (outer.Count != 2 || !outer.ContainsKey("n") || !outer.ContainsKey("c"))
                throw new AuthGoException("SDK_RESPONSE_INVALID");
            var responseContext = Bytes(
                Encoding.UTF8.GetString(context) + "\0" + Hash(Bytes(B64(n) + "." + B64(ct)))
            );
            env = (JsonObject)Parse(
                Unpad(
                    Open(
                        Hkdf(shared, salt, Bytes("authgo/v2/response")),
                        Decode(S(outer, "n")),
                        Decode(S(outer, "c")),
                        responseContext
                    )
                )
            );
        }
        catch (AuthGoException)
        {
            throw;
        }
        catch
        {
            throw new AuthGoException("SDK_RESPONSE_INVALID");
        }
        try
        {
            if (
                !VerifySignature(
                    publicKey,
                    Bytes(
                        Canonical(
                            Object(("code", env["code"]), ("data", env["data"]), ("ts", env["ts"]))
                        )
                    ),
                    Standard(S(env, "signature"))
                )
            )
                throw new Exception();
        }
        catch
        {
            throw new AuthGoException("SDK_RESPONSE_SIGNATURE_INVALID");
        }
        if (S(env, "nonce") != nonce || S(env["data"], "request_nonce") != nonce)
            throw new AuthGoException("SDK_RESPONSE_NONCE_INVALID");
        if (Math.Abs(N(env, "ts") - Now) > 300)
            throw new AuthGoException("SDK_RESPONSE_TIMESTAMP_INVALID");
        if (S(env, "code") != "OK")
            throw new AuthGoException(S(env, "code"), true){LatestVersion=S(env["data"]!.AsObject(),"latest_version"),LatestEntitledVersion=S(env["data"]!.AsObject(),"latest_entitled_version")};
        return ((JsonObject)env["data"]!.DeepClone(), challenge);
    }

    JsonObject Grant(string ticket)
    {
        try
        {
            var p = ticket.Split('.');
            if (p.Length != 2)
                throw new Exception();
            var raw = Decode(p[0]);
            if (!VerifySignature(publicKey, [.. Bytes("authgo-ticket-v2\0"), .. raw], Decode(p[1])))
                throw new Exception();
            var g = (JsonObject)Parse(raw);
            if (
                N(g, "v") != 2
                || S(g, "app_key") != S(config, "app_key")
                || S(g, "status") != "active"
                || N(g, "license_id") <= 0
                || S(g, "device_hash") != Hash(Bytes(fp))
                || Decode(S(g, "challenge")).Length != 32
                || N(g, "next_check_in") < 1
                || N(g, "next_check_in") > 86400
                || Date(g["grace_until"]) < Date(g["issued_at"])
            )
                throw new Exception();
            return g;
        }
        catch
        {
            throw new AuthGoException("SDK_RESPONSE_SIGNATURE_INVALID");
        }
    }

    void Valid(JsonObject g)
    {
        if (Now + 300 < N(state, "observed"))
            throw new AuthGoException("SDK_CLOCK_ROLLBACK");
        if (g["starts_at"] != null && Now < Date(g["starts_at"]))
            throw new AuthGoException("LICENSE_NOT_STARTED");
        if (Now >= Date(g["expires_at"]))
            throw new AuthGoException("LICENSE_EXPIRED");
    }

    public void Validate(string ticket)
    {
        lock (gate)
        {
            if (B(state, "refused"))
                throw new AuthGoException("SDK_NOT_ACTIVATED");
            EnsureInstance(null);
            var g = Grant(ticket);
            Valid(g);
            if(B(g,"floating")&&(g["lease_expires_at"]==null||Now>=Date(g["lease_expires_at"]))&&!(ticket==offlineTicket&&Now<offlineUntil))throw new AuthGoException("LEASE_EXPIRED");
            if (Now < Date(g["grace_until"]) || ticket == onlineTicket && Now < onlineUntil)
                return;
            if (Now >= Date(g["grace_until"]))
                throw new AuthGoException("SDK_GRACE_EXPIRED");
        }
    }

    internal Result GuardCheck(string key) {
        lock(gate) {
            if(key!="")return Check(key);
            key=S(state,"trial_key");
            if(key=="") {
                var (data,challenge)=Request("trial",Object(("device_fingerprint",fp)));
                if(S(data,"challenge")!=challenge)throw new AuthGoException("SDK_RESPONSE_NONCE_INVALID");
                key=S(data,"license_key");ValidateKey(key);
                state["trial_key"]=key;SaveWarning();
            }
            return Check(key);
        }
    }
    Result Fallback(AuthGoException cause)
    {
        JsonObject g;
        byte[] seed;
        try
        {
            if (B(state, "refused") || S(state, "ticket") == "")
                throw new Exception();
            g = Grant(S(state, "ticket"));
            seed = Decode(S(state, "seed"));
            if (Hash(seed) != S(g, "unlock_hash"))
                throw new Exception();
        }
        catch
        {
            throw cause;
        }
        if(B(g,"is_trial"))throw new AuthGoException("SDK_GRACE_EXPIRED");
        if(Now+300<N(state,"observed"))throw new AuthGoException("SDK_CLOCK_ROLLBACK");
        state["observed"]=Math.Max((long)Now,N(state,"observed"));Save();
        Valid(g);
        state["observed"] = Math.Max((long)Now, N(state, "observed"));
        SaveWarning();
        var end=Math.Min(Date(g["grace_until"]),Date(g["expires_at"]));
        offlineTicket=S(state,"ticket");offlineUntil=end;
        SaveWarning();
        if (Now < end)
            return new(this, g, S(state, "ticket"), seed, "grace", end, cause.Code);
        throw new AuthGoException("SDK_GRACE_EXPIRED", false, cause);
    }

    void ValidGrantTime(JsonObject g){try{if(g["starts_at"]!=null&&Now<Date(g["starts_at"]))throw new AuthGoException("LICENSE_NOT_STARTED");if(Now>=Date(g["expires_at"]))throw new AuthGoException("LICENSE_EXPIRED");if(B(g,"floating")&&(g["lease_expires_at"]==null||Now>=Date(g["lease_expires_at"])))throw new AuthGoException("LEASE_EXPIRED");}catch(AuthGoException){throw;}catch{throw new AuthGoException("SDK_RESPONSE_INVALID");}}
    Result? Authorization(string op, string key = "")
    {
        lock (gate)
        {
            try
            {
                var result = Authorize(op, key);
                if (op == "deactivate") { payloadReady = false; ClearPayloadKeys(); }
                else if (result != null) RecordPayloadResult(result);
                return result;
            }
            catch (AuthGoException error)
            {
                if (error.Refusal) { payloadReady = false; ClearPayloadKeys(); }
                throw;
            }
        }
    }

    Result? Authorize(string op, string key)
    {
        lock (gate)
        {
            if(key!=""||op=="activate")ValidateKey(key);
            EnsureInstance(op=="activate"?key:null);
            if(op=="verify"&&S(state,"ticket")!=""){
                try{var cached=Grant(S(state,"ticket"));if(B(cached,"floating")&&Now>=Date(cached["lease_expires_at"]))op="heartbeat";}
                catch(AuthGoException){}
            }
            var previous=(JsonObject)state.DeepClone();
            if (op == "activate")
            {
                if (S(state, "key") != key)
                    state = Object(
                        ("trial_key",state["trial_key"]),
                        ("observed", state["observed"])
                    );
                state["key"] = key;
            }
            else if (S(state, "token") == "")
                throw new AuthGoException("SDK_NOT_ACTIVATED");
            try
            {
                var input=Body();if(op=="deactivate")input.Remove("instance_session");if(op=="activate")input["activation_token"]="";
                var (d, ch) = Request(op, input);
                if (op == "deactivate")
                {
                    if (!B(d, "deactivated"))
                        throw new AuthGoException("SDK_RESPONSE_INVALID");
                    state["ticket"] = "";
                    state["seed"] = "";
                    state["token"] = "";
                    state["refused"] = true;
                    Save();
                    return null;
                }
                var g = Grant(S(d, "ticket"));
ValidGrantTime(g);
                if(Canonical(g["license_id"])!=Canonical(d["license_id"])||Canonical(g["next_check_in"])!=Canonical(d["next_check_in"]))throw new AuthGoException("SDK_RESPONSE_INVALID");
                var seed = Decode(S(d, "unlock_seed"));
                if (S(g, "challenge") != ch)
                    throw new AuthGoException("SDK_RESPONSE_NONCE_INVALID");
                if (Math.Abs(Date(g["issued_at"]) - Now) > 300)
                    throw new AuthGoException("SDK_RESPONSE_TIMESTAMP_INVALID");
                if (seed.Length != 32 || Hash(seed) != S(g, "unlock_hash"))
                    throw new AuthGoException("SDK_RESPONSE_SIGNATURE_INVALID");
                if (op == "activate")
                {
                    if (
                        !System.Text.RegularExpressions.Regex.IsMatch(
                            S(d, "activation_token"),
                            "^act_[A-Za-z0-9_-]{43}$"
                        )
                    )
                        throw new AuthGoException("SDK_RESPONSE_INVALID");
                    state["token"] = S(d, "activation_token");
                }
                state["heartbeat_interval"] = Heartbeat(g,N(d,"heartbeat_interval"));
                state["ticket"] = S(d, "ticket");
                state.Remove("status"); state.Remove("availability"); state.Remove("guard");
                state["seed"] = S(d, "unlock_seed");
                state["refused"] = false;
                state["observed"] = Math.Max(Now, Date(g["issued_at"]));
                offlineTicket="";offlineUntil=0;
                onlineTicket = S(d, "ticket");
                onlineUntil = Now + N(g, "next_check_in");
                SaveWarning();
                Validate(onlineTicket);
                return new(
                    this,
                    g,
                    onlineTicket,
                    seed,
                    "online",
                    Math.Min(
                        Math.Min(
                            Math.Max(Date(g["grace_until"]), onlineUntil),
                            Date(g["expires_at"])
                        ),
                        B(g, "floating") ? Date(g["lease_expires_at"]) : double.PositiveInfinity
                    )
                );
            }
            catch (AuthGoException e)
            {
                if(e.Authenticated&&e.Code=="INSTANCE_REPLACED"){state=previous;ContainerIdentity.Replaced.TryAdd(InstanceKey(op=="activate"?key:null),0);offlineUntil=onlineUntil=0;throw;}
                if(op=="activate"&&S(previous,"key")!=key){state=previous;throw;}
                if(op=="activate"&&e.Refusal){state["token"]="";RevokeCache();throw;}
                if (op is "verify" or "heartbeat")
                {
                    onlineUntil = 0;
                    if (e.Refusal)
                    {
                        RevokeCache();
                        throw;
                    }
                    return Fallback(e);
                }
                throw;
            }
            catch(Exception cause){if(op=="activate"&&S(previous,"key")!=key)state=previous;var error=new AuthGoException("SDK_RESPONSE_INVALID",false,cause);if(op is "verify" or "heartbeat"){onlineUntil=0;return Fallback(error);}throw error;}
        }
    }

    void RecordPayloadResult(Result result)
    {
        var grant = Grant(result.Ticket());
        payloadReady = true;
        payloadNoCache = B(grant, "is_trial") || Date(grant["grace_until"]) <= Date(grant["issued_at"]);
        if (payloadNoCache) ClearPayloadKeys();
    }
    bool PayloadCacheDisabled(Result? result) => payloadNoCache || memoryCache || result == null || result.IsTrial || result.Status == "offline";
    public void SavePayloadKey(Payload payload, Result result, byte[] key)
    {
        lock (gate)
        {
            var p = payload?.Validated() ?? throw Payload.Invalid();
            try { if (!PayloadCacheDisabled(result)) PayloadCache.Save(p, Grant(result.Ticket()), Now, false, key); }
            catch { /* Online unlock is independent of writable storage. */ }
        }
    }
    public byte[] LoadPayloadKey(Payload payload, Result result)
    {
        lock (gate)
        {
            var p = payload?.Validated() ?? throw Payload.Invalid();
            if (PayloadCacheDisabled(result)) throw new AuthGoException("SDK_CACHE_UNAVAILABLE");
            return PayloadCache.Load(p, Grant(result.Ticket()), Now, false);
        }
    }
    public void ClearPayloadKeys() { lock (gate) { PayloadCache.Clear(memoryCache); } }
    Result PayloadCachedResult()
    {
        string ticket = S(state, "ticket"); var g = Grant(ticket); byte[] seed = Decode(S(state, "seed"));
        if (seed.Length != 32 || Hash(seed) != S(g, "unlock_hash")) throw new AuthGoException("SDK_RESPONSE_SIGNATURE_INVALID");
        // An accepted offline floating grant remains usable after its original lease expires.
        if (g["starts_at"] != null && Now < Date(g["starts_at"])) throw new AuthGoException("LICENSE_NOT_STARTED");
        if (Now >= Date(g["expires_at"])) throw new AuthGoException("LICENSE_EXPIRED");
        return new(this, g, ticket, seed, "online", Date(g["grace_until"]));
    }
    Result PayloadFreshResult(JsonObject data, string challenge, Result previous)
    {
        try
        {
            string[] required = ["license_id", "status", "expires_at", "features", "next_check_in", "grace_until", "heartbeat_interval", "satisfied_methods", "ticket", "unlock_seed"];
            if (required.Any(k => !data.ContainsKey(k))) throw new AuthGoException("SDK_RESPONSE_INVALID");
            var g = Grant(S(data, "ticket")); var id = Payload.Integer(data["license_id"]);
            if (g["is_trial"] != null && g["is_trial"]!.GetValueKind() is not (JsonValueKind.True or JsonValueKind.False)) throw new AuthGoException("SDK_RESPONSE_INVALID");
            if (g["issued_at"] == null || g["grace_until"] == null || id <= 0 || id > long.MaxValue || id != Payload.Integer(g["license_id"]) ||
                S(data, "status") != "active" || data["features"] is not JsonObject || Payload.Integer(data["next_check_in"]) != Payload.Integer(g["next_check_in"]) ||
                Payload.Integer(data["heartbeat_interval"]) < 1 || Payload.Integer(data["heartbeat_interval"]) > 3600 || data["satisfied_methods"] is not JsonArray methods)
                throw new AuthGoException("SDK_RESPONSE_INVALID");
            var names = methods.Select(Payload.Text).ToArray();
            if (!names.Contains("KEY") || names.Distinct(StringComparer.Ordinal).Count() != names.Length || names.Any(m => !new[] { "KEY", "FLOATING" }.Contains(m)) ||
                names.Contains("FLOATING") && data["lease_expires_at"] == null || data["grace_until"] == null) throw new AuthGoException("SDK_RESPONSE_INVALID");
            _ = Date(data["grace_until"]); var periods = (JsonObject)data.DeepClone(); periods["floating"] = names.Contains("FLOATING"); ValidGrantTime(periods);
            if (Math.Abs(Date(g["issued_at"]) - Now) > 300) throw new AuthGoException("SDK_RESPONSE_TIMESTAMP_INVALID");
            byte[] seed = Decode(S(data, "unlock_seed"));
            if (seed.Length != 32 || Hash(seed) != S(g, "unlock_hash") || S(g, "challenge") != challenge || id != Payload.Integer(previous.Data["license_id"])) throw new AuthGoException("SDK_RESPONSE_INVALID");
            return new(this, g, S(data, "ticket"), seed, "online", Date(g["grace_until"]));
        }
        catch (AuthGoException error) when (error.Code == "PAYLOAD_INVALID") { throw new AuthGoException("SDK_RESPONSE_INVALID"); }
        catch (AuthGoException) { throw; }
        catch { throw new AuthGoException("SDK_RESPONSE_INVALID"); }
    }
    byte[] PayloadFailure(Payload payload, Result result, AuthGoException error)
    {
        if (error.Refusal)
        {
            payloadReady = false; ClearPayloadKeys();
            if (error.Code == "INSTANCE_REPLACED") { ContainerIdentity.Replaced.TryAdd(InstanceKey(null), 0); onlineUntil = offlineUntil = 0; }
            else RevokeCache();
            throw error;
        }
        try { return LoadPayloadKey(payload, result); } catch (AuthGoException) { throw error; }
    }
    /// <summary>Return the authenticated 32-byte content key. Caller must zero it after use.</summary>
    public byte[] UnlockPayload(Payload payload)
    {
        byte[] material = UnlockPayloadMaterial(payload);
        if (material.Length == 32) return material;
        try { return material[..32]; } finally { CryptographicOperations.ZeroMemory(material); }
    }
    internal byte[] UnlockPayloadMaterial(Payload payload)
    {
        lock (gate)
        {
            if (!payloadReady || B(state, "refused") || S(state, "ticket") == "" || ContainerIdentity.Replaced.ContainsKey(InstanceKey(null))) throw new AuthGoException("SDK_NOT_ACTIVATED");
            var p = payload?.Validated() ?? throw Payload.Invalid();
            if (p.AppKey != S(config, "app_key")) throw Payload.Invalid();
            var previous = PayloadCachedResult();
            if (Now + 300 < N(state, "observed")) throw new AuthGoException("SDK_CLOCK_ROLLBACK");
            if (offlineTicket == previous.Ticket() && onlineUntil == 0) return LoadPayloadKey(p, previous);
            byte[] privateKey = new X25519PrivateKeyParameters(new SecureRandom()).GetEncoded();
            try
            {
                byte[] ephemeral = new X25519PrivateKeyParameters(privateKey).GeneratePublicKey().GetEncoded();
                var input = Body(); foreach (string key in input.Select(x => x.Key).ToArray()) if (!new[] { "license_key", "activation_token", "device_fingerprint", "instance_session" }.Contains(key)) input.Remove(key);
                input["payload"] = p.ToJson(); input["ephemeral_public_key"] = B64(ephemeral);
                JsonObject data; string challenge;
                try { (data, challenge) = Request("payload.unlock", input); }
                catch (AuthGoException error) { return PayloadFailure(p, previous, error); }
                catch { return PayloadFailure(p, previous, new AuthGoException("SDK_RESPONSE_INVALID")); }
                // Fresh grant/unwrap authentication errors must not be hidden by cached keys.
                var fresh = PayloadFreshResult(data, challenge, previous);
                if (fresh.IsTrial || Date(fresh.Data["grace_until"]) <= Date(fresh.Data["issued_at"])) { payloadNoCache = true; ClearPayloadKeys(); }
                if (p.V == 2) { byte[] wm = PayloadWatermark.Response(data["watermark"]); CryptographicOperations.ZeroMemory(wm); }
                foreach (string key in new[] { "e", "n", "c" }) if (!data.ContainsKey(key) || data[key] != null && data[key]!.GetValueKind() != JsonValueKind.String)
                    return PayloadFailure(p, previous, new AuthGoException("SDK_RESPONSE_INVALID"));
                byte[] contentKey = p.Unwrap(new(S(data, "e"), S(data, "n"), S(data, "c")), privateKey, ephemeral, Decode(challenge));
                if (p.V == 2) {
                    byte[] watermark = PayloadWatermark.Response(data["watermark"]);
                    try { byte[] material = [..contentKey, ..watermark]; CryptographicOperations.ZeroMemory(contentKey); contentKey = material; }
                    finally { CryptographicOperations.ZeroMemory(watermark); }
                }
                SavePayloadKey(p, fresh, contentKey); return contentKey;
            }
            finally { CryptographicOperations.ZeroMemory(privateKey); }
        }
    }

    public Result Check(string key)
    {
        lock (gate)
        {
            ValidateKey(key);
            return Authorization(
                S(state, "key") == key && S(state, "token") != "" ? "verify" : "activate",
                key
            )!;
        }
    }

    public Result Activate(string key) => Authorization("activate", key)!;

    public Result Verify() => Authorization("verify")!;

    public Result Heartbeat() => Authorization("heartbeat")!;

    string InstanceKey(string? key)=>endpoint+"\0"+S(config,"app_key")+"\0"+fp+"\0"+S(config,"public_key")+"\0"+(key??S(state,"key"))+"\0"+ContainerIdentity.Session;
    void EnsureInstance(string? key){if(ContainerIdentity.Replaced.ContainsKey(InstanceKey(key)))throw new AuthGoException("INSTANCE_REPLACED");}
    public void ReleaseSeat(){lock(gate){
        if(S(state,"ticket")==""||!B(Grant(S(state,"ticket")),"floating"))return;
        try{Request("release-seat",Body());}catch(AuthGoException e){
            if(e.Refusal){payloadReady=false;ClearPayloadKeys();}
            if(e.Authenticated&&e.Code=="INSTANCE_REPLACED"){ContainerIdentity.Replaced.TryAdd(InstanceKey(null),0);offlineUntil=onlineUntil=0;}
            else if(e.Refusal)RevokeCache();throw;
        }
    }}
    public void Deactivate() => Authorization("deactivate");

    public JsonArray Announcements() => Request("announcement").Item1["items"]!.AsArray();

    public JsonObject CheckUpdate(string current)
    {
        lock (gate)
        {
            if (S(state, "token") == "")
                throw new AuthGoException("SDK_NOT_ACTIVATED");
            var body = Body();
            body["current_version"] = current;
            body["client_version"] = current;
            var d = Request("update.check", body).Item1;
            foreach (var key in d.Select(x => x.Key).ToArray()) if (!new[]{"available", "docker_image", "docker_pull", "version", "changelog", "mandatory", "published_at", "maintenance_until", "latest_entitled_version", "renewal_required"}.Contains(key)) d.Remove(key);
            return d;
        }
    }

}
