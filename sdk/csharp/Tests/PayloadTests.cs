using AuthGo;
using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

static class PayloadTests
{
    const string License = "AUTH-RNMSQ-VSQQA-4S4NH-JDGCM";
    const string Fingerprint = "c4ffc8a324a624018c71f7b23e99eafda2093769f82cddba01a2f1fb32d18bcd";
    static int cases;
    static string S(JsonNode? node, string key) => node?[key]?.GetValue<string>() ?? "";
    static byte[] H(JsonNode node, string key) => Convert.FromHexString(S(node, key));
    static string Hex(byte[] raw) => Convert.ToHexString(raw).ToLowerInvariant();
    static byte[] Digest(byte[] raw) => SHA256.HashData(raw);
    static byte[] Bytes(string text) => Client.Bytes(text);
    static JsonObject Read(string name) => (JsonObject)Client.Parse(File.ReadAllBytes("sdk/vectors/" + name));
    static JsonObject Copy(JsonObject node) => (JsonObject)node.DeepClone();
    static void Check(bool value) { if (!value) throw new Exception("payload assertion failed"); }
    static void Equal<T>(T actual, T expected) => Check(EqualityComparer<T>.Default.Equals(actual, expected));
    static void Same(byte[] actual, byte[] expected) => Check(actual.SequenceEqual(expected));
    static void Error(string code, Action action)
    {
        try { action(); throw new Exception("expected " + code); } catch (AuthGoException error) { Equal(error.Code, code); }
    }
    static void SetMode(string path, UnixFileMode mode)
    {
        if (OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("These cache tests require POSIX permissions");
        File.SetUnixFileMode(path, mode);
    }
    static UnixFileMode GetMode(string path)
    {
        if (OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("These cache tests require POSIX permissions");
        return File.GetUnixFileMode(path);
    }
    static void Case(string name, Action test) { test(); cases++; Console.WriteLine("payload: " + name + " PASS"); }
    static string Iso(long time) => DateTimeOffset.FromUnixTimeSeconds(time).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
    static JsonObject Obj(params (string, object?)[] pairs)
    {
        var result = new JsonObject(); foreach (var (key, value) in pairs) result[key] = value is JsonNode node ? node.DeepClone() : System.Text.Json.JsonSerializer.SerializeToNode(value); return result;
    }
    static byte[] Sign(Ed25519PrivateKeyParameters key, byte[] raw)
    {
        var signer = new Ed25519Signer(); signer.Init(true, key); signer.BlockUpdate(raw); return signer.GenerateSignature();
    }
    internal sealed class Transport(Server server) : HttpMessageHandler
    {
        protected override HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Equal(request.RequestUri!.OriginalString, "https://PAYLOAD.EXAMPLE.TEST/api/v1/client/gateway");
            Equal(request.Content!.Headers.ContentType!.MediaType, "application/json");
            return server.Reply(request.Content.ReadAsByteArrayAsync(cancellationToken).GetAwaiter().GetResult());
        }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => Task.FromResult(Send(request, cancellationToken));
    }
    internal sealed class Server
    {
        internal readonly Ed25519PrivateKeyParameters Signer = new(new SecureRandom());
        readonly X25519PrivateKeyParameters gateway = new(new SecureRandom());
        internal readonly Payload Payload;
        internal readonly byte[] Key, Seed = Enumerable.Repeat((byte)0x27, 32).ToArray();
        internal readonly JsonObject Config;
        internal readonly List<string> Calls = [];
        internal long Now = Read("payload-cache-v2.json")["proof_now"]!.GetValue<long>();
        internal string Mode = "", Code = "";
        internal long Grace = 120;
        internal ulong Id = 42;
        internal bool Trial, Floating;
        internal string? Expires = null;
        internal JsonObject Changes = [], GrantChanges = [];
        internal int InFlight, Maximum;
        internal ManualResetEventSlim? Entered, Proceed;
        internal string ObservedVersion = "";
        internal Server(Payload? original = null)
        {
            var cache = Read("payload-cache-v2.json"); Payload = original ?? AuthGo.Payload.ParsePayload(AuthGo.Client.Canonical(cache["payload"])); Key = H(cache, "content_key_hex");
            Config = (JsonObject)AuthGo.Client.Parse(AuthGo.Client.Decode(Payload.Config[8..])); Config["public_key"] = Convert.ToBase64String(Signer.GeneratePublicKey().GetEncoded());
            Config["gateway_key"] = AuthGo.Client.B64(gateway.GeneratePublicKey().GetEncoded()); Config["url"] = "https://PAYLOAD.EXAMPLE.TEST";
        }
        internal Client Client(string dir, string fp = Fingerprint) => new("authgo2." + AuthGo.Client.B64(Bytes(AuthGo.Client.Canonical(Config))), new ClientOptions
        { CacheDir = dir, Fingerprint = fp, Clock = () => DateTimeOffset.FromUnixTimeSeconds(Now), HttpClient = new HttpClient(new Transport(this)) });
        JsonObject Ticket(JsonObject body) => Obj(("v", 2), ("app_key", S(Config, "app_key")), ("challenge", S(body, "challenge")), ("license_id", Id),
            ("license_ref", "public-synthetic-ref"), ("device_hash", AuthGo.Client.Hash(Bytes(S(body, "device_fingerprint")))), ("status", "active"), ("issued_at", Iso(Now)),
            ("starts_at", null), ("expires_at", Expires), ("features", Obj(("export", true))), ("next_check_in", 10), ("grace_until", Iso(Now + Grace)),
            ("lease_expires_at", Floating ? Iso(Now + 20) : null), ("floating", Floating), ("is_trial", Trial), ("unlock_hash", AuthGo.Client.Hash(Seed)));
        internal string Signed(JsonObject grant)
        {
            byte[] raw = Bytes(AuthGo.Client.Canonical(grant)); return AuthGo.Client.B64(raw) + "." + AuthGo.Client.B64(Sign(Signer, [..Bytes("authgo-ticket-v2\0"), ..raw]));
        }
        internal HttpResponseMessage Reply(byte[] packet)
        {
            int flight = Interlocked.Increment(ref InFlight); Maximum = Math.Max(Maximum, flight);
            try
            {
                Calls.Add("transport");
                if (Mode == "network") throw new HttpRequestException("fixture unreachable");
                if (Mode is "status" or "html") return new(Mode == "status" ? HttpStatusCode.BadGateway : HttpStatusCode.OK) { Content = new ByteArrayContent(Bytes("<html>not signed</html>")) };
                var outer = (JsonObject)AuthGo.Client.Parse(packet);
                byte[] aad = Bytes("authgo-gateway-v2\0" + S(outer, "k") + "\0" + S(outer, "e"));
                byte[] shared = AuthGo.Client.Shared(gateway.GetEncoded(), AuthGo.Client.Decode(S(outer, "e"))), salt = Digest(aad);
                var inner = (JsonObject)AuthGo.Client.Parse(AuthGo.Client.Unpad(AuthGo.Client.Open(AuthGo.Client.Hkdf(shared, salt, Bytes("authgo/v2/request")), AuthGo.Client.Decode(S(outer, "n")), AuthGo.Client.Decode(S(outer, "c")), aad)));
                var body = inner["body"]!.AsObject();
                string op = S(inner, "op"), nonce = S(inner, "nonce");
                if (op != "payload.unlock") ObservedVersion = S(body, "client_version");
                Equal(S(inner, "signature"), Hex(HMACSHA256.HashData(Bytes(S(Config, "app_secret")), Bytes(op + S(inner, "timestamp") + nonce + AuthGo.Client.Hash(Bytes(AuthGo.Client.Canonical(body)))))));
                Equal(AuthGo.Client.Decode(S(body, "challenge")).Length, 32); Calls[^1] = op;
                var grant = Ticket(body); var data = Copy(grant);
                data["unlock_seed"] = AuthGo.Client.B64(Seed); data["request_nonce"] = nonce; data["heartbeat_interval"] = 5;
                data["satisfied_methods"] = Floating ? new JsonArray("KEY", "FLOATING") : new JsonArray("KEY");
                if (op == "activate") data["activation_token"] = "act_" + AuthGo.Client.B64(new byte[32]);
                if (op == "deactivate") data["deactivated"] = true;
                if (op == "release-seat") data["released"] = true;
                if (op == "payload.unlock")
                {
                    Check(body.Select(p => p.Key).ToHashSet().SetEquals(["license_key", "activation_token", "device_fingerprint", "instance_session", "payload", "ephemeral_public_key", "challenge"]));
                    Equal(S(body, "license_key"), License); Check(S(body, "activation_token").StartsWith("act_", StringComparison.Ordinal));
                    Same(AuthGo.Payload.ParsePayload(AuthGo.Client.Canonical(body["payload"])).PayloadBinding(), Payload.PayloadBinding());
                    if (Entered != null) { Entered.Set(); Check(Proceed!.Wait(TimeSpan.FromSeconds(5))); }
                    var pair = new X25519PrivateKeyParameters(new SecureRandom()); byte[] ephemeral = AuthGo.Client.Decode(S(body, "ephemeral_public_key"));
                    byte[] rewrap = Payload.RewrapAAD(ephemeral, AuthGo.Client.Decode(S(body, "challenge"))), n = RandomNumberGenerator.GetBytes(12);
                    byte[] kek = AuthGo.Client.Hkdf(AuthGo.Client.Shared(pair.GetEncoded(), ephemeral), Digest(rewrap), Bytes("authgo/payload/v1/rewrap"));
                    if (Payload.V == 2) data["watermark"] = string.Concat(Enumerable.Repeat("19", 32));
                    data["e"] = AuthGo.Client.B64(pair.GeneratePublicKey().GetEncoded()); data["n"] = AuthGo.Client.B64(n); data["c"] = AuthGo.Client.B64(AuthGo.Client.Seal(kek, n, Key, rewrap));
                    switch (Mode)
                    {
                        case "challenge": grant["challenge"] = AuthGo.Client.B64(new byte[32]); break;
                        case "license": grant["license_id"] = 41; data["license_id"] = 41; break;
                        case "seed": data["unlock_seed"] = AuthGo.Client.B64(new byte[32]); break;
                        case "issued": grant["issued_at"] = Iso(Now + 301); grant["grace_until"] = Iso(Now + 500); break;
                        case "wrap": data["c"] = AuthGo.Client.B64(new byte[48]); break;
                        case "missing-wrap": data.Remove("e"); break;
                        case "trial": grant["is_trial"] = true; break;
                        case "zero": grant["grace_until"] = grant["issued_at"]!.DeepClone(); break;
                    }
                }
                foreach (var entry in GrantChanges) grant[entry.Key] = entry.Value?.DeepClone(); data["ticket"] = Signed(grant);
                foreach (var entry in Changes) data[entry.Key] = entry.Value?.DeepClone();
                var env = Obj(("code", Code == "" ? "OK" : Code), ("data", data), ("ts", Now), ("nonce", nonce));
                env["signature"] = Convert.ToBase64String(Sign(Signer, Bytes(AuthGo.Client.Canonical(Obj(("code", env["code"]), ("data", data), ("ts", Now))))));
                if (Mode == "signature") env["signature"] = Convert.ToBase64String(new byte[64]);
                if (Mode == "watermark-tamper" && op == "payload.unlock") {
                    // Obj clones data: mutate the transmitted field after signing, before encryption.
                    ((JsonObject)env["data"]!)["watermark"] = string.Concat(Enumerable.Repeat("2a", 32));
                }
                if (Mode == "nonce") env["nonce"] = "wrong";
                byte[] rn = RandomNumberGenerator.GetBytes(12), context = [..aad, ..Bytes("\0" + AuthGo.Client.Hash(Bytes(S(outer, "n") + "." + S(outer, "c"))))];
                byte[] encrypted = AuthGo.Client.Seal(AuthGo.Client.Hkdf(shared, salt, Bytes("authgo/v2/response")), rn, AuthGo.Client.Pad(Bytes(AuthGo.Client.Canonical(env))), context);
                return new(HttpStatusCode.OK) { Content = new ByteArrayContent(Bytes(AuthGo.Client.Canonical(Obj(("n", AuthGo.Client.B64(rn)), ("c", AuthGo.Client.B64(encrypted)))))) };
            }
            finally { Interlocked.Decrement(ref InFlight); }
        }
    }
    sealed class Fixture : IDisposable
    {
        internal readonly string Dir = Path.Combine(Path.GetTempPath(), "authgo-payload-" + Guid.NewGuid().ToString("N"));
        internal readonly Server Server = new();
        internal readonly Client Client;
        internal Payload Payload => Server.Payload;
        internal Result Result = null!;
        internal Fixture() { Directory.CreateDirectory(Dir); Client = Server.Client(Dir); }
        internal Fixture Prime() { Result = Client.Check(License); Same(Client.UnlockPayload(Payload), Server.Key); return this; }
        internal string[] Caches() => Directory.GetFiles(Dir, "authgo-payload-v2-*.cache");
        public void Dispose() { Server.Proceed?.Set(); Directory.Delete(Dir, true); }
    }
    static Result GrantResult(Fixture f, JsonObject grant) => new(f.Client, grant, f.Server.Signed(grant), [], "online", double.PositiveInfinity);

    static void Vectors()
    {
        var v = Read("payload-unlock-v2.json"); var payload = Payload.ParsePayload(Client.Canonical(v["payload"]));
        byte[] privateKey = H(v, "client_private_hex"), ephemeral = new X25519PrivateKeyParameters(privateKey).GeneratePublicKey().GetEncoded(), challenge = H(v, "challenge_hex");
        Same(ephemeral, H(v, "client_public_hex")); byte[] aad = payload.RewrapAAD(ephemeral, challenge); Equal(Hex(aad), S(v, "rewrap_aad_hex"));
        byte[] shared = Client.Shared(privateKey, H(v, "server_public_hex")); Equal(Hex(shared), S(v, "shared_hex")); Equal(Client.Hash(aad), S(v, "salt_hex"));
        Equal(Hex(Client.Hkdf(shared, Digest(aad), Bytes("authgo/payload/v1/rewrap"))), S(v, "kek_hex"));
        var response = v["response"]!; Same(payload.Unwrap(new(S(response, "e"), S(response, "n"), S(response, "c")), privateKey, ephemeral, challenge), H(v, "content_key_hex"));
        var original = Read("payload-envelope.json"); var p = Payload.ParsePayload(Client.Canonical(original["payload"])); Equal(Hex(p.PayloadBinding()), S(original, "binding_hex"));
        byte[] envelope = [..p.AAD(), ..Client.Decode(p.Envelope.E)]; Equal(Hex(envelope), S(original, "envelope_aad_hex"));
        byte[] wrapShared = Client.Shared(H(original, "recipient_private_hex"), Client.Decode(p.Envelope.E)); Equal(Hex(wrapShared), S(original, "shared_hex")); Equal(Client.Hash(envelope), S(original, "salt_hex"));
        byte[] wrapKey = Client.Hkdf(wrapShared, Digest(envelope), Bytes("authgo/payload/v1/wrap")); Equal(Hex(wrapKey), S(original, "kek_hex"));
        Same(Client.Open(wrapKey, Client.Decode(p.Envelope.N), Client.Decode(p.Envelope.C), envelope), H(original, "content_key_hex"));
        var cache = Read("payload-cache-v2.json"); var cp = Payload.ParsePayload(Client.Canonical(cache["payload"])); byte[] label = cp.CacheLabel(S(cache, "fingerprint"));
        Equal(Hex(label), S(cache, "label_hex")); byte[] info = [..Bytes("authgo-unlock-v2\0"), ..label]; Equal(Hex(info), S(cache, "resource_info_hex"));
        byte[] key = Client.Hkdf(H(cache, "unlock_hash_hex"), [], info); Equal(Hex(key), S(cache, "cache_key_hex"));
        byte[] license = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(license, cache["license_id"]!.GetValue<ulong>());
        byte[] fileAAD = [..Bytes("authgo-payload-cache-file-v2\0"), ..Digest(label), ..license]; Equal(Hex(fileAAD), S(cache, "aad_hex"));
        byte[] cipher = Client.Seal(key, H(cache, "nonce_hex"), H(cache, "material_hex"), fileAAD); Equal(Hex(cipher), S(cache, "ciphertext_hex"));
        Equal(PayloadCache.Prefix + Client.B64([..H(cache, "nonce_hex"), ..cipher]), S(cache, "file_utf8"));
        using var f = new Fixture(); var options = new ClientOptions { CacheDir = f.Dir, Fingerprint = S(cache, "fingerprint"), Clock = () => DateTimeOffset.FromUnixTimeSeconds(cache["proof_now"]!.GetValue<long>()) };
        var client = new Client(cp.Config, options); Equal(client.PayloadCache.Identity, S(cache, "cache_identity_utf8"));
        var spelling = new PayloadCache(f.Dir, "HTTPS://EXAMPLE.TEST/Keep%2FPath?Case=YES", "app", Fingerprint, new byte[32]); Check(spelling.Identity.StartsWith("https://example.test/Keep%2FPath?Case=YES\0app\0", StringComparison.Ordinal));
        string ticket = S(cache, "ticket"); var grant = (JsonObject)Client.Parse(Client.Decode(ticket.Split('.')[0]));
        var result = new Result(client, grant, ticket, [], "online", double.PositiveInfinity);
        using var material = client.PayloadCache.Derive(cp, grant, options.Clock().ToUnixTimeSeconds(), false);
        Equal(Path.GetFileName(material.File), S(cache, "filename")); Same(material.Key, key); Same(material.AAD, fileAAD);
        File.WriteAllText(material.File, S(cache, "file_utf8")); SetMode(material.File, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        Same(client.LoadPayloadKey(cp, result), H(cache, "material_hex")); client.SavePayloadKey(cp, result, H(cache, "material_hex"));
        Same(client.LoadPayloadKey(cp, result), H(cache, "material_hex")); Equal(GetMode(material.File), UnixFileMode.UserRead | UnixFileMode.UserWrite);
        Check(!Directory.GetFiles(f.Dir).Any(path => Path.GetFileName(path).Contains("proof", StringComparison.Ordinal)));
        Console.WriteLine("{\"language\":\"csharp\",\"payload_vectors\":\"PASS\",\"vectors\":[\"payload-envelope\",\"payload-unlock-v2\",\"payload-cache-v2\"]}");
    }

    internal static Payload V2() => AuthGo.Payload.ParsePayload(Client.Canonical(Read("payload-cache-v2.json")["payload"]));
    static void WatermarkSignatureTamperV2()
    {
        var p = V2(); string dir = Path.Combine(Path.GetTempPath(), "authgo-v2-watermark-tamper-" + Guid.NewGuid()); Directory.CreateDirectory(dir);
        try {
            var server = new Server(p); var client = server.Client(dir); client.Check(License);
            Equal(Directory.GetFiles(dir, "authgo-payload-v*-*.cache").Length, 0);
            int before = server.Calls.Count; server.Mode = "watermark-tamper";
            Error("SDK_RESPONSE_SIGNATURE_INVALID", () => client.UnlockPayloadMaterial(p));
            Equal(Directory.GetFiles(dir, "authgo-payload-v*-*.cache").Length, 0);
            Error("SDK_RESPONSE_SIGNATURE_INVALID", () => client.UnlockPayload(p));
            Equal(Directory.GetFiles(dir, "authgo-payload-v*-*.cache").Length, 0);
            Check(server.Calls.Skip(before).SequenceEqual(new[] { "payload.unlock", "payload.unlock" }));
            server.Mode = ""; Same(client.UnlockPayloadMaterial(p), [..server.Key, ..Enumerable.Repeat((byte)0x19, 32)]);
        } finally { Directory.Delete(dir, true); }
    }

    static void WatermarkV2()
    {
        var p = V2(); Same(AuthGo.Payload.ParsePayload(Client.Canonical(p.ToJson())).PayloadBinding(), p.PayloadBinding());
        Check(Encoding.ASCII.GetString(p.AAD()).StartsWith("authgo-payload-envelope-v2\0", StringComparison.Ordinal));
        Error("PAYLOAD_INVALID", () => (p with { V = 99 }).Validated());
        var m = Client.Parse(Client.Decode(p.Manifest)); m["files"]!.AsArray().Last()!["main_class"] = "";
        Error("PAYLOAD_INVALID", () => (p with { Manifest = Client.B64(Bytes(Client.Canonical(m))) }).Validated());
        foreach (var bad in new[] { new string('0', 64), new string('A', 64), "1" }) Error("SDK_RESPONSE_INVALID", () => PayloadWatermark.Response(JsonValue.Create(bad)));
        string dir = Path.Combine(Path.GetTempPath(), "authgo-v2-" + Guid.NewGuid()); Directory.CreateDirectory(dir);
        try {
            var server = new Server(p); var client = server.Client(dir); var result = client.Check(License);
            Same(client.UnlockPayload(p), server.Key); byte[] material = client.UnlockPayloadMaterial(p);
            Same(material, [..server.Key, ..Convert.FromHexString(string.Concat(Enumerable.Repeat("19", 32)))]); Same(client.LoadPayloadKey(p, result), material);
            Check(Directory.GetFiles(dir, "authgo-payload-v2-*").Length == 1);
            var grant = (JsonObject)Client.Parse(Client.Decode(result.Ticket().Split('.')[0])); var otherGrant = (JsonObject)grant.DeepClone(); otherGrant["license_id"] = 43;
            Error("SDK_CACHE_INVALID", () => client.PayloadCache.Load(p, otherGrant, server.Now, false));
            using (var derived = client.PayloadCache.Derive(p, grant, server.Now, false)) {
                byte[] saved = File.ReadAllBytes(derived.File), nonce = RandomNumberGenerator.GetBytes(12);
                File.WriteAllText(derived.File, "AUTHGO-PAYLOAD-CACHE-v2." + Client.B64([..nonce, ..Client.Seal(derived.Key, nonce, server.Key, derived.AAD)]));
                Error("SDK_CACHE_INVALID", () => client.PayloadCache.Load(p, grant, server.Now, false)); File.WriteAllBytes(derived.File, saved);
            }
            server.Changes["watermark"] = new string('0', 64); Error("SDK_RESPONSE_INVALID", () => client.UnlockPayloadMaterial(p)); server.Changes.Clear();
            server.Mode = "network"; Same(client.UnlockPayloadMaterial(p), material); server.Now += 121; Error("SDK_NETWORK_ERROR", () => client.UnlockPayloadMaterial(p)); server.Now -= 121;
            server.Mode = ""; server.Code = "LICENSE_REVOKED"; Error("LICENSE_REVOKED", () => client.UnlockPayloadMaterial(p)); Check(Directory.GetFiles(dir, "authgo-payload-v2-*").Length == 0);
            Check(Directory.GetFiles(dir, "authgo-payload-v2-*").Length == 0);
            server.Code = ""; client.Check(License); server.Trial = true; client.UnlockPayloadMaterial(p); Check(Directory.GetFiles(dir, "authgo-payload-v2-*").Length == 0);
            CryptographicOperations.ZeroMemory(material);
        } finally { Directory.Delete(dir, true); }
        string tag = new('a', 32); byte[] target = Bytes(string.Concat(Enumerable.Repeat(tag + new string('0', 64), 8)));
        var files = new[] { new PayloadFiles.File("app", "dotnet", "00000000.agc", target.Length) };
        var offsets = new JsonArray(); for (int i = 0; i < 8; i++) offsets.Add((i * 96).ToString(CultureInfo.InvariantCulture));
        var index = Obj(("v", "1"), ("tag", tag), ("files", new JsonArray(Obj(("index", "0"), ("entries", new JsonArray(Obj(("path", new JsonArray("Main.dll")), ("offsets", offsets))))))));
        string raw = Client.Canonical(index); var parsed = PayloadWatermark.Parse(Bytes(raw), files);
        var targets = new Dictionary<string, byte[]> { ["Main.dll"] = target };
        target[^1] = (byte)'1'; Error("PAYLOAD_INVALID", () => PayloadWatermark.Prepare(targets, parsed, 0)); Equal(target[32], (byte)'0'); target[^1] = (byte)'0';
        PayloadWatermark.Apply(PayloadWatermark.Prepare(targets, parsed, 0), [..new byte[32], ..Enumerable.Repeat((byte)0x19, 32)]); Equal(Encoding.ASCII.GetString(target, 32, 64), string.Concat(Enumerable.Repeat("19", 32)));
        foreach (var bad in new[] { raw.Replace("\"v\":\"1\"", "\"v\":2", StringComparison.Ordinal), raw.Replace("Main.dll", "../Main.dll", StringComparison.Ordinal), raw.Replace("\"96\"", "\"95\"", StringComparison.Ordinal), raw.Replace("\"v\":\"1\"", "\"v\":\"1\",\"v\":\"1\"", StringComparison.Ordinal) }) Error("PAYLOAD_INVALID", () => PayloadWatermark.Parse(Bytes(bad), files));
    }

    public static void Run()
    {
        cases = 0;
        Case("cross-language vectors", Vectors);
        Case("v2 schema material cache refusal trial expiry and atomic slots", WatermarkV2);
        Case("v2 post-signature valid watermark tamper rejects signature without payload cache", WatermarkSignatureTamperV2);
        Case("NOT_ACTIVATED and restored cache", () => { using var f = new Fixture(); Error("SDK_NOT_ACTIVATED", () => f.Client.UnlockPayload(f.Payload)); Equal(f.Server.Calls.Count, 0);
            f.Client.Check(License); var restored = f.Server.Client(f.Dir); int calls = f.Server.Calls.Count; Error("SDK_NOT_ACTIVATED", () => restored.UnlockPayload(f.Payload)); Equal(f.Server.Calls.Count, calls); });
        Case("authenticated unlock encrypted files only", () => { using var f = new Fixture().Prime(); Equal(f.Caches().Length, 1); string file = f.Caches()[0], raw = File.ReadAllText(file);
            Check(raw.StartsWith(PayloadCache.Prefix, StringComparison.Ordinal)); Check(!raw.Contains(Client.B64(f.Server.Key), StringComparison.Ordinal)); Check(!file.Contains(License, StringComparison.Ordinal));
            Check(!Directory.GetFiles(f.Dir).Any(p => p.Contains("proof", StringComparison.Ordinal))); Error("SDK_CACHE_UNAVAILABLE", () => f.Client.LoadPayloadKey(f.Payload, new(f.Client, [], "", [], "offline", double.PositiveInfinity))); });
        Case("offline ticket avoids repeated network timeout", () => { using var f = new Fixture(); f.Server.Floating = true; f.Prime(); f.Server.Now += 25; f.Server.Mode = "network";
            Equal(f.Client.Check(License).Status, "grace"); int calls = f.Server.Calls.Count; Same(f.Client.UnlockPayload(f.Payload), f.Server.Key); Equal(f.Server.Calls.Count, calls);
            var restored = f.Server.Client(f.Dir); Equal(restored.Check(License).Status, "grace"); calls = f.Server.Calls.Count; Same(restored.UnlockPayload(f.Payload), f.Server.Key); Equal(f.Server.Calls.Count, calls); });
        Case("tamper permissions symlink and size", () => { using var f = new Fixture().Prime(); string file = f.Caches()[0]; byte[] raw = File.ReadAllBytes(file);
            File.WriteAllText(file, PayloadCache.Prefix + Client.B64(new byte[60])); Error("SDK_CACHE_INVALID", () => f.Client.LoadPayloadKey(f.Payload, f.Result)); File.WriteAllBytes(file, raw);
            SetMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead); Error("SDK_CACHE_UNAVAILABLE", () => f.Client.LoadPayloadKey(f.Payload, f.Result));
            SetMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite); File.WriteAllBytes(file, new byte[257]); Error("SDK_CACHE_UNAVAILABLE", () => f.Client.LoadPayloadKey(f.Payload, f.Result));
            File.Delete(file); string target = Path.Combine(f.Dir, "target"); File.WriteAllBytes(target, raw); SetMode(target, UnixFileMode.UserRead | UnixFileMode.UserWrite); File.CreateSymbolicLink(file, target);
            Error("SDK_CACHE_UNAVAILABLE", () => f.Client.LoadPayloadKey(f.Payload, f.Result)); f.Client.SavePayloadKey(f.Payload, f.Result, [..f.Server.Key, ..Enumerable.Repeat((byte)0x19, 32)]); Check(new FileInfo(file).LinkTarget != null); Same(File.ReadAllBytes(target), raw); });
        Case("atomic replacement and inode substitution", () => { using var f = new Fixture().Prime(); string file = f.Caches()[0]; byte[] raw = File.ReadAllBytes(file);
            var before = PayloadCache.Snapshot(file); using var opened = PayloadCache.OpenRead(file); string replacement = Path.Combine(f.Dir, "replacement"); File.WriteAllBytes(replacement, raw); SetMode(replacement, UnixFileMode.UserRead | UnixFileMode.UserWrite); File.Move(replacement, file, true);
            Error("SDK_CACHE_INVALID", () => PayloadCache.VerifyHandle(file, opened, before)); Same(f.Client.LoadPayloadKey(f.Payload, f.Result), [..f.Server.Key, ..Enumerable.Repeat((byte)0x19, 32)]);
            f.Client.SavePayloadKey(f.Payload, f.Result, new byte[1]); Same(File.ReadAllBytes(file), raw); Same(f.Client.UnlockPayload(f.Payload), f.Server.Key); Check(!Directory.GetFiles(f.Dir).Any(p => p.EndsWith(".tmp", StringComparison.Ordinal))); });
        Case("unwritable cache best effort", () => { using var f = new Fixture(); string file = Path.Combine(f.Dir, "not-directory"); File.WriteAllText(file, "file"); var c = f.Server.Client(file); c.Check(License); Same(c.UnlockPayload(f.Payload), f.Server.Key); });
        Case("memory cache never persists keys", () => { using var f = new Fixture(); var client = f.Server.Client(""); var result = client.Check(License); Same(client.UnlockPayload(f.Payload), f.Server.Key); Error("SDK_CACHE_UNAVAILABLE", () => client.LoadPayloadKey(f.Payload, result)); Equal(f.Caches().Length, 0); });
        Case("trial and zero grace clear old keys", () => { using var f = new Fixture().Prime(); foreach (string mode in new[] { "trial", "zero" }) { f.Server.Mode = ""; f.Client.Verify(); f.Client.UnlockPayload(f.Payload); Equal(f.Caches().Length, 1); f.Server.Mode = mode; Same(f.Client.UnlockPayload(f.Payload), f.Server.Key); Equal(f.Caches().Length, 0); } });
        Case("ordinary authorization and deactivate cleanup", () => { using var f = new Fixture().Prime(); f.Server.Trial = true; f.Client.Verify(); Equal(f.Caches().Length, 0); f.Server.Trial = false; f.Client.Verify(); f.Client.UnlockPayload(f.Payload); Equal(f.Caches().Length, 1); f.Client.Deactivate(); Equal(f.Caches().Length, 0); Error("SDK_NOT_ACTIVATED", () => f.Client.UnlockPayload(f.Payload)); });
        Case("cache scope proof untouched and license binding", () => { using var f = new Fixture().Prime(); var other = f.Server.Client(f.Dir, new string('b', 64)); other.Check(License); other.UnlockPayload(f.Payload);
            string proof = Path.Combine(f.Dir, "authgo-payload-proof-v1-untouched.cache"); File.WriteAllText(proof, "untouched"); var g = Copy(f.Result.Data); g["license_id"] = 43;
            Error("SDK_CACHE_INVALID", () => f.Client.LoadPayloadKey(f.Payload, GrantResult(f, g))); f.Client.ClearPayloadKeys(); Equal(f.Caches().Length, 1); Equal(File.ReadAllText(proof), "untouched"); });
        Case("cache expiry future issue and starts_at", () => { using var f = new Fixture().Prime(); var g = Copy(f.Result.Data); g["grace_until"] = Iso(f.Server.Now);
            Error("SDK_GRACE_EXPIRED", () => f.Client.LoadPayloadKey(f.Payload, GrantResult(f, g))); g["issued_at"] = Iso(f.Server.Now + 301); g["grace_until"] = Iso(f.Server.Now + 500);
            Error("SDK_GRACE_EXPIRED", () => f.Client.LoadPayloadKey(f.Payload, GrantResult(f, g))); g["issued_at"] = Iso(f.Server.Now); g["starts_at"] = Iso(f.Server.Now + 1); Error("LICENSE_NOT_STARTED", () => f.Client.LoadPayloadKey(f.Payload, GrantResult(f, g))); });
        Case("grace exact expiry license expiry and rollback", () => { using var f = new Fixture().Prime(); long initial = f.Server.Now; f.Server.Now += 120;
            Error("SDK_GRACE_EXPIRED", () => f.Client.LoadPayloadKey(f.Payload, f.Result)); f.Client.ClearPayloadKeys(); f.Client.SavePayloadKey(f.Payload, f.Result, [..f.Server.Key, ..Enumerable.Repeat((byte)0x19, 32)]); Equal(f.Caches().Length, 0);
            f.Server.Now = initial - 301; Error("SDK_CLOCK_ROLLBACK", () => f.Client.UnlockPayload(f.Payload)); f.Server.Now = initial; var g = Copy(f.Result.Data); g["expires_at"] = Iso(initial); Error("LICENSE_EXPIRED", () => f.Client.LoadPayloadKey(f.Payload, GrantResult(f, g))); });
        Case("authenticated refusals clear unlock verify heartbeat", () => { using var f = new Fixture(); foreach (string code in new[] { "LICENSE_REVOKED", "VERSION_DISABLED", "MAINTENANCE_EXPIRED", "UNKNOWN_NEW_REFUSAL" }) for (int op = 0; op < 3; op++) {
            f.Server.Code = ""; f.Prime(); f.Server.Code = code; int action = op; Error(code, () => { if (action == 0) f.Client.UnlockPayload(f.Payload); else if (action == 1) f.Client.Verify(); else f.Client.Heartbeat(); }); Equal(f.Caches().Length, 0); Error("SDK_NOT_ACTIVATED", () => f.Client.UnlockPayload(f.Payload)); } });
        Case("instance replacement preserves proof clears keys", () => { using var f = new Fixture().Prime(); var field = typeof(Client).GetField("state", BindingFlags.Instance | BindingFlags.NonPublic)!;
            var before = Copy((JsonObject)field.GetValue(f.Client)!); f.Server.Code = "INSTANCE_REPLACED"; Error("INSTANCE_REPLACED", () => f.Client.UnlockPayload(f.Payload)); Equal(f.Caches().Length, 0);
            Error("SDK_NOT_ACTIVATED", () => f.Client.UnlockPayload(f.Payload)); Error("INSTANCE_REPLACED", () => f.Client.Verify()); var after = (JsonObject)field.GetValue(f.Client)!; Equal(S(after, "ticket"), S(before, "ticket")); Equal(S(after, "seed"), S(before, "seed")); Check(after["refused"]?.GetValue<bool>() != true); });
        Case("PAYLOAD_INVALID and channel failures preserve caches", () => { using var f = new Fixture().Prime(); string file = f.Caches()[0]; byte[] raw = File.ReadAllBytes(file);
            foreach (string mode in new[] { "network", "status", "html", "signature", "nonce", "" }) { f.Server.Mode = mode; f.Server.Code = mode == "" ? "PAYLOAD_INVALID" : ""; Same(f.Client.UnlockPayload(f.Payload), f.Server.Key); Same(File.ReadAllBytes(file), raw); }
            f.Client.ClearPayloadKeys(); Error("PAYLOAD_INVALID", () => f.Client.UnlockPayload(f.Payload)); Check(Client.Temporary.Contains("PAYLOAD_INVALID")); });
        Case("wrap schema recovers null and invalid strings do not", () => { using var f = new Fixture().Prime(); foreach (object value in new object[] { 17, true, new JsonObject(), new JsonArray() }) { f.Server.Changes = Obj(("e", value)); Same(f.Client.UnlockPayload(f.Payload), f.Server.Key); }
            f.Server.Changes = []; f.Server.Mode = "missing-wrap"; Same(f.Client.UnlockPayload(f.Payload), f.Server.Key); f.Server.Mode = "";
            foreach (string? value in new string?[] { null, "bad", "=" }) { f.Server.Changes = Obj(("e", value)); Error("SDK_RESPONSE_INVALID", () => f.Client.UnlockPayload(f.Payload)); } });
        Case("fresh malformed ticket or unwrap never use cache", () => { using var f = new Fixture().Prime(); string file = f.Caches()[0]; byte[] raw = File.ReadAllBytes(file);
            foreach (string mode in new[] { "challenge", "license", "seed", "issued", "wrap" }) { f.Server.Mode = mode; Error(mode == "issued" ? "SDK_RESPONSE_TIMESTAMP_INVALID" : "SDK_RESPONSE_INVALID", () => f.Client.UnlockPayload(f.Payload)); Same(File.ReadAllBytes(file), raw); }
            f.Server.Mode = ""; f.Server.GrantChanges = Obj(("is_trial", "true")); Error("SDK_RESPONSE_INVALID", () => f.Client.UnlockPayload(f.Payload));
            f.Server.GrantChanges = []; f.Server.Changes = Obj(("ticket", "bad")); Error("SDK_RESPONSE_SIGNATURE_INVALID", () => f.Client.UnlockPayload(f.Payload)); });
        Case("copy rename into another instance rejected", () => { using var f = new Fixture().Prime(); var other = f.Server.Client(f.Dir, new string('c', 64)); var result = other.Check(License);
            using var material = other.PayloadCache.Derive(f.Payload, result.Data, f.Server.Now, false); File.Copy(f.Caches()[0], material.File); Error("SDK_CACHE_INVALID", () => other.LoadPayloadKey(f.Payload, result)); });
        Case("strict payload schemas duplicates aliases and config binding", () => { using var f = new Fixture(); var original = f.Payload.ToJson(); foreach (var entry in original) { var wrong = Copy(original); wrong.Remove(entry.Key); Error("PAYLOAD_INVALID", () => Payload.ParsePayload(Client.Canonical(wrong))); }
            foreach (string raw in new[] { "null", "[]", "{}", "{\"v\":2,\"v\":2}", new string('{', 66000) }) Error("PAYLOAD_INVALID", () => Payload.ParsePayload(raw));
            foreach (var entry in Obj(("v", true), ("key_id", "bad.key"), ("version", "1.2.3-01"), ("built_at", "2026-02-30T00:00:00Z"), ("app_key", new string('a', 257)), ("manifest", "__=="), ("App_Key", "wrong"), ("config", "authgo2.bad"))) { var wrong = Copy(original); wrong[entry.Key] = entry.Value?.DeepClone(); Error("PAYLOAD_INVALID", () => Payload.ParsePayload(Client.Canonical(wrong))); }
            var config = (JsonObject)Client.Parse(Client.Decode(f.Payload.Config[8..])); config["app_secret"] = "changed"; var changed = Copy(original); changed["config"] = "authgo2." + Client.B64(Bytes(Client.Canonical(config))); Check(!Payload.ParsePayload(Client.Canonical(changed)).PayloadBinding().SequenceEqual(f.Payload.PayloadBinding()));
            f.Prime(); config["app_key"] = "other-app"; changed["app_key"] = "other-app"; changed["config"] = "authgo2." + Client.B64(Bytes(Client.Canonical(config))); var wrongApp = Payload.ParsePayload(Client.Canonical(changed)); int calls = f.Server.Calls.Count; Error("PAYLOAD_INVALID", () => f.Client.UnlockPayload(wrongApp)); Equal(f.Server.Calls.Count, calls); });
        Case("JSON boundary integer spelling and exact 64-bit values", () => { using var f = new Fixture(); string raw = Client.Canonical(f.Payload.ToJson()); Payload.ParsePayload(raw + new string(' ', 65536 - Bytes(raw).Length)); Error("PAYLOAD_INVALID", () => Payload.ParsePayload(raw + new string(' ', 65537 - Bytes(raw).Length)));
            foreach (string token in new[] { "2.0", "2e0", "\"2\"" }) Error("PAYLOAD_INVALID", () => Payload.ParsePayload(raw.Replace("\"v\":2", "\"v\":" + token, StringComparison.Ordinal)));
            var manifest = (JsonObject)Client.Parse(Client.Decode(f.Payload.Manifest)); var file = manifest["files"]![0]!.AsObject(); foreach (var size in new JsonNode[] { JsonValue.Create("0")!, JsonValue.Create(-1)!, JsonNode.Parse("4611686018427387904")! }) { file["size"] = size.DeepClone(); var wrong = f.Payload.ToJson(); wrong["manifest"] = Client.B64(Bytes(Client.Canonical(manifest))); Error("PAYLOAD_INVALID", () => Payload.ParsePayload(Client.Canonical(wrong))); }
            file["size"] = JsonNode.Parse("4611686018427387903"); var good = f.Payload.ToJson(); good["manifest"] = Client.B64(Bytes(Client.Canonical(manifest))); Payload.ParsePayload(Client.Canonical(good));
            foreach (string field in new[] { "python_version", "main_class", "architecture" }) { var m = Copy(manifest); m["files"]![0]![field] = null; var wrong = f.Payload.ToJson(); wrong["manifest"] = Client.B64(Bytes(Client.Canonical(m))); Error("PAYLOAD_INVALID", () => Payload.ParsePayload(Client.Canonical(wrong))); }
            foreach (string date in new[] { "2026-02-29T00:00:00Z", "2026-11-07T24:00:00Z", "2026-11-07T00:60:00Z", "2026-11-07T00:00:60Z", "2026-11-07T00:00:00+00:00" }) { var wrong = f.Payload.ToJson(); wrong["built_at"] = date; Error("PAYLOAD_INVALID", () => Payload.ParsePayload(Client.Canonical(wrong))); }
            var leap = f.Payload.ToJson(); leap["built_at"] = "0000-02-29T00:00:00Z"; Payload.ParsePayload(Client.Canonical(leap));
            f.Server.Id = 9007199254740993; f.Prime(); Same(f.Client.LoadPayloadKey(f.Payload, f.Result), [..f.Server.Key, ..Enumerable.Repeat((byte)0x19, 32)]); using var material = f.Client.PayloadCache.Derive(f.Payload, f.Result.Data, f.Server.Now, false); Equal(BinaryPrimitives.ReadUInt64BigEndian(material.AAD.AsSpan(material.AAD.Length - 8)), f.Server.Id); });
        Case("Go HTTPS predicate not System.Uri normalization", () => { using var f = new Fixture(); var config = (JsonObject)Client.Parse(Client.Decode(f.Payload.Config[8..]));
            foreach (string url in new[] { "http://host", "https:host", "https:///host", "https://host\n", " https://host", "https://user@host", "https://host?x=1", "https://host#x", "https://host:abc", "https://ho%41st", "https://ho{st", "https://ho|st", "https://ho}st", "https://host/path%zz" }) foreach (string field in new[] { "url" }) { var c = Copy(config); c[field] = field == "url" ? JsonValue.Create(url) : new JsonArray(url); var wrong = f.Payload.ToJson(); wrong["config"] = "authgo2." + Client.B64(Bytes(Client.Canonical(c))); Error("PAYLOAD_INVALID", () => Payload.ParsePayload(Client.Canonical(wrong))); }
            foreach (string url in new[] { "HTTPS://host", "https://ho]st", "https://[syntactic-host]", "https://host:65536", "https://host:", "https://host/path space", "https://host/path?", "https://host#" }) { var c = Copy(config); c["url"] = url; var good = f.Payload.ToJson(); good["config"] = "authgo2." + Client.B64(Bytes(Client.Canonical(c))); Payload.ParsePayload(Client.Canonical(good)); } });
        Case("unwrap rejects altered binding low-order challenge", () => { var v = Read("payload-unlock-v2.json"); var p = Payload.ParsePayload(Client.Canonical(v["payload"])); var response = v["response"]!; var wrap = new PayloadEnvelope(S(response, "e"), S(response, "n"), S(response, "c")); byte[] priv = H(v, "client_private_hex"), ep = H(v, "client_public_hex"), challenge = H(v, "challenge_hex");
            Error("SDK_RESPONSE_INVALID", () => (p with { Version = "2.0.0" }).Unwrap(wrap, priv, ep, challenge)); Error("SDK_RESPONSE_INVALID", () => p.Unwrap(wrap with { E = Client.B64(new byte[32]) }, priv, ep, challenge)); Error("SDK_RESPONSE_INVALID", () => p.Unwrap(wrap, priv, ep, new byte[32])); });
        Case("concurrent unlock verify and clear serialized", () => { using var f = new Fixture().Prime(); var jobs = Enumerable.Range(0, 12).Select(i => Task.Run(() => { if (i % 3 == 0) f.Client.Verify(); else if (i % 3 == 1) Same(f.Client.UnlockPayload(f.Payload), f.Server.Key); else Same(f.Client.LoadPayloadKey(f.Payload, f.Result), [..f.Server.Key, ..Enumerable.Repeat((byte)0x19, 32)]); })).ToArray(); Check(Task.WaitAll(jobs, TimeSpan.FromSeconds(5))); Equal(f.Server.Maximum, 1);
            f.Server.Entered = new(); f.Server.Proceed = new(); var unlock = Task.Run(() => f.Client.UnlockPayload(f.Payload)); Check(f.Server.Entered.Wait(TimeSpan.FromSeconds(2))); using var started = new ManualResetEventSlim();
            var clear = Task.Run(() => { started.Set(); f.Client.ClearPayloadKeys(); }); Check(started.Wait(TimeSpan.FromSeconds(2))); f.Server.Proceed.Set(); Check(Task.WaitAll([unlock, clear], TimeSpan.FromSeconds(5))); Same(unlock.Result, f.Server.Key); Equal(f.Caches().Length, 0); });
        Case("release-seat refusal cleanup", () => { using var f = new Fixture(); f.Server.Floating = true; f.Prime(); f.Server.Code = "LICENSE_REVOKED"; Error("LICENSE_REVOKED", f.Client.ReleaseSeat); Equal(f.Caches().Length, 0); Error("SDK_NOT_ACTIVATED", () => f.Client.UnlockPayload(f.Payload)); });
        Console.WriteLine("{\"language\":\"csharp\",\"payload_tests\":\"PASS\",\"tests\":" + cases + "}");
    }
}
