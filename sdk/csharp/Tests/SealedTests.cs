using System.Buffers.Binary;
using System.Diagnostics;
using System.Formats.Tar;
using System.Reflection;
using System.Reflection.PortableExecutable;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using AuthGo;

static class SealedTests
{
    static int cases;
    const string Main = "AuthGoSealedMain", Dependency = "AuthGoSealedDependency", Marker = "AUTHGO_CSHARP_CORE_MEMORY_ONLY_7B";
    static readonly byte[] Key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
    static string FixturePath(string name) => Path.Combine(AppContext.BaseDirectory, "fixtures", name);
    static readonly string WatermarkTag = "0123456789abcdef0123456789abcdef";
    static byte[] FixtureBytes(string name) { var raw = File.ReadAllBytes(FixturePath(name)); return name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? [..raw, ..Client.Bytes(string.Concat(Enumerable.Repeat(WatermarkTag + new string('0', 64), 8)))] : raw; }
    static JsonNode Vector(string name) => Client.Parse(File.ReadAllBytes("sdk/vectors/" + name));
    static string S(JsonNode n, string name) => n[name]!.GetValue<string>();
    static byte[] H(JsonNode n, string name) => Convert.FromHexString(S(n, name));
    static void Check(bool ok) { if (!ok) throw new Exception("sealed assertion failed"); }
    static void Equal<T>(T a, T b) { if (!EqualityComparer<T>.Default.Equals(a, b)) throw new Exception($"sealed values differ: {a} != {b}"); }
    static void Same(byte[] a, byte[] b) => Check(a.AsSpan().SequenceEqual(b));
    static void Error(string code, Action action)
    {
        try { action(); throw new Exception("expected " + code); }
        catch (Exception error) when (HasCode(error, code)) { }
    }
    static bool HasCode(Exception error, string code)
    { for (Exception? e = error; e is not null; e = e.InnerException) if (e is AuthGoException auth && auth.Code == code) return true; return false; }
    static async Task Case(string name, Func<Task> test) { await test(); cases++; Console.WriteLine("sealed: " + name + " PASS"); }
    static Task Case(string name, Action test) => Case(name, () => { test(); return Task.CompletedTask; });

    sealed class Backend : IGuardBackend
    {
        internal readonly Client Client = new(Payload.ParsePayload(AuthGo.Client.Canonical(Vector("payload-cache-v2.json")["payload"])).Config,
            new ClientOptions { CacheDir = "", Fingerprint = new string('a', 64) });
        internal volatile string? Refused;
        internal int Validations, Unlocks;
        internal object? MustNotBeHeld;
        internal byte[]? Returned;
        internal ManualResetEventSlim? Entered, Proceed;
        public double Now => DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        internal Result Value() => new(Client, new JsonObject { ["features"] = new JsonObject(), ["next_check_in"] = 3600, ["floating"] = false }, "proof", new byte[32], "online", Now + 3600);
        public Result Verify() { Validate("proof"); return Value(); }
        public Result Heartbeat() => Verify();
        public void Validate(string ticket) { if (MustNotBeHeld is not null) Check(!Monitor.IsEntered(MustNotBeHeld)); Equal(ticket, "proof"); Interlocked.Increment(ref Validations); if (Refused is not null) throw new AuthGoException(Refused, true); }
        public void Release() { }
        public byte[] UnlockPayloadMaterial(Payload payload) { byte[] key = UnlockPayload(payload); Returned = [..key, ..Enumerable.Repeat((byte)0x19, 32)]; CryptographicOperations.ZeroMemory(key); return Returned; }
        public byte[] UnlockPayload(Payload payload)
        {
            Interlocked.Increment(ref Unlocks); Entered?.Set(); if (Proceed is not null) Check(Proceed.Wait(TimeSpan.FromSeconds(5)));
            Returned = Key.ToArray(); return Returned;
        }
    }
    sealed class Setup : IAsyncDisposable
    {
        internal readonly Backend Backend = new();
        internal readonly Guard Guard;
        readonly List<SealedLoadContext> contexts = [];
        internal Setup() { Guard = new Guard(Backend, Backend.Value()); }
        internal SealedLoadContext Open(params (byte[] Bytes, bool Primary)[] archives)
        { var c = SealedLoadContext.Open(Guard, archives); contexts.Add(c); return c; }
        internal SealedLoadContext OpenDefault() => Open((MainTar(), true), (DepTar(), false));
        public async ValueTask DisposeAsync()
        { foreach (var context in contexts) context.Dispose(); Backend.Proceed?.Set(); await Guard.DisposeAsync(); }
    }
    static byte[] Tar(params (string Name, byte[] Data)[] entries)
    {
        using var buffer = new MemoryStream();
        using (var writer = new TarWriter(buffer, TarEntryFormat.Ustar, leaveOpen: true))
            foreach (var entry in entries)
            {
                using var data = new MemoryStream(entry.Data, false);
                writer.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, entry.Name) { DataStream = data });
            }
        return buffer.ToArray();
    }
    static byte[] SpecialTar(TarEntryType type)
    {
        using var buffer = new MemoryStream();
        using (var writer = new TarWriter(buffer, TarEntryFormat.Ustar, leaveOpen: true))
        { var entry = new UstarTarEntry(type, "evil.dll"); if (type is TarEntryType.SymbolicLink or TarEntryType.HardLink) entry.LinkName = "outside.dll"; writer.WriteEntry(entry); }
        return buffer.ToArray();
    }
    static byte[] MainTar() => Tar((Main + ".dll", FixtureBytes(Main + ".dll")));
    static byte[] DepTar() => Tar((Dependency + ".dll", FixtureBytes(Dependency + ".dll")));
    static MethodInfo DependencyMethod(SealedLoadContext context) => context.MainAssembly.GetType("AuthGoSealedFixture.Entry")!.GetMethod("UseDependency")!;
    static Payload PayloadFor(params (byte[] Bytes, string Name, string Kind)[] entries)
    {
        var p = Vector("payload-envelope.json")["payload"]!.DeepClone(); var files = new JsonArray();
        for (int i = 0; i < entries.Length; i++) files.Add(new JsonObject {
            ["name"] = entries[i].Name, ["kind"] = entries[i].Kind, ["path"] = $"{i:D8}.agc", ["size"] = entries[i].Bytes.LongLength,
            ["chunk_size"] = 1 << 20, ["encoding"] = entries[i].Kind == "dotnet" ? "tar" : "raw"
        });
        files.Add(new JsonObject { ["name"] = "__authgo_watermark", ["kind"] = "watermark", ["path"] = $"{files.Count:D8}.agc", ["size"] = 1, ["chunk_size"] = 1 << 20, ["encoding"] = "raw" });
        p["manifest"] = Client.B64(Client.Bytes(Client.Canonical(new JsonObject { ["files"] = files })));
        return Payload.ParsePayload(Client.Canonical(p));
    }
    static byte[] Encrypt(Payload p, int index, byte[] plain)
    {
        using var output = new MemoryStream(); using var aes = new AesGcm(Key, 16);
        long count = Math.Max(1, (plain.LongLength + (1 << 20) - 1) / (1 << 20));
        for (long j = 0; j < count; j++)
        {
            int at = (int)(j * (1 << 20)), n = Math.Min(1 << 20, plain.Length - at);
            byte[] nonce = new byte[12]; BinaryPrimitives.WriteUInt32BigEndian(nonce, (uint)index); BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), (ulong)j);
            byte[] aad = [..Client.Bytes("authgo-payload-chunk-v1\0"), ..p.PayloadBinding(), ..nonce, (byte)(j == count - 1 ? 1 : 0)], ct = new byte[n], tag = new byte[16];
            aes.Encrypt(nonce, plain.AsSpan(at, n), ct, tag, aad); output.Write(ct); output.Write(tag);
        }
        return output.ToArray();
    }
    static Payload WritePayload(string directory)
    {
        byte[] main = MainTar(), dependency = DepTar(); var p = PayloadFor((main, "app", "dotnet"), (dependency, "dependency", "dotnet"));
        var privateFiles = new JsonArray(); var archives = new[] {main, dependency};
        for (int i = 0; i < archives.Length; i++) {
            var entries = new JsonArray(); using var reader = new TarReader(new MemoryStream(archives[i])); TarEntry? entry;
            while ((entry = reader.GetNextEntry()) is not null) { if (!entry.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) continue; using var bytes = new MemoryStream(); entry.DataStream!.CopyTo(bytes); var data = bytes.ToArray(); var offsets = new JsonArray(); byte[] needle = Client.Bytes(WatermarkTag + new string('0', 64)); for (int j = 0; j <= data.Length - 96; j++) if (data.AsSpan(j, 96).SequenceEqual(needle)) offsets.Add(j.ToString(System.Globalization.CultureInfo.InvariantCulture)); entries.Add(new JsonObject { ["path"] = new JsonArray(entry.Name), ["offsets"] = offsets }); }
            privateFiles.Add(new JsonObject { ["index"] = i.ToString(System.Globalization.CultureInfo.InvariantCulture), ["entries"] = entries });
        }
        byte[] privateIndex = Client.Bytes(Client.Canonical(new JsonObject { ["v"] = "1", ["tag"] = WatermarkTag, ["files"] = privateFiles }));
        var manifest = Client.Parse(Client.Decode(p.Manifest)); manifest["files"]!.AsArray().Last()!["size"] = privateIndex.Length; p = p with { Manifest = Client.B64(Client.Bytes(Client.Canonical(manifest))) };
        File.WriteAllText(Path.Combine(directory, "payload.json"), Client.Canonical(p.ToJson()));
        File.WriteAllBytes(Path.Combine(directory, "00000002.agc"), Encrypt(p, 2, privateIndex));
        File.WriteAllBytes(Path.Combine(directory, "00000000.agc"), Encrypt(p, 0, main)); File.WriteAllBytes(Path.Combine(directory, "00000001.agc"), Encrypt(p, 1, dependency));
        return p;
    }
    static string Temp() { string dir = Path.Combine(Path.GetTempPath(), "authgo-sealed-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(dir); return dir; }

    static void Chunks()
    {
        var v = Vector("payload-envelope.json"); var p = Payload.ParsePayload(Client.Canonical(v["payload"]));
        Equal(Convert.ToHexString(p.PayloadBinding()).ToLowerInvariant(), S(v, "binding_hex"));
        var cts = new Dictionary<int, MemoryStream>(); var plains = new Dictionary<int, MemoryStream>();
        foreach (var item in v["chunks"]!.AsArray())
        {
            var chunk = item!; int index = chunk["file"]!.GetValue<int>(); long j = chunk["chunk"]!.GetValue<long>();
            byte[] plain = chunk["plain_hex"] is not null ? H(chunk, "plain_hex") : Enumerable.Repeat(H(chunk, "plain_repeat_hex")[0], chunk["plain_repeat_count"]!.GetValue<int>()).ToArray();
            byte[] nonce = new byte[12]; BinaryPrimitives.WriteUInt32BigEndian(nonce, (uint)index); BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), (ulong)j);
            byte[] aad = [..Client.Bytes("authgo-payload-chunk-v1\0"), ..p.PayloadBinding(), ..nonce, (byte)(chunk["last"]!.GetValue<bool>() ? 1 : 0)];
            Same(nonce, H(chunk, "nonce_hex")); Same(aad, H(chunk, "aad_hex"));
            byte[] ct = new byte[plain.Length], tag = new byte[16]; using (var aes = new AesGcm(H(v, "content_key_hex"), 16)) aes.Encrypt(nonce, plain, ct, tag, aad);
            byte[] full = [..ct, ..tag];
            if (chunk["cipher_hex"] is not null) Same(full, H(chunk, "cipher_hex"));
            else { Same(full[..32], H(chunk, "cipher_first32_hex")); Same(tag, H(chunk, "tag_hex")); Equal(Client.Hash(full), S(chunk, "cipher_sha256_hex")); }
            if (!cts.ContainsKey(index)) { cts[index] = new MemoryStream(); plains[index] = new MemoryStream(); }
            cts[index].Write(full); plains[index].Write(plain);
        }
        foreach (var (index, ct) in cts)
        {
            using var output = new MemoryStream(); PayloadFiles.DecryptPayloadFile(output, ct.ToArray(), p, H(v, "content_key_hex"), index);
            Same(output.ToArray(), plains[index].ToArray()); Equal(PayloadFiles.PayloadCipherSize(output.Length), ct.Length);
        }
        Console.WriteLine("{\"language\":\"csharp\",\"payload_chunks\":\"PASS\",\"vector\":\"payload-envelope\"}");
    }
    sealed class BoundedInput(byte[] data) : MemoryStream(data, false)
    {
        public override int Read(byte[] buffer, int offset, int count) { Check(count <= (1 << 20) + 16); return base.Read(buffer, offset, count); }
        public override int Read(Span<byte> buffer) { Check(buffer.Length <= (1 << 20) + 16); return base.Read(buffer); }
    }
    public static async Task<int> RunProbe(string[] args)
    {
        string directory = Environment.GetEnvironmentVariable("AUTHGO_PAYLOAD_DIR")!;
        var p = Payload.ParsePayload(File.ReadAllBytes(Path.Combine(directory, "payload.json")));
        var server = new PayloadTests.Server(p); if (args.Contains("refuse")) server.Code = "LICENSE_REVOKED";
        bool runningRefuse = args.Contains("running-refuse");
        if (runningRefuse)
        {
            server.GrantChanges["next_check_in"] = 1; server.Changes["next_check_in"] = 1;
            AppContext.SetData("authgo.sealed.started", (Action)(() => { server.Code = "LICENSE_REVOKED";  }));
        }
        var elapsed = Stopwatch.StartNew();
        var options = new GuardOptions {
            Config = "authgo2." + Client.B64(Client.Bytes(Client.Canonical(server.Config))), License = "AUTH-RNMSQ-VSQQA-4S4NH-JDGCM", Version = "999.0.0",
            SDKOptions = new ClientOptions { Fingerprint = new string('a', 64), CacheDir = "", Clock = () => DateTimeOffset.FromUnixTimeSeconds(server.Now + (runningRefuse ? elapsed.ElapsedMilliseconds / 1000 : 0)), HttpClient = new HttpClient(new PayloadTests.Transport(server)) }
        };
        AppDomain.CurrentDomain.ProcessExit += (_, _) => Console.WriteLine("BOOT_VERSION=" + server.ObservedVersion);
        try { return await Bootstrap.RunAsync(options, args.Contains("throw") ? ["throw"] : runningRefuse ? ["running-refuse"] : ["worker", "argument"]); }
        catch (InvalidOperationException error) when (args.Contains("throw") && error.Message == "business failure preserved")
        { Console.WriteLine("BUSINESS_EXCEPTION_PRESERVED"); return 19; }
    }
    static async Task Probe(bool refuse, bool businessError = false, bool runningRefuse = false)
    {
        string dir = Temp();
        try
        {
            var p = WritePayload(dir);
            var start = new ProcessStartInfo("dotnet") { RedirectStandardOutput = true, RedirectStandardError = true };
            start.ArgumentList.Add(typeof(SealedTests).Assembly.Location); start.ArgumentList.Add("sealed-bootstrap-probe"); if (refuse) start.ArgumentList.Add("refuse"); if (businessError) start.ArgumentList.Add("throw"); if (runningRefuse) start.ArgumentList.Add("running-refuse");
            start.Environment["AUTHGO_PAYLOAD_DIR"] = dir;
            using var process = Process.Start(start)!;
            var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync();
            try { await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20)); } catch { process.Kill(true); throw; }
            string output = await stdout + await stderr;
            if (refuse || runningRefuse) { Equal(process.ExitCode, 77); Check(output.Contains("LICENSE_REVOKED", StringComparison.Ordinal)); if (runningRefuse) Check(output.Contains("SEALED_RESULT=" + Marker, StringComparison.Ordinal)); }
            else if (businessError) { Equal(process.ExitCode, 19); Check(output.Contains("BUSINESS_EXCEPTION_PRESERVED", StringComparison.Ordinal)); }
            else
            {
                if (process.ExitCode != 7 || !output.Contains("SEALED_RESULT=" + Marker, StringComparison.Ordinal) || !output.Contains("BOOT_WORKER=True", StringComparison.Ordinal) || !output.Contains("BOOT_VERSION=" + p.Version, StringComparison.Ordinal)) throw new Exception("Bootstrap probe: " + output);
            }
            Check(!output.Contains("AUTH-RNMSQ", StringComparison.Ordinal)); Check(!output.Contains("authgo2.", StringComparison.Ordinal));
        }
        finally { Directory.Delete(dir, true); }
    }

    static async Task WatermarkLoaderV2()
    {
        await using var setup = new Setup(); byte[] dependency = FixtureBytes(Dependency + ".dll");
        string tag = new('a', 32); var offsets = new JsonArray();
        for (int slot = 0; slot < 8; slot++) {
            byte[] marker = Client.Bytes("c0dec0dec0dec0de" + slot.ToString("x16", System.Globalization.CultureInfo.InvariantCulture) + new string('0', 64));
            int found = -1;
            for (int i = 0; i <= dependency.Length - marker.Length; i++) if (dependency.AsSpan(i, marker.Length).SequenceEqual(marker)) { Check(found < 0); found = i; }
            Check(found >= 0); Client.Bytes(tag).CopyTo(dependency, found); offsets.Add(found.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }
        var sorted = offsets.Select(n => long.Parse(n!.GetValue<string>(), System.Globalization.CultureInfo.InvariantCulture)).OrderBy(n => n).ToArray();
        var wireOffsets = new JsonArray(); foreach (long n in sorted) wireOffsets.Add(n.ToString(System.Globalization.CultureInfo.InvariantCulture));
        var raw = new JsonObject { ["v"] = "1", ["tag"] = tag, ["files"] = new JsonArray(new JsonObject { ["index"] = "0", ["entries"] = new JsonArray(new JsonObject { ["path"] = new JsonArray(Dependency + ".dll"), ["offsets"] = wireOffsets }) }) };
        var index = PayloadWatermark.Parse(Client.Bytes(Client.Canonical(raw)), [new PayloadFiles.File("dependency", "dotnet", "00000000.agc", dependency.Length)]);
        byte[] material = [..Key, ..Enumerable.Repeat((byte)0x19, 32)];
        using var context = SealedLoadContext.Open(setup.Guard, [(MainTar(), true), (Tar((Dependency + ".dll", dependency)), false)], targets => {
            var pending = PayloadWatermark.Prepare(targets[1], index, 0); PayloadWatermark.Apply(pending, material);
        });
        var assembly = context.LoadFromAssemblyName(new AssemblyName(Dependency));
        var values = (byte[][])assembly.GetType("AuthGoSealedFixture.WatermarkProbe", true)!.GetMethod("Read")!.Invoke(null, null)!;
        foreach (var value in values) Equal(Encoding.ASCII.GetString(value, 32, 64), string.Concat(Enumerable.Repeat("19", 32)));
        CryptographicOperations.ZeroMemory(material); CryptographicOperations.ZeroMemory(dependency);
    }

    public static async Task Run()
    {
        await Case("v2 PE exact raw bytes patched before LoadFromStream", WatermarkLoaderV2);
        await Case("Go chunk vectors", Chunks);
        await Case("IL-only metadata and empty Assembly.Location", async () => { await using var f = new Setup(); using var context = f.OpenDefault(); var a = context.MainAssembly; Equal(a.GetName().Name, Main); Equal(a.Location, ""); Check(a.EntryPoint is not null); Check(AssemblyLoadContext.GetLoadContext(a) == context); });
        await Case("private dependency resolves in the same memory context", async () => { await using var f = new Setup(); var c = f.OpenDefault(); Equal(DependencyMethod(c).Invoke(null, null), Marker); var d = c.LoadAssembly(new AssemblyName(Dependency)); Check(AssemblyLoadContext.GetLoadContext(d) == c); });
        await Case("public SDK identity shared instead of a second guard", async () => { await using var f = new Setup(); var c = f.OpenDefault(); Check(c.LoadAssembly(typeof(Guard).Assembly.GetName()) == typeof(Guard).Assembly); });
        await Case("parallel loading returns one assembly", async () => { await using var f = new Setup(); var c = f.OpenDefault(); var values = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(() => c.MainAssembly))); Check(values.All(v => ReferenceEquals(v, values[0]))); });
        await Case("parallel private dependency loading is serialized", async () => { await using var f = new Setup(); var c = f.OpenDefault(); var values = await Task.WhenAll(Enumerable.Range(0, 24).Select(_ => Task.Run(() => c.LoadAssembly(new AssemblyName(Dependency))))); Check(values.All(v => ReferenceEquals(v, values[0]))); });
        await Case("dependency gates never hold the context lifecycle lock", async () => {
            await using var f = new Setup(); var c = f.OpenDefault();
            f.Backend.MustNotBeHeld = typeof(SealedLoadContext).GetField("gate", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(c)!;
            Equal(DependencyMethod(c).Invoke(null, null), Marker);
        });
        await Case("refusal blocks main, private dependency and runtime resolve", async () => { await using var f = new Setup(); var c = f.OpenDefault(); var method = DependencyMethod(c); Check(!c.Assemblies.Any(a => a.GetName().Name == Dependency)); f.Backend.Refused = "LICENSE_REVOKED"; Error("LICENSE_REVOKED", () => c.LoadAssembly(new AssemblyName(Dependency))); Error("LICENSE_REVOKED", () => _ = c.MainAssembly); Error("LICENSE_REVOKED", () => method.Invoke(null, null)); });
        await Case("closed guard and context reject loads", async () => { await using var f = new Setup(); var c = f.OpenDefault(); c.Dispose(); Error("SDK_NOT_ACTIVATED", () => _ = c.MainAssembly); await f.Guard.DisposeAsync(); Error("SDK_NOT_ACTIVATED", () => f.OpenDefault()); });
        await Case("assembly identity version mismatch rejected", async () => { await using var f = new Setup(); var c = f.OpenDefault(); foreach (string identity in new[] { Dependency + ", Version=9.0.0.0", Dependency + ", Culture=fr", Dependency + ", PublicKeyToken=abcdef1234567890" }) Error("PAYLOAD_INVALID", () => c.LoadAssembly(new AssemblyName(identity))); });
        await Case("duplicate paths and assembly identities rejected", async () => { await using var f = new Setup(); Error("PAYLOAD_INVALID", () => f.Open((Tar((Main + ".dll", FixtureBytes(Main + ".dll")), (Main + ".dll", FixtureBytes(Main + ".dll"))), true))); Error("PAYLOAD_INVALID", () => f.Open((MainTar(), true), (MainTar(), false))); });
        await Case("unsafe tar paths symlinks and devices rejected", async () => { await using var f = new Setup(); foreach (var path in new[] { "../outside.dll", "/outside.dll", "a/../x.dll", "a//x.dll", "a\\x.dll", "a:x.dll" }) Error("PAYLOAD_INVALID", () => f.Open((Tar((path, FixtureBytes(Main + ".dll"))), true))); foreach (var type in new[] { TarEntryType.SymbolicLink, TarEntryType.HardLink, TarEntryType.Fifo }) Error("PAYLOAD_INVALID", () => f.Open((SpecialTar(type), true))); });
        await Case("raw native and mixed-mode PE rejected", async () => { await using var f = new Setup(); Error("PAYLOAD_INVALID", () => f.Open((Tar(("native.dll", [0x4d, 0x5a, 0])), true))); var data = FixtureBytes(Main + ".dll"); using var pe = new PEReader(new MemoryStream(data, false)); int at = pe.PEHeaders.CorHeaderStartOffset + 16; var mixed = data.ToArray(); BinaryPrimitives.WriteUInt32LittleEndian(mixed.AsSpan(at), BinaryPrimitives.ReadUInt32LittleEndian(mixed.AsSpan(at)) & ~1u); Error("PAYLOAD_INVALID", () => f.Open((Tar((Main + ".dll", mixed)), true))); });
        await Case("PInvoke and deps.json native assets rejected", async () => { await using var f = new Setup(); Error("PAYLOAD_INVALID", () => f.Open((Tar(("native.dll", FixtureBytes("AuthGoSealedNative.dll"))), true))); foreach (var json in new[] { "{\"native\":{}}", "{\"runtimeTargets\":{\"library\":{\"assetType\":\"native\"}}}" }) Error("PAYLOAD_INVALID", () => f.Open((Tar((Main + ".dll", FixtureBytes(Main + ".dll")), (Main + ".deps.json", Client.Bytes(json))), true))); });
        await Case("metadata signature and native entry flags rejected", async () => {
            await using var f = new Setup(); byte[] raw = FixtureBytes(Main + ".dll"); using var pe = new PEReader(new MemoryStream(raw, false));
            byte[] bad = raw.ToArray(); bad[pe.PEHeaders.MetadataStartOffset] ^= 1;
            Error("PAYLOAD_INVALID", () => f.Open((Tar((Main + ".dll", bad)), true)));
            byte[] native = raw.ToArray(); int flags = pe.PEHeaders.CorHeaderStartOffset + 16;
            BinaryPrimitives.WriteUInt32LittleEndian(native.AsSpan(flags), BinaryPrimitives.ReadUInt32LittleEndian(native.AsSpan(flags)) | 16u);
            Error("PAYLOAD_INVALID", () => f.Open((Tar((Main + ".dll", native)), true)));
        });
        await Case("malformed dependency JSON cannot become a server response error", async () => {
            await using var f = new Setup(); Error("PAYLOAD_INVALID", () => f.Open((Tar((Main + ".dll", FixtureBytes(Main + ".dll")), (Main + ".deps.json", Client.Bytes("{broken"))), true)));
        });
        await Case("SDK payload copy and missing executable entry rejected", async () => { await using var f = new Setup(); Error("PAYLOAD_INVALID", () => f.Open((Tar(("AuthGo.dll", File.ReadAllBytes(typeof(Guard).Assembly.Location))), true))); Error("PAYLOAD_INVALID", () => f.Open((DepTar(), true))); });
        await Case("managed .deps.json accepted without filesystem resolution", async () => { await using var f = new Setup(); var c = f.Open((Tar((Main + ".dll", FixtureBytes(Main + ".dll")), (Main + ".deps.json", FixtureBytes(Main + ".deps.json"))), true), (DepTar(), false)); Equal(DependencyMethod(c).Invoke(null, null), Marker); });
        await Case("chunk lengths keys and index validated", () => { byte[] plain = Client.Bytes("abc"); var p = PayloadFor((plain, "app", "node")); var ct = Encrypt(p, 0, plain); foreach (var bad in new[] { ct[..^1], ct.Concat(new byte[1]).ToArray(), new byte[ct.Length] }) Error("PAYLOAD_INVALID", () => PayloadFiles.DecryptPayloadFile(new MemoryStream(), bad, p, Key, 0)); Error("PAYLOAD_INVALID", () => PayloadFiles.DecryptPayloadFile(new MemoryStream(), ct, p, new byte[32], 0)); Error("PAYLOAD_INVALID", () => PayloadFiles.DecryptPayloadFile(new MemoryStream(), ct, p, Key, -1)); foreach (long bad in new[] { -1L, long.MaxValue }) Error("PAYLOAD_INVALID", () => PayloadFiles.PayloadCipherSize(bad)); });
        await Case("only authenticated blocks emitted on last-block corruption", () => { byte[] plain = new byte[(1 << 20) + 3]; var p = PayloadFor((plain, "app", "node")); var ct = Encrypt(p, 0, plain); ct[^1] ^= 1; using var output = new MemoryStream(); Error("PAYLOAD_INVALID", () => PayloadFiles.DecryptPayloadFile(output, ct, p, Key, 0)); Equal(output.Length, 1L << 20); });
        await Case("nonce and binding prevent block reordering and substitution", () => { byte[] plain = new byte[3 << 20]; var p = PayloadFor((plain, "app", "node")); var ct = Encrypt(p, 0, plain); int stride = (1 << 20) + 16; byte[] reordered = [..ct[stride..(2 * stride)], ..ct[..stride], ..ct[(2 * stride)..]]; Error("PAYLOAD_INVALID", () => PayloadFiles.DecryptPayloadFile(new MemoryStream(), reordered, p, Key, 0)); var obj = p.ToJson(); obj["version"] = "2.0.0"; Error("PAYLOAD_INVALID", () => PayloadFiles.DecryptPayloadFile(new MemoryStream(), ct, Payload.ParsePayload(Client.Canonical(obj)), Key, 0)); });
        await Case("stream input and output remain chunk-bounded", () => { byte[] plain = new byte[(2 << 20) + 9]; var p = PayloadFor((plain, "app", "node")); var ct = Encrypt(p, 0, plain); using var input = new BoundedInput(ct); using var output = new MemoryStream(); PayloadFiles.DecryptPayloadFile(output, input, ct.Length, p, Key, 0); Same(output.ToArray(), plain); });
        await Case("Bootstrap reads only ciphertext and clears returned content key", async () => { await using var f = new Setup(); string dir = Temp(); try { WritePayload(dir); var before = Directory.GetFiles(dir).ToDictionary(path => path, File.ReadAllBytes); using var c = Bootstrap.Load(f.Guard, "app", dir); Equal(DependencyMethod(c).Invoke(null, null), Marker); Equal(f.Backend.Unlocks, 1); Same(f.Backend.Returned!, new byte[64]); Equal(Directory.GetFiles(dir).Length, before.Count); foreach (var file in before) { Same(File.ReadAllBytes(file.Key), file.Value); Check(!Encoding.Latin1.GetString(file.Value).Contains(Marker, StringComparison.Ordinal)); } } finally { Directory.Delete(dir, true); } });
        await Case("refusal during key acquisition cannot publish assemblies", async () => { await using var f = new Setup(); string dir = Temp(); try { WritePayload(dir); f.Backend.Entered = new(false); f.Backend.Proceed = new(false); var loading = Task.Run(() => Bootstrap.Load(f.Guard, "app", dir)); Check(f.Backend.Entered.Wait(TimeSpan.FromSeconds(2))); f.Backend.Refused = "LICENSE_REVOKED"; f.Backend.Proceed.Set(); try { using var ignored = await loading; throw new Exception("expected refusal"); } catch (AuthGoException error) { Equal(error.Code, "LICENSE_REVOKED"); } Same(f.Backend.Returned!, new byte[64]); } finally { f.Backend.Proceed?.Set(); Directory.Delete(dir, true); } });
        await Case("entry invocation checks guard before executing", async () => { await using var f = new Setup(); var c = f.OpenDefault(); f.Backend.Refused = "LICENSE_REVOKED"; try { await Bootstrap.InvokeAsync(f.Guard, c, []); throw new Exception("expected refusal"); } catch (AuthGoException error) { Equal(error.Code, "LICENSE_REVOKED"); } });
        await Case("real Bootstrap entry with authenticated HTTP seam and async return", () => Probe(false));
        await Case("Bootstrap authenticated refusal returns 77 and hides credentials", () => Probe(true));
        await Case("running Bootstrap exits 77 on authenticated refusal", () => Probe(false, runningRefuse: true));
        await Case("business entry exception keeps its original type", () => Probe(false, true));
        await Case("safe customer diagnostics do not expose exception contents", () => Check(!Bootstrap.Message(new Exception("PRIVATE-CONTENT")).Contains("PRIVATE-CONTENT", StringComparison.Ordinal)));
        Console.WriteLine("{\"language\":\"csharp\",\"sealed_tests\":" + cases + ",\"result\":\"PASS\"}");
    }
}
