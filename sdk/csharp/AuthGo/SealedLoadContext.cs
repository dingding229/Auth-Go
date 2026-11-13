using System.Formats.Tar;
using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace AuthGo;

internal sealed class SealedFormatException(string message) : Exception(message);

/// <summary>A collectible in-memory IL-only assembly context. Not a security sandbox.</summary>
public sealed class SealedLoadContext : AssemblyLoadContext, IDisposable
{
    sealed record Image(AssemblyName Identity, byte[] Bytes, bool Entry);
    readonly Guard guard;
    readonly object gate = new();
    readonly Dictionary<string, Image> images;
    readonly Dictionary<string, Lazy<Assembly>> loaded = new(StringComparer.OrdinalIgnoreCase);
    readonly string main;
    bool closed;
    static readonly string sdkName = typeof(Guard).Assembly.GetName().Name!;
    static readonly HashSet<string> platform = ((string?)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES") ?? "")
        .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries).Select(Path.GetFileNameWithoutExtension)
        .Where(n => n is not null).Select(n => n!).ToHashSet(StringComparer.OrdinalIgnoreCase);

    SealedLoadContext(Guard guard, Dictionary<string, Image> images, string main)
        : base("authgo-sealed-" + Guid.NewGuid().ToString("N"), isCollectible: true)
    {
        this.guard = guard; this.images = images; this.main = main;
        Resolving += Resolve;
        ResolvingUnmanagedDll += (_, _) => throw Unsupported("代码加密不支持原生依赖");
    }
    internal static AuthGoException Unsupported(string message) => new("PAYLOAD_INVALID", false, new SealedFormatException(message));
    void Active() { guard.Require(); lock (gate) if (closed) throw new AuthGoException("SDK_NOT_ACTIVATED"); }

    internal static (AssemblyName Identity, bool Entry) Inspect(byte[] bytes)
    {
        try
        {
            using var source = new MemoryStream(bytes, false);
            using var pe = new PEReader(source);
            var header = pe.PEHeaders.CorHeader;
            if (!pe.HasMetadata || header is null || (header.Flags & CorFlags.ILOnly) == 0 ||
                (header.Flags & CorFlags.NativeEntryPoint) != 0 || header.ManagedNativeHeaderDirectory.Size != 0)
                throw Unsupported("仅支持 IL-only 托管程序集，不支持原生或混合模式");
            var content = pe.GetMetadata().GetContent();
            if (content.Length < 4 || content[0] != (byte)'B' || content[1] != (byte)'S' || content[2] != (byte)'J' || content[3] != (byte)'B')
                throw Payload.Invalid();
            var metadata = pe.GetMetadataReader();
            if (!metadata.IsAssembly) throw Payload.Invalid();
            foreach (var handle in metadata.MethodDefinitions)
                if ((metadata.GetMethodDefinition(handle).Attributes & MethodAttributes.PinvokeImpl) != 0)
                    throw Unsupported("代码加密不支持 P/Invoke 原生依赖");
            var assembly = metadata.GetAssemblyDefinition();
            string name = metadata.GetString(assembly.Name);
            if (string.IsNullOrWhiteSpace(name) || name.IndexOfAny(['/', '\\', '\0']) >= 0) throw Payload.Invalid();
            var identity = new AssemblyName { Name = name, Version = assembly.Version,
                CultureName = assembly.Culture.IsNil ? null : metadata.GetString(assembly.Culture) };
            if (!assembly.PublicKey.IsNil) identity.SetPublicKey(metadata.GetBlobBytes(assembly.PublicKey));
            return (identity, header.EntryPointTokenOrRelativeVirtualAddress != 0);
        }
        catch (AuthGoException) { throw; }
        catch { throw Payload.Invalid(); }
    }

    static bool Native(JsonNode? value) => value switch
    {
        JsonObject obj => obj.Any(entry => entry.Key == "native" || Native(entry.Value)),
        JsonArray array => array.Any(Native),
        JsonValue scalar when scalar.TryGetValue<string>(out var text) => text == "native",
        _ => false
    };
    static void SafePath(string path)
    {
        if (string.IsNullOrEmpty(path) || path.StartsWith('/') || path.IndexOfAny(['\\', ':', '\0']) >= 0 ||
            path.Split('/').Any(p => p is "" or "." or "..")) throw Payload.Invalid();
    }
    static string Archive(Guard guard, Stream source, Dictionary<string, Image> images, bool primary, Dictionary<string, byte[]> targets)
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string? entryName = null;
        using var reader = new TarReader(source, leaveOpen: true);
        while (reader.GetNextEntry(copyData: false) is { } entry)
        {
            guard.Require(); SafePath(entry.Name);
            if (!paths.Add(entry.Name) || entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile) ||
                entry.DataStream is null || entry.Length < 0 || entry.Length > int.MaxValue || entry.Length > source.Length)
                throw Payload.Invalid();
            using var output = new WipingMemoryStream();
            byte[] block = new byte[8192];
            try
            {
                int count; while ((count = entry.DataStream.Read(block)) != 0)
                {
                    if (output.Length + count > entry.Length) throw Payload.Invalid();
                    output.Write(block, 0, count);
                }
            }
            finally { CryptographicOperations.ZeroMemory(block); }
            if (output.Length != entry.Length) throw Payload.Invalid();
            byte[] data = output.ToArray();
            bool retained = false;
            try
            {
                if (entry.Name.EndsWith(".deps.json", StringComparison.OrdinalIgnoreCase))
                {
                    JsonNode deps;
                    try { deps = Client.Parse(data); } catch { throw Payload.Invalid(); }
                    if (deps is not JsonObject) throw Payload.Invalid();
                    if (Native(deps)) throw Unsupported("依赖清单包含原生资产，代码加密仅支持托管依赖");
                    continue;
                }
                if (!entry.Name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && !entry.Name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    throw Unsupported("加密程序集归档只能包含托管程序集和依赖清单");
                if (!targets.TryAdd(entry.Name, data)) throw Payload.Invalid();
                var (identity, hasEntry) = Inspect(data);
                if (identity.Name!.Equals(sdkName, StringComparison.OrdinalIgnoreCase) || platform.Contains(identity.Name))
                    throw Unsupported("业务载荷不能包含或覆盖 Auth Go SDK 与运行库程序集");
                if (!images.TryAdd(identity.Name, new Image(identity, data, hasEntry))) throw Unsupported("加密载荷包含重名程序集");
                retained = true;
                if (primary && hasEntry)
                {
                    if (entryName is not null) throw Unsupported("主归档必须只有一个程序集入口点");
                    entryName = identity.Name;
                }
            }
            finally { if (!retained) CryptographicOperations.ZeroMemory(data); }
        }
        return entryName ?? "";
    }

    internal static SealedLoadContext Open(Guard guard, IReadOnlyList<(byte[] Bytes, bool Primary)> archives, Action<IReadOnlyList<Dictionary<string, byte[]>>>? beforeLoad = null)
    {
        guard.Require();
        var images = new Dictionary<string, Image>(StringComparer.OrdinalIgnoreCase);
        try
        {
            string main = "";
            var targets = new List<Dictionary<string, byte[]>>();
            foreach (var archive in archives)
            {
                using var source = new MemoryStream(archive.Bytes, false);
                var selected = new Dictionary<string, byte[]>(StringComparer.Ordinal); targets.Add(selected);
                string candidate = Archive(guard, source, images, archive.Primary, selected);
                if (archive.Primary) { if (main.Length != 0 || candidate.Length == 0) throw Payload.Invalid(); main = candidate; }
            }
            if (main.Length == 0) throw Payload.Invalid();
            beforeLoad?.Invoke(targets);
            guard.Require(); return new SealedLoadContext(guard, images, main);
        }
        catch (AuthGoException) { foreach (var image in images.Values) CryptographicOperations.ZeroMemory(image.Bytes); throw; }
        catch { foreach (var image in images.Values) CryptographicOperations.ZeroMemory(image.Bytes); throw Payload.Invalid(); }
    }

    static void Match(AssemblyName requested, AssemblyName actual)
    {
        if (!string.Equals(requested.Name, actual.Name, StringComparison.OrdinalIgnoreCase) ||
            requested.Version is not null && requested.Version != actual.Version ||
            !string.Equals(requested.CultureName ?? "", actual.CultureName ?? "", StringComparison.OrdinalIgnoreCase) ||
            (requested.Version is not null || requested.GetPublicKeyToken() is { Length: > 0 }) && !(requested.GetPublicKeyToken() ?? []).AsSpan().SequenceEqual(actual.GetPublicKeyToken() ?? []))
            throw Unsupported("程序集名称、版本或签名标识不匹配");
    }
    Assembly LoadImage(Image image)
    {
        // Validate outside the context lock: Guard checks may wait behind HTTP.
        // Closing the context must not inherit that wait or block seat release.
        Active(); byte[] copy;
        lock (gate)
        {
            if (closed) throw new AuthGoException("SDK_NOT_ACTIVATED");
            copy = image.Bytes.ToArray();
        }
        try
        {
            Active();
            using var source = new MemoryStream(copy, false);
            var result = LoadFromStream(source);
            Match(image.Identity, result.GetName());
            lock (gate) if (closed) throw new AuthGoException("SDK_NOT_ACTIVATED");
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(copy);
            lock (gate) CryptographicOperations.ZeroMemory(image.Bytes);
        }
    }
    Assembly? Own(AssemblyName requested)
    {
        Active(); Lazy<Assembly> pending;
        lock (gate)
        {
            if (closed) throw new AuthGoException("SDK_NOT_ACTIVATED");
            if (requested.Name is null || !images.TryGetValue(requested.Name, out var image)) return null;
            Match(requested, image.Identity);
            if (!loaded.TryGetValue(requested.Name, out pending!))
            {
                pending = new Lazy<Assembly>(() => LoadImage(image), LazyThreadSafetyMode.ExecutionAndPublication);
                loaded.Add(requested.Name, pending);
            }
        }
        return pending.Value;
    }
    protected override Assembly? Load(AssemblyName assemblyName)
    {
        Active();
        if (assemblyName.Name is not null && assemblyName.Name.Equals(sdkName, StringComparison.OrdinalIgnoreCase))
        { var shared = typeof(Guard).Assembly; Match(assemblyName, shared.GetName()); return shared; }
        return Own(assemblyName);
    }
    Assembly? Resolve(AssemblyLoadContext context, AssemblyName name) { Active(); return Own(name); }
    protected override nint LoadUnmanagedDll(string unmanagedDllName)
    { Active(); throw Unsupported("代码加密不支持原生依赖"); }
    public Assembly LoadAssembly(AssemblyName name)
    {
        Active(); return Own(name) ?? LoadFromAssemblyName(name);
    }
    public Assembly MainAssembly { get { Active(); return LoadAssembly(new AssemblyName(main)); } }

    public void Dispose()
    {
        lock (gate)
        {
            if (closed) return; closed = true;
            foreach (var image in images.Values) CryptographicOperations.ZeroMemory(image.Bytes);
            images.Clear(); loaded.Clear();
        }
        Unload();
    }
}

/// <summary>Clear retired backing buffers as well as the final buffer. Never a file.</summary>
internal sealed class WipingMemoryStream : MemoryStream
{
    void Grow(int count)
    {
        long needed = checked(Position + count);
        if (needed <= Capacity) return;
        byte[] old = GetBuffer();
        Capacity = checked((int)Math.Max(needed, Math.Max(256L, (long)Capacity * 2)));
        CryptographicOperations.ZeroMemory(old);
    }
    public override void Write(byte[] buffer, int offset, int count) { Grow(count); base.Write(buffer, offset, count); }
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        Grow(buffer.Length); long start = Position, end = checked(start + buffer.Length);
        if (end > Length) SetLength(end);
        buffer.CopyTo(GetBuffer().AsSpan((int)start)); Position = end;
    }
    public override void WriteByte(byte value) { Grow(1); base.WriteByte(value); }
    protected override void Dispose(bool disposing)
    { if (disposing) CryptographicOperations.ZeroMemory(GetBuffer()); base.Dispose(disposing); }
}
