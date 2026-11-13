using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace AuthGo;

/// <summary>Compiled public entry point for an encrypted, IL-only .NET 8 program.</summary>
public static class Bootstrap
{
    sealed class Session(Guard guard, SealedLoadContext context)
    {
        internal readonly Guard Guard = guard;
        internal readonly SealedLoadContext Context = context;
        internal int Closing;
        internal EventHandler? ExitHandler;
        internal readonly TaskCompletionSource Closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal async Task CloseAsync()
        {
            if (Interlocked.Exchange(ref Closing, 1) != 0) return;
            Closed.TrySetResult();
            if (ExitHandler is not null) AppDomain.CurrentDomain.ProcessExit -= ExitHandler;
            Context.Dispose();
            try { await Guard.DisposeAsync().ConfigureAwait(false); }
            finally { Interlocked.CompareExchange(ref current, null, this); }
        }
    }
    static Session? current;
    static int starting;
    /// <summary>The same guard for encrypted business code and its worker threads.</summary>
    public static Guard Current
    {
        get { var session = Volatile.Read(ref current) ?? throw new AuthGoException("SDK_NOT_ACTIVATED"); session.Guard.Require(); return session.Guard; }
    }
    static string DirectoryPath => Environment.GetEnvironmentVariable("AUTHGO_PAYLOAD_DIR") is { Length: > 0 } path ? path : "/opt/authgo";
    static Payload Metadata(string directory)
    {
        using var file = File.OpenRead(Path.Combine(directory, "payload.json"));
        byte[] buffer = new byte[65537]; int count = 0;
        while (count < buffer.Length)
        { int read = file.Read(buffer, count, buffer.Length - count); if (read == 0) break; count += read; }
        return Payload.ParsePayload(buffer.AsSpan(0, count).ToArray());
    }
    public static SealedLoadContext Load(Guard guard, string name = "app") => Load(guard, name, DirectoryPath);
    internal static SealedLoadContext Load(Guard guard, string name, string directory)
    { guard.Require(); return Load(guard, name, directory, Metadata(directory)); }
    static SealedLoadContext Load(Guard guard, string name, string directory, Payload payload)
    {
        guard.Require();
        if (!Regex.IsMatch(name, @"\A[a-z0-9_-]{1,128}\z", RegexOptions.CultureInvariant)) throw Payload.Invalid();
        var files = PayloadFiles.Files(payload);
        if (!files.Any(file => file.Name == name && file.Kind == "dotnet")) throw Payload.Invalid();
        byte[] material = guard.UnlockPayloadMaterial(payload), key = material[..32];
        var archives = new List<(byte[] Bytes, bool Primary)>();
        var selectedIndices = new List<int>();
        try
        {
            var watermark = PayloadWatermark.Read(directory, payload, material);
            for (int i = 0; i < files.Count; i++)
            {
                var file = files[i]; if (file.Kind != "dotnet") continue;
                guard.Require();
                using var source = File.OpenRead(Path.Combine(directory, file.Path));
                using var output = new WipingMemoryStream();
                PayloadFiles.DecryptPayloadFile(output, source, source.Length, payload, key, i);
                archives.Add((output.ToArray(), file.Name == name)); selectedIndices.Add(i);
            }
            guard.Require(); return SealedLoadContext.Open(guard, archives, targets => {
                var pending = new List<PayloadWatermark.Patch>();
                for (int j = 0; j < targets.Count; j++) pending.AddRange(PayloadWatermark.Prepare(targets[j], watermark, selectedIndices[j]));
                PayloadWatermark.Apply(pending, material);
            });
        }
        finally
        {
            CryptographicOperations.ZeroMemory(material); CryptographicOperations.ZeroMemory(key);
            foreach (var archive in archives) CryptographicOperations.ZeroMemory(archive.Bytes);
        }
    }
    /// <summary>Config is a compiled constant. Version is taken from this same authenticated envelope.</summary>
    public static async Task<int> RunAsync(GuardOptions options, string[] args, string name = "app", CancellationToken cancellationToken = default)
    {
        if (Interlocked.CompareExchange(ref starting, 1, 0) != 0) throw new InvalidOperationException("已有加密程序正在启动");
        Guard? guard = null; SealedLoadContext? context = null; Session? session = null;
        bool executing = false, complete = false;
        try
        {
            if (Volatile.Read(ref current) is not null) throw new InvalidOperationException("已有加密程序正在运行");
            if (options is null || string.IsNullOrEmpty(options.Config)) throw new AuthGoException("SDK_INVALID_CONFIG");
            string directory = DirectoryPath; Payload payload = Metadata(directory);
            guard = await Guard.StartAsync(new GuardOptions {
                Config = options.Config, License = options.License, Version = payload.Version,
                SDKOptions = options.SDKOptions, OnChange = options.OnChange
            }, cancellationToken).ConfigureAwait(false);
            context = Load(guard, name, directory, payload);
            session = new Session(guard, context);
            if (Interlocked.CompareExchange(ref current, session, null) is not null) throw new InvalidOperationException("已有加密程序正在运行");
            session.ExitHandler = (_, _) => { try { session.CloseAsync().GetAwaiter().GetResult(); } catch { } };
            AppDomain.CurrentDomain.ProcessExit += session.ExitHandler;
            _ = StopOnRefusal(session);
            executing = true;
            int result = await InvokeAsync(guard, context, args).ConfigureAwait(false);
            complete = true;
            // Foreground workers may outlive synchronous Main; retain the guard
            // until ProcessExit rather than releasing a still-running instance.
            return result;
        }
        catch (Exception error) when (AuthorizationError(error) is not null) { Console.Error.WriteLine(Message(AuthorizationError(error))); return Guard.ExitLicense; }
        catch (OperationCanceledException) { throw; }
        catch (Exception error) when (!executing) { Console.Error.WriteLine(Message(error)); return Guard.ExitLicense; }
        finally
        {
            Interlocked.Exchange(ref starting, 0);
            if (!complete)
            {
                if (session is not null) { try { await session.CloseAsync().ConfigureAwait(false); } catch { } }
                else { context?.Dispose(); if (guard is not null) try { await guard.DisposeAsync().ConfigureAwait(false); } catch { } }
            }
        }
    }
    static async Task StopOnRefusal(Session session)
    {
        await Task.WhenAny(session.Guard.Done, session.Closed.Task).ConfigureAwait(false);
        if (Volatile.Read(ref session.Closing) != 0) return;
        Console.Error.WriteLine(Message(session.Guard.Error));
        Environment.Exit(Guard.ExitLicense);
    }
    internal static async Task<int> InvokeAsync(Guard guard, SealedLoadContext context, string[] args)
    {
        guard.Require();
        MethodInfo entry = context.MainAssembly.EntryPoint ?? throw Payload.Invalid();
        var parameters = entry.GetParameters();
        if (!entry.IsStatic || parameters.Length > 1 || parameters.Length == 1 && parameters[0].ParameterType != typeof(string[])) throw Payload.Invalid();
        guard.Require();
        object? result;
        try { result = entry.Invoke(null, parameters.Length == 0 ? null : [args.ToArray()]); }
        catch (TargetInvocationException error) when (error.InnerException is not null) { ExceptionDispatchInfo.Capture(error.InnerException).Throw(); throw; }
        if (result is Task<int> integer) return await integer.ConfigureAwait(false);
        if (result is Task task) { await task.ConfigureAwait(false); return 0; }
        return result is int exitCode ? exitCode : entry.ReturnType == typeof(void) ? 0 : throw Payload.Invalid();
    }
    static AuthGoException? AuthorizationError(Exception error)
    { for (Exception? next = error; next is not null; next = next.InnerException) if (next is AuthGoException auth) return auth; return null; }
    internal static string Message(Exception? error)
    {
        if (error is AuthGoException auth)
        {
            if (auth.InnerException is SealedFormatException detail) return "代码载荷不受支持：" + detail.Message;
            if (Regex.IsMatch(auth.Code, @"\A[A-Z0-9_]{1,64}\z")) return "授权或代码解锁失败：" + auth.Code + "（退出码 77）";
        }
        return "加密程序启动失败，请检查构建时接入配置、载荷和授权状态（退出码 77）";
    }
    internal static async Task CloseCurrentAsync()
    { if (Volatile.Read(ref current) is { } session) await session.CloseAsync().ConfigureAwait(false); }
}
