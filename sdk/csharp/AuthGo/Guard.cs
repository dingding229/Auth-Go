namespace AuthGo;

public sealed class GuardOptions
{
    public string Config { get; set; } = "";
    public string License { get; set; } = "";
    public string Version { get; set; } = "";
    public ClientOptions SDKOptions { get; set; } = new();
    public Action<Result?, AuthGoException?>? OnChange { get; set; }
}

internal interface IGuardBackend
{
    double Now { get; }
    Result Verify();
    Result Heartbeat();
    void Validate(string ticket);
    void Release();
    byte[] UnlockPayloadMaterial(Payload payload) => UnlockPayload(payload);
    byte[] UnlockPayload(Payload payload) => throw new AuthGoException("SDK_NOT_ACTIVATED");
}

/// <summary>In-process guard; signals and exit belong to the application.</summary>
public sealed class Guard : IAsyncDisposable
{
    public const int ExitLicense = 77;
    sealed class Backend(Client client) : IGuardBackend
    {
        public double Now => client.Now;
        public Result Verify() => client.Verify();
        public Result Heartbeat() => client.Heartbeat();
        public void Validate(string ticket) => client.Validate(ticket);
        public void Release() => client.ReleaseSeat();
        public byte[] UnlockPayload(Payload payload) => client.UnlockPayload(payload);
        public byte[] UnlockPayloadMaterial(Payload payload) => client.UnlockPayloadMaterial(payload);
    }
    readonly object gate = new();
    readonly IGuardBackend client;
    readonly CancellationTokenSource stop;
    readonly TaskCompletionSource done = new(TaskCreationOptions.RunContinuationsAsynchronously);
    readonly Action<Result?, AuthGoException?>? change;
    readonly Task worker;
    Result current;
    AuthGoException? error;
    Task? closed;

    public static async Task<Guard> StartAsync(GuardOptions options, CancellationToken ct = default)
    {
        if (options == null || string.IsNullOrEmpty(options.Config)) throw new AuthGoException("SDK_INVALID_CONFIG");
        ct.ThrowIfCancellationRequested();
        var src = options.SDKOptions ?? new();
        var client = new Client(options.Config, new ClientOptions {
            Fingerprint=src.Fingerprint, CacheDir=src.CacheDir,
            Clock=src.Clock, HttpClient=src.HttpClient, Version=options.Version
        });
        var key = string.IsNullOrEmpty(options.License) ? Environment.GetEnvironmentVariable("AUTHGO_LICENSE") ?? "" : options.License;
        var result = await Task.Run(() => client.GuardCheck(key), CancellationToken.None).WaitAsync(ct).ConfigureAwait(false);
        ct.ThrowIfCancellationRequested();
        return new Guard(new Backend(client), result, options.OnChange, ct);
    }
    internal Guard(IGuardBackend backend, Result initial, Action<Result?,AuthGoException?>? onChange = null, CancellationToken ct = default)
    {
        client = backend; current = initial.Snapshot(); change = onChange;
        stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        worker = Task.Run(RunAsync);
    }
    public Result Result { get { lock(gate) return current.Snapshot(); } }
    public Task Done => done.Task;
    public AuthGoException? Error { get { lock(gate) return error; } }
    void Active()
    {
        if(error != null) throw error;
        if(stop.IsCancellationRequested || done.Task.IsCompleted) throw new AuthGoException("SDK_NOT_ACTIVATED");
    }
    public void Require(string feature = "")
    {
        Result proof;
        lock(gate) {Active();proof=current.Snapshot();}
        client.Validate(proof.Ticket()); // Never hold lifecycle lock behind synchronous HTTP.
        lock(gate) {
            Active();
            if(feature != "" && proof.Features?[feature]?.ToJsonString() != "true") throw new AuthGoException("INVALID_POLICY");
        }
    }
    internal byte[] UnlockPayload(Payload payload) { Require(); return client.UnlockPayload(payload); }
    internal byte[] UnlockPayloadMaterial(Payload payload) { Require(); return client.UnlockPayloadMaterial(payload); }
    void Notify(Result? result, AuthGoException? problem)
    {
        lock(gate) {
            if(stop.IsCancellationRequested) return;
            if(result != null) current = result.Snapshot();
            if(problem != null && error == null) {error=problem;done.TrySetResult();}
        }
        change?.Invoke(result?.Snapshot(),problem);
    }
    static double Date(System.Text.Json.Nodes.JsonNode? value) => value == null ? double.PositiveInfinity : DateTimeOffset.Parse(value.GetValue<string>(),System.Globalization.CultureInfo.InvariantCulture).ToUnixTimeMilliseconds()/1000.0;
    static double Next(Result r) => double.Parse(r.Data["next_check_in"]!.ToJsonString(),System.Globalization.CultureInfo.InvariantCulture);
    async Task RunAsync()
    {
        try {
            if(stop.IsCancellationRequested) return;
            var result=client.Verify();Notify(result,null);
            var verifyAt=client.Now+Next(result);var heartbeatAt=client.Now+result.HeartbeatInterval;
            while(!stop.IsCancellationRequested) {
                var floating=result.Data["floating"]?.ToJsonString()=="true";
                var next=Math.Min(verifyAt,floating?heartbeatAt:double.PositiveInfinity);
                next=Math.Min(next,Date(result.Data["expires_at"]));
                next=Math.Min(next,result.Status=="grace"?result.UsableUntil:Date(result.Data["lease_expires_at"]));
                await Task.Delay(TimeSpan.FromSeconds(Math.Max(0,next-client.Now)),stop.Token).ConfigureAwait(false);
                var now=client.Now;
                if(now>=verifyAt || now>=next && (!floating || now<heartbeatAt)) {
                    result=client.Verify();Notify(result,null);verifyAt=client.Now+Next(result);
                }
                if(!stop.IsCancellationRequested && result.Data["floating"]?.ToJsonString()=="true" && client.Now>=heartbeatAt) {
                    result=client.Heartbeat();Notify(result,null);heartbeatAt=client.Now+result.HeartbeatInterval;
                }
            }
        } catch(OperationCanceledException) when(stop.IsCancellationRequested) { }
          catch(AuthGoException e) {Notify(null,e);}
          catch(Exception e) {Notify(null,new AuthGoException("SDK_RESPONSE_INVALID",false,e));}
    }
    public ValueTask DisposeAsync()
    {
        lock(gate) {
            if(closed == null) {
                var deadline=System.Diagnostics.Stopwatch.StartNew();stop.Cancel();
                closed=CloseCore(deadline);
            }
            return new ValueTask(closed);
        }
    }
    async Task CloseCore(System.Diagnostics.Stopwatch elapsed)
    {
        int expired=0;
        var finished=Task.Run(async () => {
            await worker.ConfigureAwait(false);
            if(Volatile.Read(ref expired)!=0 || elapsed.Elapsed>=TimeSpan.FromSeconds(5)) throw new AuthGoException("SDK_NETWORK_ERROR");
            client.Release();
        });
        try {
            await finished.WaitAsync(TimeSpan.FromMilliseconds(Math.Max(0,5000-elapsed.Elapsed.TotalMilliseconds))).ConfigureAwait(false);
        } catch(TimeoutException e) {Interlocked.Exchange(ref expired,1);throw new AuthGoException("SDK_NETWORK_ERROR",false,e);}
    }
}
