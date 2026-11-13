using AuthGo;
using System.Text.Json.Nodes;
using System.Threading;

static class GuardTests
{
    static void Check(bool test){if(!test)throw new Exception("guard assertion");}
    sealed class Fake : IGuardBackend
    {
        public readonly Client Client;
        public volatile string Status="grace";
        public volatile string? Failure;
        public int Calls,Releases,Heartbeats;
        public ManualResetEventSlim? Block,Validation;
        public readonly ManualResetEventSlim Entered=new(false);
        public string? ReleaseFailure;
        public double Now=>DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        public Fake(){var vector=JsonNode.Parse(File.ReadAllText("sdk/vectors/v2.json"))!;Client=new Client(Config(vector),new ClientOptions {Fingerprint=new string('a',64),CacheDir=""});}
        public Result Value(){var d=new JsonObject { ["features"]=new JsonObject {["export"]=true,["nested"]=new JsonObject {["n"]=1}},["floating"]=true,["next_check_in"]=10,["issued_at"]=DateTimeOffset.FromUnixTimeSeconds((long)Now).ToString("o"),["lease_expires_at"]=DateTimeOffset.FromUnixTimeSeconds((long)Now+2).ToString("o")};return new Result(Client,d,"proof",new byte[32],Status,Now+30);}
        public Result Verify(){Interlocked.Increment(ref Calls);Block?.Wait();if(Failure!=null)throw new AuthGoException(Failure);return Value();}
        public Result Heartbeat(){Interlocked.Increment(ref Heartbeats);return Verify();}
        public void Validate(string ticket){Check(ticket=="proof");Entered.Set();Validation?.Wait();}
        public void Release(){Interlocked.Increment(ref Releases);if(ReleaseFailure!=null)throw new AuthGoException(ReleaseFailure);}
    }
    static string Config(JsonNode v)=>"authgo2."+Client.B64(Client.Bytes(new JsonObject {["url"]="http://127.0.0.1:1",["app_key"]="unit",["app_secret"]="test",["public_key"]=Convert.ToBase64String(Client.Decode(v["ed25519_public"]!.GetValue<string>())),["gateway_key"]=v["gateway_public"]!.GetValue<string>()}.ToJsonString()));
    static async Task Wait(Func<bool> condition){var end=DateTime.UtcNow.AddSeconds(3);while(!condition()){Check(DateTime.UtcNow<end);await Task.Delay(10);}}
    public static async Task Run(){
        try{await Guard.StartAsync(new GuardOptions());throw new Exception();}catch(AuthGoException e){Check(e.Code=="SDK_INVALID_CONFIG");}
        var v=JsonNode.Parse(File.ReadAllText("sdk/vectors/v2.json"))!;
        try{await Guard.StartAsync(new GuardOptions {Config=Config(v),License="abc",SDKOptions=new ClientOptions {Fingerprint=new string('a',64),CacheDir=""}});throw new Exception();}catch(AuthGoException e){Check(e.Code=="INVALID_LICENSE_KEY");}
        var f=new Fake();var g=new Guard(f,f.Value());await Wait(()=>Volatile.Read(ref f.Calls)>0);Check(!g.Done.IsCompleted);Check(g.Result.HeartbeatInterval==1);Check(g.Result.Data["heartbeat_interval"]==null);
        await Task.WhenAll(Enumerable.Range(0,12).Select(_=>Task.Run(()=>{for(int j=0;j<100;j++){var r=g.Result;r.Data["features"]!["nested"]!["n"]=99;g.Require("export");}})));
        Check(g.Result.Data["features"]!["nested"]!["n"]!.GetValue<int>()==1);
        try{g.Require("missing");throw new Exception();}catch(AuthGoException e){Check(e.Code=="INVALID_POLICY");}
        await Wait(()=>Volatile.Read(ref f.Heartbeats)>0);Check(f.Calls<=3);
        f.Failure="SDK_GRACE_EXPIRED";await g.Done.WaitAsync(TimeSpan.FromSeconds(3));Check(g.Error?.Code==f.Failure);
        try{g.Require();throw new Exception();}catch(AuthGoException e){Check(e.Code==f.Failure);}
        await g.DisposeAsync();await g.DisposeAsync();Check(f.Releases==1);
        var releasing=new Fake {ReleaseFailure="SDK_NETWORK_ERROR"};var releaseGuard=new Guard(releasing,releasing.Value());
        try{await releaseGuard.DisposeAsync();throw new Exception();}catch(AuthGoException e){Check(e.Code=="SDK_NETWORK_ERROR");Check(!releaseGuard.Done.IsCompleted);}
        var reading=new Fake {Validation=new(false)};var rg=new Guard(reading,reading.Value());
        var reader=Task.Run(()=>{try{rg.Require();throw new Exception();}catch(AuthGoException e){Check(e.Code=="SDK_NOT_ACTIVATED");}});
        await Wait(()=>reading.Entered.IsSet);_=Task.Delay(2000).ContinueWith(_=>reading.Validation.Set());var closeClock=System.Diagnostics.Stopwatch.StartNew();await rg.DisposeAsync();Check(closeClock.Elapsed<TimeSpan.FromSeconds(1));reading.Validation.Set();await reader.WaitAsync(TimeSpan.FromSeconds(1));
        var blocked=new Fake {Block=new(false)};var b=new Guard(blocked,blocked.Value());await Wait(()=>blocked.Calls>0);var clock=System.Diagnostics.Stopwatch.StartNew();
        try{await b.DisposeAsync();throw new Exception();}catch(AuthGoException e){Check(e.Code=="SDK_NETWORK_ERROR");Check(clock.Elapsed<TimeSpan.FromMilliseconds(5500));}finally{blocked.Block.Set();}
        await Task.Delay(30);Check(blocked.Releases==0);Check(Guard.ExitLicense==77);
        Console.WriteLine("C# Guard lifecycle/concurrency/heartbeat/close PASS");
    }
}
