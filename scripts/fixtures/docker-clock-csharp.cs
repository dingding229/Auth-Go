using AuthGo;
int advance=0;
try {
    await using var guard=await Guard.StartAsync(new GuardOptions {
        Config=Build.Config,Version=Build.Version,
        SDKOptions=new ClientOptions { Clock=()=>DateTimeOffset.UtcNow.AddSeconds(Volatile.Read(ref advance)==1?72*3600+1:0)},
        OnChange=(r,e)=>{
            if(r!=null){Console.WriteLine($"clock agent: {r.Status}");if(r.Status=="grace")Interlocked.Exchange(ref advance,1);}
            if(e!=null)Console.WriteLine($"clock agent: {e.Message}");
        }
    });
    Console.WriteLine("clock ready");await guard.Done;Console.WriteLine($"clock stopped: {guard.Error?.Message}");
} catch(AuthGoException e){Console.WriteLine($"clock error: {e.Message}");}
return Guard.ExitLicense;
