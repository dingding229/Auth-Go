using AuthGo;
using System.Net;
using System.Runtime.InteropServices;

var stopping=new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
using var term=PosixSignalRegistration.Create(PosixSignal.SIGTERM,ctx=>{ctx.Cancel=true;stopping.TrySetResult();});
using var interrupt=PosixSignalRegistration.Create(PosixSignal.SIGINT,ctx=>{ctx.Cancel=true;stopping.TrySetResult();});
Guard? guard=null;
int code=0;
try {
    var startup=Guard.StartAsync(new GuardOptions {Config=Build.Config,Version=Build.Version,OnChange=(r,e)=>{
        if(e!=null)Console.Error.WriteLine($"授权检查: {e.Message}");
        if(r!=null){Console.WriteLine($"授权状态: {r.Status}");if(r.CacheWarning!=null)Console.WriteLine($"缓存提示: {r.CacheWarning}");}
    }});
    if(await Task.WhenAny(startup,stopping.Task)==stopping.Task)return 0;
    guard=await startup;
    if(guard.Result.IsTrial)Console.WriteLine("当前为试用");
    if(guard.Result.CacheWarning!=null)Console.WriteLine($"缓存提示: {guard.Result.CacheWarning}");
    string addr="0.0.0.0:8080";
    for(int i=0;i+1<args.Length;i++)if(args[i]=="-listen")addr=args[i+1];
    var split=addr.Split(':');
    // TcpListener accepts port zero, unlike HttpListener, for shared-host tests.
    var server=new System.Net.Sockets.TcpListener(IPAddress.Parse(split[0]),int.Parse(split[1]));server.Start();
    Console.WriteLine($"HTTP已启动 version={Build.Version}");
    try {
        while(!stopping.Task.IsCompleted && !guard.Done.IsCompleted){
            var accept=server.AcceptTcpClientAsync();
            if(await Task.WhenAny(accept,stopping.Task,guard.Done)!=accept)break;
            var socket=await accept;var g=guard;
            _=Task.Run(()=>{
                using(socket){socket.ReceiveTimeout=200;socket.SendTimeout=200;
                    try{var stream=socket.GetStream();var input=new byte[1024];stream.Read(input);g.Require();var body="{\"features\":"+(g.Result.Features?.ToJsonString()??"{}")+"}";var length=System.Text.Encoding.UTF8.GetByteCount(body);var response=System.Text.Encoding.UTF8.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n{body}");stream.Write(response);}
                    catch(Exception){ }
                }
            });
        }
    } finally{server.Stop();}
    if(guard.Error!=null){Console.Error.WriteLine($"授权已失效: {guard.Error.Message}");code=Guard.ExitLicense;}
} catch(AuthGoException e){Console.Error.WriteLine($"授权验证失败: {e.Message}");code=Guard.ExitLicense;}
finally {if(guard!=null)try{await guard.DisposeAsync();}catch(Exception e){Console.Error.WriteLine($"释放席位: {e.Message}");}}
return code;
