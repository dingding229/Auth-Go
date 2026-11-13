using System.Collections.Concurrent;
using System.Security.Cryptography;
namespace AuthGo;
internal static class ContainerIdentity
{
    internal static readonly string Session = Client.B64(RandomNumberGenerator.GetBytes(16));
    internal static readonly ConcurrentDictionary<string,byte> Replaced = new();
    static readonly ConcurrentDictionary<string,string> Memory = new();
    internal static bool Detect(Func<string,byte[]> read, Func<string,string?> env)
    {
        var force=env("AUTHGO_CONTAINER"); if(force is "0" or "1")return force=="1";
        foreach(var p in new[]{"/.dockerenv","/run/.containerenv"})try{read(p);return true;}catch(IOException){}catch(UnauthorizedAccessException){}
        try{var raw=System.Text.Encoding.UTF8.GetString(read("/proc/1/cgroup"));return new[]{"docker","containerd","kubepods","libpod"}.Any(raw.Contains);}catch(IOException){return false;}catch(UnauthorizedAccessException){return false;}
    }
    internal static bool Detect()=>Detect(File.ReadAllBytes,Environment.GetEnvironmentVariable);
    internal static string Hash(string id)=>Client.Hash(Client.Bytes("authgo/instance/v1\0"+id));
    static string Read(string p)
    {
        var info=new FileInfo(p);
        if(info.LinkTarget!=null||info.Length!=64||!OperatingSystem.IsWindows()&&File.GetUnixFileMode(p)!=(UnixFileMode.UserRead|UnixFileMode.UserWrite))throw new IOException();
        var value=File.ReadAllText(p);if(!System.Text.RegularExpressions.Regex.IsMatch(value,"^[0-9a-f]{64}$"))throw new IOException();return value;
    }
    internal static (string,bool) Load(string dir)
    {
        try{
            if(dir=="")throw new IOException();Directory.CreateDirectory(dir);var target=Path.Combine(dir,"instance-id");
            if(File.Exists(target))return(Read(target),false);
            var tmp=Path.Combine(dir,".instance-"+Client.B64(RandomNumberGenerator.GetBytes(16)));
            try{
                var opt=new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None};
                if(!OperatingSystem.IsWindows())opt.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
                using(var f=new FileStream(tmp,opt)){f.Write(System.Text.Encoding.ASCII.GetBytes(Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant()));f.Flush(true);}
                try{File.Move(tmp,target,false);}catch(IOException)when(File.Exists(target)){}
            }finally{File.Delete(tmp);}
            return(Read(target),false);
        }catch(IOException){return(Memory.GetOrAdd(Path.GetFullPath(dir==""?".":dir),_=>Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant()),true);}
        catch(UnauthorizedAccessException){return(Memory.GetOrAdd(Path.GetFullPath(dir==""?".":dir),_=>Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant()),true);}
    }
}
