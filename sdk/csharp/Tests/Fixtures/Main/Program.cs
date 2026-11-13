using System.Runtime.CompilerServices;
using AuthGo;
namespace AuthGoSealedFixture;
public static class Entry
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static string UseDependency() => Value.Read();
    public static AssemblyMarker Identity() => new();
    public sealed class AssemblyMarker { }
    public static async Task<int> Main(string[] args)
    {
        Bootstrap.Current.Require();
        await Task.Yield();
        if (args.Contains("throw")) throw new InvalidOperationException("business failure preserved");
        Console.WriteLine("SEALED_RESULT=" + UseDependency() + ":" + string.Join(',', args));
        if (args.Contains("running-refuse"))
        {
            (AppContext.GetData("authgo.sealed.started") as Action)?.Invoke();
            while (true) await Task.Delay(20);
        }
        if (args.Contains("worker"))
            new Thread(() => { Thread.Sleep(150); Console.WriteLine("BOOT_WORKER=" + (Bootstrap.Current is not null)); }).Start();
        return 7;
    }
}
