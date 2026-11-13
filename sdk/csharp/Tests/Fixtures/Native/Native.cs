using System.Runtime.InteropServices;
namespace AuthGoSealedFixture;
public static class Native
{
    [DllImport("nonexistent-native-library")]
    public static extern int Run();
}
