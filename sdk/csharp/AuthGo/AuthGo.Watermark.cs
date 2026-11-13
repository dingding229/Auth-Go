// Compile this source into BUSINESS assemblies, never the AuthGo SDK assembly.
// Trimming, AOT and single-file pipelines are unsupported; the wizard excludes it there.
using System;
using System.Runtime.CompilerServices;
using System.Threading;

internal static class AuthGoBusinessWatermark
{
    private static int aggregate;

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static int Read(ReadOnlySpan<byte> bytes)
    {
        int sum = 0;
        for (int i = 0; i < bytes.Length; i++) sum = unchecked(sum * 31 + bytes[i]);
        return sum;
    }

    [ModuleInitializer]
    [MethodImpl(MethodImplOptions.NoInlining)]
    internal static void Initialize()
    {
        int sum = Read("c0dec0dec0dec0de00000000000000000000000000000000000000000000000000000000000000000000000000000000"u8);
        sum ^= Read("c0dec0dec0dec0de00000000000000010000000000000000000000000000000000000000000000000000000000000000"u8);
        sum ^= Read("c0dec0dec0dec0de00000000000000020000000000000000000000000000000000000000000000000000000000000000"u8);
        sum ^= Read("c0dec0dec0dec0de00000000000000030000000000000000000000000000000000000000000000000000000000000000"u8);
        sum ^= Read("c0dec0dec0dec0de00000000000000040000000000000000000000000000000000000000000000000000000000000000"u8);
        sum ^= Read("c0dec0dec0dec0de00000000000000050000000000000000000000000000000000000000000000000000000000000000"u8);
        sum ^= Read("c0dec0dec0dec0de00000000000000060000000000000000000000000000000000000000000000000000000000000000"u8);
        sum ^= Read("c0dec0dec0dec0de00000000000000070000000000000000000000000000000000000000000000000000000000000000"u8);
        Volatile.Write(ref aggregate, sum ^ Volatile.Read(ref aggregate));
    }
}
