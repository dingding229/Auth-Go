using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace AuthGo;

/// <summary>The Go payload chunk format. Never expose bytes before GCM authentication.</summary>
public static class PayloadFiles
{
    public const int ChunkSize = 1 << 20;
    public sealed record File(string Name, string Kind, string Path, long Size);

    public static IReadOnlyList<File> Files(Payload payload)
    {
        try
        {
            var p = payload.Validated();
            var manifest = Client.Parse(Client.Decode(p.Manifest));
            return manifest["files"]!.AsArray().Select(value => new File(
                value!["name"]!.GetValue<string>(), value["kind"]!.GetValue<string>(),
                value["path"]!.GetValue<string>(), checked((long)Payload.Integer(value["size"])))).ToArray();
        }
        catch { throw Payload.Invalid(); }
    }

    public static long PayloadCipherSize(long size)
    {
        if (size < 0 || size > long.MaxValue / 2) throw Payload.Invalid();
        return checked(size + 16 * Math.Max(1, (size + ChunkSize - 1) / ChunkSize));
    }

    /// <summary>Writes authenticated blocks only. Discard partial output on any error.</summary>
    public static void DecryptPayloadFile(Stream target, Stream source, long total,
        Payload payload, byte[] key, int index)
    {
        var files = Files(payload);
        if (index < 0 || index >= files.Count || key is null || key.Length != 32 || source is null || target is null)
            throw Payload.Invalid();
        long size = files[index].Size;
        if (total != PayloadCipherSize(size)) throw Payload.Invalid();
        byte[] binding = payload.PayloadBinding(), cipher = new byte[ChunkSize + 16];
        long count = Math.Max(1, (size + ChunkSize - 1) / ChunkSize);
        try
        {
            using var aes = new AesGcm(key, 16);
            for (long j = 0; j < count; j++)
            {
                int n = (int)Math.Min(ChunkSize, size - j * ChunkSize);
                try { source.ReadExactly(cipher, 0, n + 16); }
                catch (EndOfStreamException) { throw Payload.Invalid(); }
                byte[] nonce = new byte[12];
                BinaryPrimitives.WriteUInt32BigEndian(nonce, (uint)index);
                BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), (ulong)j);
                byte[] aad = [..Client.Bytes("authgo-payload-chunk-v1\0"), ..binding, ..nonce, (byte)(j == count - 1 ? 1 : 0)];
                // .NET 8 supports fully overlapping input/output; reuse one chunk buffer.
                aes.Decrypt(nonce, cipher.AsSpan(0, n), cipher.AsSpan(n, 16), cipher.AsSpan(0, n), aad);
                target.Write(cipher, 0, n);
                CryptographicOperations.ZeroMemory(cipher.AsSpan(0, n));
            }
            if (source.ReadByte() != -1) throw Payload.Invalid();
        }
        catch (CryptographicException) { throw Payload.Invalid(); }
        finally { CryptographicOperations.ZeroMemory(cipher); }
    }

    public static void DecryptPayloadFile(Stream target, byte[] ciphertext, Payload payload, byte[] key, int index)
    {
        using var source = new MemoryStream(ciphertext, false);
        DecryptPayloadFile(target, source, ciphertext.LongLength, payload, key, index);
    }
}
