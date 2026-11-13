using System.Buffers.Binary;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace AuthGo;

/// <summary>Language-neutral content-key cache, never launcher proof files.</summary>
internal sealed class PayloadCache
{
    internal const string Prefix = "AUTHGO-PAYLOAD-CACHE-v2.";
    const UnixFileMode Mode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    readonly string directory, fingerprint;
    internal readonly string Identity, Base;
    internal PayloadCache(string directory, string endpoint, string appKey, string fingerprint, byte[] publicKey)
    {
        this.directory = directory; this.fingerprint = fingerprint;
        var match = Regex.Match(endpoint, @"\A(https?://)([^/?#]*)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        string normalized = match.Success ? match.Groups[1].Value.ToLowerInvariant() + match.Groups[2].Value.ToLowerInvariant() + endpoint[match.Length..] : endpoint;
        Identity = string.Join('\0', normalized, appKey, fingerprint, Client.Hash(publicKey));
        Base = "authgo-payload-v2-" + Client.Hash(Client.Bytes(Identity)) + "-";
    }
    internal sealed record Material(string File, byte[] Key, byte[] AAD) : IDisposable
    {
        public void Dispose() => CryptographicOperations.ZeroMemory(Key);
    }
    static double Stamp(JsonNode? value) => value is null ? double.PositiveInfinity : DateTimeOffset.Parse(value.GetValue<string>(), System.Globalization.CultureInfo.InvariantCulture).ToUnixTimeMilliseconds() / 1000.0;
    internal Material Derive(Payload payload, JsonObject grant, double now, bool disabled)
    {
        if (disabled) throw new AuthGoException("SDK_CACHE_UNAVAILABLE");
        if (grant["issued_at"] is null || grant["grace_until"] is null) throw new AuthGoException("SDK_CACHE_INVALID");
        double issued = Stamp(grant["issued_at"]), grace = Stamp(grant["grace_until"]);
        if (grant["is_trial"]?.GetValue<bool>() == true || grace <= issued || now >= grace || issued > now + 300) throw new AuthGoException("SDK_GRACE_EXPIRED");
        if (grant["starts_at"] != null && now < Stamp(grant["starts_at"])) throw new AuthGoException("LICENSE_NOT_STARTED");
        if (now >= Stamp(grant["expires_at"])) throw new AuthGoException("LICENSE_EXPIRED");
        string seed = grant["unlock_hash"]?.GetValue<string>() ?? "";
        if (!Regex.IsMatch(seed, @"\A[0-9a-fA-F]{64}\z")) throw new AuthGoException("SDK_CACHE_INVALID");
        BigInteger id = Payload.Integer(grant["license_id"]);
        if (id <= 0 || id > ulong.MaxValue) throw new AuthGoException("SDK_CACHE_INVALID");
        byte[] label = payload.CacheLabel(fingerprint), digest = SHA256.HashData(label), license = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(license, (ulong)id);
        byte[] key = Client.Hkdf(Convert.FromHexString(seed), [], [..Client.Bytes("authgo-unlock-v2\0"), ..label]);
        return new(Path.Combine(directory, Base + Convert.ToHexString(digest).ToLowerInvariant() + ".cache"), key,
            [..Client.Bytes($"authgo-payload-cache-file-v{payload.V}\0"), ..digest, ..license]);
    }

    // .NET 8 System.Native normalizes Unix stat layouts (Linux/macOS, x64/arm64).
    // Layout/exports match dotnet/runtime v8.0.22 Interop.Stat.cs and pal_io.h.
    // No architecture-dependent libc struct stat marshalling or third-party package.
    [StructLayout(LayoutKind.Sequential)]
    internal struct FileStatus
    {
        internal int Flags, Mode;
        internal uint Uid, Gid;
        internal long Size, ATime, ATimeNsec, MTime, MTimeNsec, CTime, CTimeNsec,
            BirthTime, BirthTimeNsec, Device, RDevice, Inode;
        internal uint UserFlags;
    }
    [DllImport("System.Native", EntryPoint = "SystemNative_LStat", SetLastError = true)]
    static extern int LStat([MarshalAs(UnmanagedType.LPUTF8Str)] string path, out FileStatus info);
    [DllImport("System.Native", EntryPoint = "SystemNative_FStat", SetLastError = true)]
    static extern int FStat(SafeFileHandle handle, out FileStatus info);
    [DllImport("System.Native", EntryPoint = "SystemNative_Open", SetLastError = true)]
    static extern IntPtr UnixOpen([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags, int mode);
    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    static extern int LinuxOpen([MarshalAs(UnmanagedType.LPUTF8Str)] string path, int flags);
    internal static FileStatus Snapshot(string path)
    {
        if (OperatingSystem.IsWindows() || LStat(path, out var info) != 0) throw new IOException("cache identity unavailable");
        return info;
    }
    internal static SafeFileHandle OpenRead(string path)
    {
        if (OperatingSystem.IsWindows()) throw new IOException("cache permissions unavailable");
        // On Linux also use O_NONBLOCK so even a FIFO swap cannot block the reader.
        IntPtr fd = OperatingSystem.IsLinux() ? (IntPtr)LinuxOpen(path, 0x20000 | 0x800 | 0x80000) : UnixOpen(path, 0x0200 | 0x0010, 0);
        if (fd == (IntPtr)(-1)) throw new IOException("cache open");
        return new SafeFileHandle(fd, true);
    }
    static bool Regular(FileStatus info) => (info.Mode & 0xf000) == 0x8000;
    static void Check(FileStatus info)
    {
        if (!Regular(info) || (info.Mode & 0xfff) != 0x180 || info.Size < 0 || info.Size > 256) throw new IOException("cache file");
    }
    static bool Same(FileStatus a, FileStatus b) => a.Inode == b.Inode && a.Device == b.Device;
    internal static FileStatus VerifyHandle(string path, SafeFileHandle handle, FileStatus expected)
    {
        if (FStat(handle, out var opened) != 0) throw new IOException("cache descriptor");
        Check(opened); var current = Snapshot(path); Check(current);
        if (!Same(expected, opened) || !Same(opened, current) || opened.Size != expected.Size) throw new AuthGoException("SDK_CACHE_INVALID");
        return opened;
    }
    static bool Destination(string path)
    {
        if (OperatingSystem.IsWindows()) return false;
        if (LStat(path, out var info) == 0) return Regular(info);
        if (Marshal.GetLastPInvokeError() == 2) return true;
        throw new IOException("cache destination unavailable");
    }
    internal void Save(Payload payload, JsonObject grant, double now, bool disabled, byte[] key)
    {
        if (!PayloadWatermark.Material(payload, key)) return;
        string? temp = null;
        try
        {
            using var material = Derive(payload, grant, now, disabled);
            // If this platform cannot verify mode and descriptor identity, do not persist a key.
            if (!Destination(material.File)) return;
            byte[] nonce = RandomNumberGenerator.GetBytes(12);
            byte[] raw = Client.Bytes(Prefix + Client.B64([..nonce, ..Client.Seal(material.Key, nonce, key, material.AAD)]));
            if (OperatingSystem.IsWindows()) return;
            Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            temp = Path.Combine(directory, ".authgo-payload-" + Client.B64(RandomNumberGenerator.GetBytes(12)) + ".tmp");
            var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, UnixCreateMode = Mode };
            using (var output = new FileStream(temp, options))
            {
                File.SetUnixFileMode(output.SafeFileHandle, Mode); output.Write(raw); output.Flush(true);
                VerifyHandle(temp, output.SafeFileHandle, Snapshot(temp));
            }
            File.Move(temp, material.File, true);
        }
        catch { /* Best effort: storage failure must not fail online unlock. */ }
        finally { if (temp != null) try { File.Delete(temp); } catch { /* best effort */ } }
    }
    internal byte[] Load(Payload payload, JsonObject grant, double now, bool disabled)
    {
        using var material = Derive(payload, grant, now, disabled);
        byte[] raw;
        try
        {
            var before = Snapshot(material.File); Check(before);
            using var handle = OpenRead(material.File);
            var opened = VerifyHandle(material.File, handle, before);
            using var input = new FileStream(handle, FileAccess.Read);
            byte[] buffer = new byte[257]; int count = 0, got;
            while (count < buffer.Length && (got = input.Read(buffer, count, buffer.Length - count)) != 0) count += got;
            VerifyHandle(material.File, handle, opened);
            raw = buffer[..count];
        }
        catch (AuthGoException) { throw; }
        catch { throw new AuthGoException("SDK_CACHE_UNAVAILABLE"); }
        try
        {
            string text = new UTF8Encoding(false, true).GetString(raw);
            if (raw.Length > 256 || !text.StartsWith(Prefix, StringComparison.Ordinal)) throw new Exception();
            byte[] encrypted = Client.Decode(text[Prefix.Length..]);
            if (encrypted.Length != 92) throw new Exception();
            byte[] key = Client.Open(material.Key, encrypted[..12], encrypted[12..], material.AAD);
            if (!PayloadWatermark.Material(payload, key)) { CryptographicOperations.ZeroMemory(key); throw new Exception(); } return key;
        }
        catch { throw new AuthGoException("SDK_CACHE_INVALID"); }
    }
    internal void Clear(bool disabled)
    {
        if (disabled) return;
        try
        {
            foreach (string file in Directory.EnumerateFileSystemEntries(directory))
            {
                string name = Path.GetFileName(file);
                if (name.StartsWith(Base, StringComparison.Ordinal) && name.EndsWith(".cache", StringComparison.Ordinal)) try { File.Delete(file); } catch { /* best effort */ }
            }
        }
        catch { /* Cleanup must not mask an authenticated denial. */ }
    }
}
