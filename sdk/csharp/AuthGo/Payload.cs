using System.Buffers.Binary;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace AuthGo;

public sealed record PayloadEnvelope(string E, string N, string C);

/// <summary>Complete original payload.json. Config binds the envelope, never the connection target.</summary>
public sealed record Payload(int V, string AppKey, string Version, string BuiltAt, string KeyId,
    string Config, string Manifest, PayloadEnvelope Envelope)
{
    static readonly string[] Fields = ["v", "app_key", "version", "built_at", "key_id", "config", "manifest", "envelope"];
    static readonly Regex Name = new(@"\A[a-z0-9_-]+\z", RegexOptions.CultureInvariant);
    static readonly Regex Semver = new(@"\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?\z", RegexOptions.CultureInvariant);
    internal static AuthGoException Invalid() => new("PAYLOAD_INVALID");
    internal static JsonObject Schema(JsonNode? value, string[] required, params string[] optional)
    {
        if (value is not JsonObject obj || required.Any(k => !obj.ContainsKey(k)) || obj.Any(k => !required.Contains(k.Key) && !optional.Contains(k.Key))) throw Invalid();
        return obj;
    }
    internal static string Text(JsonNode? value)
    {
        if (value?.GetValueKind() != JsonValueKind.String) throw Invalid();
        return Text(value.GetValue<string>());
    }
    internal static string Text(string value)
    {
        if (value is null) throw Invalid();
        for (int i = 0; i < value.Length; i++) if (char.IsSurrogate(value[i]) &&
            (!char.IsHighSurrogate(value[i]) || i + 1 >= value.Length || !char.IsLowSurrogate(value[++i]))) throw Invalid();
        return value;
    }
    internal static BigInteger Integer(JsonNode? value)
    {
        if (value?.GetValueKind() != JsonValueKind.Number) throw Invalid();
        string raw = value.ToJsonString();
        if (!Regex.IsMatch(raw, @"\A-?(0|[1-9][0-9]*)\z", RegexOptions.CultureInvariant)) throw Invalid();
        return BigInteger.Parse(raw, CultureInfo.InvariantCulture);
    }
    internal static byte[] LP(string value)
    {
        byte[] raw = Client.Bytes(value), prefix = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(prefix, checked((uint)raw.Length));
        return [..prefix, ..raw];
    }
    internal static byte[] LPAll(params string[] values) => values.SelectMany(LP).ToArray();

    // Go net/url.Parse HTTPS predicate. Do not normalize with System.Uri.
    internal static void Https(string value)
    {
        Text(value);
        if (Regex.IsMatch(value, @"[\x00-\x1f\x7f]")) throw Invalid();
        var match = Regex.Match(value, @"\A(?i:https)://([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#(.*))?\z");
        if (!match.Success) throw Invalid();
        string authority = match.Groups[1].Value, path = match.Groups[2].Value;
        if (authority.Length == 0 || authority.Contains('@') || match.Groups[3].Value.Length > 0 || match.Groups[4].Value.Length > 0) throw Invalid();
        if (authority.Contains('[') && !authority.StartsWith('[')) throw Invalid();
        if (authority.StartsWith('['))
        {
            int end = authority.LastIndexOf(']');
            if (end <= 1 || !Regex.IsMatch(authority[(end + 1)..], @"\A(:[0-9]*)?\z")) throw Invalid();
        }
        else if (authority.Contains(':'))
        {
            int end = authority.LastIndexOf(':');
            if (end == 0 || !Regex.IsMatch(authority[(end + 1)..], @"\A[0-9]*\z")) throw Invalid();
        }
        foreach (char c in authority) if (c < 128 && !(char.IsAsciiLetterOrDigit(c) || "_.~!$&'()*+,;=:[]<>\"%-".Contains(c))) throw Invalid();
        if (Regex.IsMatch(authority + path, @"%(?![0-9a-fA-F]{2})")) throw Invalid();
        foreach (Match escape in Regex.Matches(authority, "%([0-9a-fA-F]{2})"))
        {
            int code = int.Parse(escape.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            if (code < 128 && code != 37) throw Invalid();
        }
    }
    static void ValidateConfig(string value, string appKey)
    {
        if (Client.Bytes(value).Length > 32768 || !value.StartsWith("authgo2.", StringComparison.Ordinal)) throw Invalid();
        var c = Schema(Client.Parse(Client.Decode(value[8..])), ["url", "app_key", "app_secret", "public_key", "gateway_key"]);
        foreach (string key in new[] { "url", "app_key", "app_secret", "public_key", "gateway_key" }) Text(c[key]);
        if (Text(c["app_key"]) != appKey || Text(c["app_secret"]).Length == 0) throw Invalid();
        Https(Text(c["url"]));
        string pub = Text(c["public_key"]);
        byte[] publicKey = Convert.FromBase64String(pub);
        if (publicKey.Length != 32 || Convert.ToBase64String(publicKey) != pub || Client.Decode(Text(c["gateway_key"])).Length != 32) throw Invalid();
    }
    static byte[] ValidateManifest(string value, int version = 2)
    {
        byte[] raw = Client.Decode(value);
        if (raw.Length > (8 << 20)) throw Invalid();
        var m = Schema(Client.Parse(raw), ["files"]);
        if (m["files"] is not JsonArray files || files.Count is < 1 or > 65535) throw Invalid();
        var names = new HashSet<string>(StringComparer.Ordinal); int metadata = 0;
        for (int i = 0; i < files.Count; i++)
        {
            var f = Schema(files[i], ["name", "kind", "path", "size", "chunk_size", "encoding"], "python_version", "main_class", "architecture");
            foreach (var pair in f) if (pair.Key is not ("size" or "chunk_size")) Text(pair.Value);
            string name = Text(f["name"]), kind = Text(f["kind"]);
            BigInteger size = Integer(f["size"]);
            if (!Name.IsMatch(name) || Client.Bytes(name).Length > 128 || !names.Add(name) || Text(f["path"]) != i.ToString("D8", CultureInfo.InvariantCulture) + ".agc" ||
                size < 0 || size > long.MaxValue / 2 || Integer(f["chunk_size"]) != 1048576) throw Invalid();
            if (kind == "watermark") {
                if (version != 2 || name != "__authgo_watermark" || Text(f["encoding"]) != "raw" || size < 1 || size > (8 << 20) || f.Count != 6) throw Invalid();
                metadata++; continue;
            }
            if (version == 2 && name == "__authgo_watermark") throw Invalid();
            string encoding = kind switch { "python" or "php" or "dotnet" => "tar", "node" or "java" or "protect" => "raw", _ => "" };
            if (encoding == "" || Text(f["encoding"]) != encoding || kind == "python" && (f["python_version"]?.GetValue<string>() ?? "") == "" ||
                kind == "protect" && (f["architecture"]?.GetValue<string>() ?? "") is not ("amd64" or "arm64")) throw Invalid();
        }
        if (version == 2 && (metadata != 1 || files.Count < 2)) throw Invalid();
        return raw;
    }
    internal byte[] AAD()
    {
        if (V != 2) throw Invalid();
        foreach (string value in new[] { AppKey, Version, BuiltAt, KeyId, Config, Manifest }) Text(value);
        if (AppKey == "" || Client.Bytes(AppKey).Length > 256 || Client.Bytes(KeyId).Length > 128 || !Name.IsMatch(KeyId) || Client.Bytes(Version).Length > 256 || !Semver.IsMatch(Version)) throw Invalid();
        string core = Version.Split('+', 2)[0]; int dash = core.IndexOf('-');
        if (dash >= 0 && core[(dash + 1)..].Split('.').Any(p => Regex.IsMatch(p, @"\A0[0-9]+\z"))) throw Invalid();
        if (!Regex.IsMatch(BuiltAt, @"\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z")) throw Invalid();
        // DateTime excludes year zero; validate Gregorian fields directly like Go/Python.
        int year = int.Parse(BuiltAt[..4], CultureInfo.InvariantCulture), month = int.Parse(BuiltAt[5..7], CultureInfo.InvariantCulture), day = int.Parse(BuiltAt[8..10], CultureInfo.InvariantCulture);
        bool leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        int[] days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
        if (month is < 1 or > 12 || day < 1 || day > days[month - 1] || int.Parse(BuiltAt[11..13], CultureInfo.InvariantCulture) > 23 ||
            int.Parse(BuiltAt[14..16], CultureInfo.InvariantCulture) > 59 || int.Parse(BuiltAt[17..19], CultureInfo.InvariantCulture) > 59) throw Invalid();
        ValidateConfig(Config, AppKey);
        return [..Client.Bytes($"authgo-payload-envelope-v{V}\0"), ..LPAll(AppKey, Version, BuiltAt, KeyId, Config), ..SHA256.HashData(ValidateManifest(Manifest, V))];
    }
    public byte[] PayloadBinding()
    {
        try
        {
            byte[] aad = AAD(), e = Client.Decode(Envelope.E), n = Client.Decode(Envelope.N), c = Client.Decode(Envelope.C);
            if (e.Length != 32 || n.Length != 12 || c.Length != 48) throw Invalid();
            return SHA256.HashData([..aad, ..e, ..n, ..c]);
        }
        catch { throw Invalid(); }
    }
    public JsonObject ToJson() => new()
    {
        ["v"] = V, ["app_key"] = AppKey, ["version"] = Version, ["built_at"] = BuiltAt, ["key_id"] = KeyId,
        ["config"] = Config, ["manifest"] = Manifest, ["envelope"] = new JsonObject { ["e"] = Envelope.E, ["n"] = Envelope.N, ["c"] = Envelope.C }
    };
    public static Payload ParsePayload(string raw)
    {
        try { return ParsePayload(new UTF8Encoding(false, true).GetBytes(Text(raw))); } catch { throw Invalid(); }
    }
    public static Payload ParsePayload(byte[] raw)
    {
        try
        {
            if (raw is null || raw.Length > 65536) throw Invalid();
            var p = Schema(Client.Parse(raw), Fields);
            int version = checked((int)Integer(p["v"])); if (version != 2) throw Invalid();
            var e = Schema(p["envelope"], ["e", "n", "c"]);
            var payload = new Payload(version, Text(p["app_key"]), Text(p["version"]), Text(p["built_at"]), Text(p["key_id"]), Text(p["config"]), Text(p["manifest"]), new(Text(e["e"]), Text(e["n"]), Text(e["c"])));
            payload.PayloadBinding(); return payload;
        }
        catch { throw Invalid(); }
    }
    internal Payload Validated() { try { return ParsePayload(Client.Canonical(ToJson())); } catch { throw Invalid(); } }
    internal byte[] RewrapAAD(byte[] ephemeral, byte[] challenge)
    {
        if (ephemeral.Length != 32 || challenge.Length != 32) throw Invalid();
        return [..Client.Bytes($"authgo-payload-rewrap-v{V}\0"), ..LPAll(AppKey, Version, BuiltAt, KeyId), ..SHA256.HashData(Client.Decode(Manifest)), ..ephemeral, ..challenge];
    }
    internal byte[] CacheLabel(string fingerprint) => [..Client.Bytes($"authgo-payload-cache-v{V}\0"), ..LPAll(AppKey, fingerprint, KeyId, Version), ..SHA256.HashData(Client.Decode(Manifest)), ..PayloadBinding()];
    internal byte[] Unwrap(PayloadEnvelope wrapped, byte[] privateKey, byte[] ephemeral, byte[] challenge)
    {
        byte[]? shared = null, kek = null;
        try
        {
            byte[] e = Client.Decode(wrapped.E), n = Client.Decode(wrapped.N), c = Client.Decode(wrapped.C);
            if (e.Length != 32 || n.Length != 12 || c.Length != 48) throw new Exception();
            shared = Client.Shared(privateKey, e); byte[] aad = RewrapAAD(ephemeral, challenge);
            kek = Client.Hkdf(shared, SHA256.HashData(aad), Client.Bytes("authgo/payload/v1/rewrap"));
            byte[] key = Client.Open(kek, n, c, aad); if (key.Length != 32) throw new Exception(); return key;
        }
        catch { throw new AuthGoException("SDK_RESPONSE_INVALID"); }
        finally { if (shared != null) CryptographicOperations.ZeroMemory(shared); if (kek != null) CryptographicOperations.ZeroMemory(kek); }
    }
}
