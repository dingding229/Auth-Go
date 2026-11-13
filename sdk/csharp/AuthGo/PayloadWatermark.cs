using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace AuthGo;

/// <summary>Authenticated private index, never public offsets. All checks precede mutation.</summary>
internal static class PayloadWatermark
{
    internal sealed record Entry(string[] Path, long[] Offsets);
    internal sealed record File(int Index, List<Entry> Entries);
    internal sealed record Index(string Tag, List<File> Files);
    internal sealed record Patch(byte[] Target, int Offset);
    internal static byte[] Response(JsonNode? value)
    {
        if (value is not JsonValue scalar || !scalar.TryGetValue<string>(out var s) || s.Length != 64 || s.Any(c => !(c is >= '0' and <= '9' or >= 'a' and <= 'f')) || s.All(c => c == '0')) throw new AuthGoException("SDK_RESPONSE_INVALID");
        return Convert.FromHexString(s);
    }
    internal static bool Material(Payload p, byte[]? value) => value is not null && p.V == 2 && value.Length == 64 && value.AsSpan(32).IndexOfAnyExcept((byte)0) >= 0;
    static long Decimal(object value, long limit = long.MaxValue / 2)
    {
        if (value is not string s || s.Length is < 1 or > 19 || s.Length > 1 && s[0] == '0' || s.Any(c => c is < '0' or > '9') || !long.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out long n) || n > limit) throw Payload.Invalid();
        return n;
    }
    static string Safe(object value)
    {
        if (value is not string s || s.Length == 0 || s.Any(c => c < 32 || c == 127 || c is '\\' or ':') || s.Split('/').Any(p => p is "" or "." or "..")) throw Payload.Invalid();
        Payload.Text(s); return s;
    }
    // Exact bounded schema, strings only, no large intermediate unbounded DOM.
    ref struct Reader
    {
        Utf8JsonReader json;
        int files, entries, offsets;
        internal Reader(byte[] raw) { json = new Utf8JsonReader(raw, new JsonReaderOptions { MaxDepth = 64 }); files = entries = offsets = 0; }
        void Token(JsonTokenType type) { if (!json.Read() || json.TokenType != type) throw Payload.Invalid(); }
        string Text(bool started = false) { if (!started) Token(JsonTokenType.String); if (json.TokenType != JsonTokenType.String) throw Payload.Invalid(); return Payload.Text(json.GetString()!); }
        internal Dictionary<string, object> Object(string[] fields, bool started = false)
        {
            if (!started) Token(JsonTokenType.StartObject);
            if (json.TokenType != JsonTokenType.StartObject) throw Payload.Invalid();
            var result = new Dictionary<string, object>(StringComparer.Ordinal);
            while (json.Read() && json.TokenType != JsonTokenType.EndObject)
            {
                if (json.TokenType != JsonTokenType.PropertyName) throw Payload.Invalid();
                string name = Payload.Text(json.GetString()!);
                if (!fields.Contains(name) || result.ContainsKey(name)) throw Payload.Invalid();
                result.Add(name, name is "files" or "entries" or "path" or "offsets" ? Array(name) : Text());
            }
            if (json.TokenType != JsonTokenType.EndObject || result.Count != fields.Length) throw Payload.Invalid();
            return result;
        }
        List<object> Array(string name)
        {
            Token(JsonTokenType.StartArray); var result = new List<object>();
            while (json.Read() && json.TokenType != JsonTokenType.EndArray)
            {
                if (name == "files" && ++files > 65535 || name == "entries" && ++entries > 65535 || name == "offsets" && ++offsets > 65535 || name == "path" && result.Count >= 8) throw Payload.Invalid();
                result.Add(name == "files" ? Object(["index", "entries"], true) : name == "entries" ? Object(["path", "offsets"], true) : Text(true));
            }
            if (json.TokenType != JsonTokenType.EndArray) throw Payload.Invalid(); return result;
        }
        internal void End() { if (json.Read()) throw Payload.Invalid(); }
    }
    internal static Index Parse(byte[] raw, IReadOnlyList<PayloadFiles.File> publicFiles)
    {
        try
        {
            if (raw.Length is < 1 or > (8 << 20) || publicFiles.Count is < 1 or > 65535) throw Payload.Invalid();
            var reader = new Reader(raw); var root = reader.Object(["v", "tag", "files"]); reader.End();
            string tag = (string)root["tag"];
            if ((string)root["v"] != "1" || tag.Length != 32 || tag.Any(c => !(c is >= '0' and <= '9' or >= 'a' and <= 'f'))) throw Payload.Invalid();
            var seen = new HashSet<int>(); var files = new List<File>();
            foreach (Dictionary<string, object> f in (List<object>)root["files"])
            {
                int i = (int)Decimal(f["index"], 65534);
                if (i >= publicFiles.Count || !seen.Add(i) || publicFiles[i].Kind == "watermark") throw Payload.Invalid();
                string kind = publicFiles[i].Kind; var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase); var entries = new List<Entry>(); int count = 0;
                foreach (Dictionary<string, object> e in (List<object>)f["entries"])
                {
                    string[] path = ((List<object>)e["path"]).Select(Safe).ToArray();
                    if (!paths.Add(string.Join('\0', path)) || (kind switch { "node" or "protect" => path.Length != 0, "python" or "php" or "dotnet" => path.Length != 1, "java" => path.Length == 0, _ => true })) throw Payload.Invalid();
                    if (kind == "dotnet" && (path[0].Contains('/') || !path[0].EndsWith(".dll", StringComparison.OrdinalIgnoreCase))) throw Payload.Invalid();
                    var offsets = new List<long>(); long last = -96;
                    foreach (object value in (List<object>)e["offsets"]) { long n = Decimal(value); if (n < last + 96 || path.Length == 0 && n + 96 > publicFiles[i].Size) throw Payload.Invalid(); offsets.Add(n); last = n; }
                    if (offsets.Count == 0) throw Payload.Invalid(); count += offsets.Count; entries.Add(new(path, offsets.ToArray()));
                }
                if (count < 8) throw Payload.Invalid(); files.Add(new(i, entries));
            }
            if (files.Count == 0) throw Payload.Invalid();
            for (int i = 0; i < publicFiles.Count; i++) if (publicFiles[i].Kind != "watermark" && !seen.Contains(i)) throw Payload.Invalid();
            return new(tag, files);
        }
        catch { throw Payload.Invalid(); }
    }
    internal static List<Patch> Prepare(Dictionary<string, byte[]> targets, Index index, int fileIndex)
    {
        var selected = index.Files.SingleOrDefault(f => f.Index == fileIndex) ?? throw Payload.Invalid();
        byte[] expected = Encoding.ASCII.GetBytes(index.Tag + new string('0', 64)); var pending = new List<Patch>();
        foreach (var entry in selected.Entries)
        {
            if (entry.Path.Length != 1 || !targets.TryGetValue(entry.Path[0], out var target)) throw Payload.Invalid();
            foreach (long n in entry.Offsets) { if (n > target.Length - 96 || !target.AsSpan((int)n, 96).SequenceEqual(expected)) throw Payload.Invalid(); pending.Add(new(target, (int)n + 32)); }
        }
        return pending;
    }
    internal static void Apply(List<Patch> pending, byte[] material)
    {
        if (material.Length != 64 || material.AsSpan(32).IndexOfAnyExcept((byte)0) < 0) throw Payload.Invalid();
        byte[] hex = Encoding.ASCII.GetBytes(Convert.ToHexString(material.AsSpan(32)).ToLowerInvariant());
        try { foreach (var p in pending) hex.CopyTo(p.Target, p.Offset); } finally { CryptographicOperations.ZeroMemory(hex); }
    }
    internal static Index Read(string directory, Payload p, byte[] material)
    {
        if (!Material(p, material)) throw Payload.Invalid(); var files = PayloadFiles.Files(p);
        for (int i = 0; i < files.Count; i++) if (files[i].Kind == "watermark")
        {
            byte[] key = material[..32]; byte[]? raw = null;
            try { using var source = System.IO.File.OpenRead(Path.Combine(directory, files[i].Path)); using var output = new WipingMemoryStream(); PayloadFiles.DecryptPayloadFile(output, source, source.Length, p, key, i); raw = output.ToArray(); return Parse(raw, files); }
            finally { CryptographicOperations.ZeroMemory(key); if (raw is not null) CryptographicOperations.ZeroMemory(raw); }
        }
        throw Payload.Invalid();
    }
}
