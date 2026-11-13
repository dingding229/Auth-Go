using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using AuthGo;

if (args.Contains("sealed-bootstrap-probe"))
{
    Environment.ExitCode = await SealedTests.RunProbe(args);
    return;
}
if (args.Contains("runner"))
{
    Runner.Run();
    return;
}
static string S(JsonNode n, string k) => n[k]!.GetValue<string>();
static byte[] H(JsonNode n, string k) => Convert.FromHexString(S(n, k));
static void Check(bool x)
{
    if (!x)
        throw new Exception("vector mismatch");
}
var root = "sdk/vectors/";
var v = JsonNode.Parse(File.ReadAllText(root + "v2.json"))!;
var h = JsonNode.Parse(File.ReadAllText(root + "hkdf.json"))!;
Check(
    Convert
        .ToHexString(
            Client.Hkdf(
                H(h, "ikm_hex"),
                H(h, "salt_hex"),
                H(h, "info_hex"),
                h["length"]!.GetValue<int>()
            )
        )
        .ToLowerInvariant() == S(h, "okm_hex")
);
var shared = Client.Shared(H(v, "ephemeral_private_hex"), Client.Decode(S(v, "gateway_public")));
var aad = H(v, "request_aad_hex");
foreach (var direction in new[] { "request", "response" })
    Check(
        Convert
            .ToHexString(
                Client.Hkdf(shared, SHA256.HashData(aad), Client.Bytes("authgo/v2/" + direction))
            )
            .ToLowerInvariant() == S(v, direction + "_key_hex")
    );
var req = v["request"]!;
var padded = Client.Open(
    H(v, "request_key_hex"),
    Client.Decode(S(req, "n")),
    Client.Decode(S(req, "c")),
    aad
);
Check(Convert.ToHexString(padded).ToLowerInvariant() == S(v, "padding_hex"));
Check(Encoding.UTF8.GetString(Client.Unpad(padded)) == S(v, "inner"));
var res = v["response"]!;
Check(
    Encoding.UTF8.GetString(
        Client.Unpad(
            Client.Open(
                H(v, "response_key_hex"),
                Client.Decode(S(res, "n")),
                Client.Decode(S(res, "c")),
                H(v, "response_aad_hex")
            )
        )
    ) == S(v, "response_plain")
);
var inner = JsonNode.Parse(S(v, "inner"))!;
var body = inner["body"]!.ToJsonString(
    new() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }
);
Check(
    Convert
        .ToHexString(
            HMACSHA256.HashData(
                Client.Bytes("test-secret-only"),
                Client.Bytes(
                    S(inner, "op")
                        + S(inner, "timestamp")
                        + S(inner, "nonce")
                        + Client.Hash(Client.Bytes(body))
                )
            )
        )
        .ToLowerInvariant() == S(inner, "signature")
);
var pub = Client.Decode(S(v, "ed25519_public"));
var p = S(v, "ticket").Split('.');
Check(
    Client.VerifySignature(
        pub,
        [.. Client.Bytes("authgo-ticket-v2\0"), .. Client.Decode(p[0])],
        Client.Decode(p[1])
    )
);
Check(!Client.VerifySignature(pub, [..Client.Bytes("invalid-domain\0"), ..Client.Decode(p[0])], Client.Decode(p[1])));
var key = Client.Hkdf(
    H(v, "unlock_seed_hex"),
    [],
    Client.Bytes("authgo-unlock-v2\0" + S(v, "unlock_label"))
);
Check(Convert.ToHexString(key).ToLowerInvariant() == S(v, "unlock_key_hex"));
p = S(v, "resource").Split('.');
Check(
    Encoding.UTF8.GetString(
        Client.Open(
            key,
            Client.Decode(p[1]),
            Client.Decode(p[2]),
            Client.Bytes("authgo-resource-v2\0settings")
        )
    ) == "hello"
);
var u = JsonNode.Parse(File.ReadAllText(root + "update-response.json"))!;
var cases = new List<JsonNode> { u };
cases.AddRange(u["docker_cases"]!.AsArray().Select(x => x!));
foreach (var c in cases)
{
    var env = c["response"]!;
    var signed = new JsonObject
    {
        ["code"] = env["code"]!.DeepClone(),
        ["data"] = env["data"]!.DeepClone(),
        ["ts"] = env["ts"]!.DeepClone(),
    };
    var canonical = Client.Canonical(signed);
    Check(canonical == S(c, "canonical_signed"));
    Check(
        Client.VerifySignature(
            Convert.FromBase64String(S(c, "public_key")),
            Client.Bytes(canonical),
            Convert.FromBase64String(S(c, "signature"))
        )
    );
}
var errors = JsonNode.Parse(File.ReadAllText(root + "error-classification.json"))!;
foreach (var c in errors["cases"]!.AsArray())
{
    bool refusal =
        c!["authenticated"]!.GetValue<bool>() && !Client.Temporary.Contains(S(c, "code"));
    Check(refusal == c["clear_cache"]!.GetValue<bool>());
}
foreach (var c in errors["update_cases"]!.AsArray())
    Check(!c!["clear_cache"]!.GetValue<bool>());
foreach (var c in JsonNode.Parse(File.ReadAllText(root + "fingerprint.json"))!["cases"]!.AsArray())
    Check(Client.IdentityHash(S(c!, "machine"), S(c!, "mac"), S(c!, "cpu")) == S(c!, "expected"));
foreach(var c in JsonNode.Parse(File.ReadAllText(root+"license-key.json"))!["cases"]!.AsArray()) {
    bool valid=true;
    try{Client.ValidateKey(S(c!,"key"));}catch(AuthGoException e){valid=false;Check(e.Code==S(c!,"code"));}
    Check(valid==c!["valid"]!.GetValue<bool>());
}
foreach(var c in JsonNode.Parse(File.ReadAllText(root+"fingerprint.json"))!["cpuinfo_cases"]!.AsArray()) {
    var cpu=Client.ParseLinuxCPU(S(c!,"cpuinfo"));Check(cpu==S(c!,"cpu"));
    if(cpu!="")Check(Client.IdentityHash(S(c!,"machine"),S(c!,"mac"),cpu)==S(c!,"expected"));
}
Console.WriteLine("{\"language\":\"csharp\",\"license_key_vectors\":16,\"cpuinfo_vectors\":8,\"result\":\"PASS\"}");
var canonicalVector = JsonNode.Parse(File.ReadAllText(root + "canonical.json"))!;
Check(
    Client.Canonical(Client.Parse(Client.Bytes(S(canonicalVector, "raw"))))
        == S(canonicalVector, "canonical")
);
Check(
    Client.VerifySignature(
        Convert.FromBase64String(S(canonicalVector, "public_key")),
        Client.Bytes(S(canonicalVector, "canonical")),
        Convert.FromBase64String(S(canonicalVector, "signature"))
    )
);
foreach (var invalid in canonicalVector["invalid"]!.AsArray())
{
    bool refused = false;
    try
    {
        Client.Parse(Client.Bytes(invalid!.GetValue<string>()));
    }
    catch (AuthGoException)
    {
        refused = true;
    }
    Check(refused);
}
Console.WriteLine("{\"language\":\"csharp\",\"vectors\":\"PASS\"}");

var containerVectors=JsonNode.Parse(File.ReadAllText(root+"container-identity.json"))!;
var containerType=typeof(Client).Assembly.GetType("AuthGo.ContainerIdentity")!;
var detect=containerType.GetMethod("Detect",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Static,null,[typeof(Func<string,byte[]>),typeof(Func<string,string>)],null)!;
var identityHash=containerType.GetMethod("Hash",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Static)!;
foreach(var value in containerVectors["detection"]!.AsArray()){
    var containerCase=value!;
    Func<string,byte[]> read=p=>containerCase["files"]![p]!=null?Encoding.UTF8.GetBytes(containerCase["files"]![p]!.GetValue<string>()):throw new FileNotFoundException();
    Func<string,string?> env=k=>containerCase["env"]![k]?.GetValue<string>();
    Check((bool)detect.Invoke(null,[read,env])! == containerCase["expected"]!.GetValue<bool>());
}
foreach(var containerItem in containerVectors["fingerprints"]!.AsArray())Check((string)identityHash.Invoke(null,[S(containerItem!,"id")])! == S(containerItem!,"expected"));
Console.WriteLine("{\"language\":\"csharp\",\"container_vectors\":\"PASS\"}");

var sessionVector=JsonNode.Parse(File.ReadAllText(root+"instance-session.json"))!["instance_session"]!;
Check(Client.Decode(S(sessionVector,"valid")).Length==sessionVector["bytes"]!.GetValue<int>());
foreach(var value in sessionVector["invalid"]!.AsArray()){
    var valid=false;try{valid=Client.Decode(value!.GetValue<string>()).Length==sessionVector["bytes"]!.GetValue<int>();}catch(AuthGoException){}Check(!valid);
}
Check(!sessionVector["persist_in_cache"]!.GetValue<bool>());

await GuardTests.Run();
PayloadTests.Run();

await SealedTests.Run();
