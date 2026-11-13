using System.Text.Json.Nodes;
using AuthGo;

public static class Runner
{
    static System.Net.Http.HttpClient TrustedClient(string pem)
    {
        var expected = System.Security.Cryptography.X509Certificates.X509Certificate2.CreateFromPem(
            pem
        );
        return new(
            new HttpClientHandler
            {
                AllowAutoRedirect = false,
                ServerCertificateCustomValidationCallback = (_, cert, _, errors) =>
                {
                    if (
                        cert == null
                        || (
                            errors
                            & System.Net.Security.SslPolicyErrors.RemoteCertificateNameMismatch
                        ) != 0
                    )
                        return false;
                    using var chain = new System.Security.Cryptography.X509Certificates.X509Chain();
                    chain.ChainPolicy.TrustMode = System
                        .Security
                        .Cryptography
                        .X509Certificates
                        .X509ChainTrustMode
                        .CustomRootTrust;
                    chain.ChainPolicy.CustomTrustStore.Add(expected);
                    chain.ChainPolicy.RevocationMode = System
                        .Security
                        .Cryptography
                        .X509Certificates
                        .X509RevocationMode
                        .NoCheck;
                    return chain.Build(cert);
                },
            }
        )
        {
            Timeout = System.Threading.Timeout.InfiniteTimeSpan,
        };
    }

    public static void Run()
    {
        Client? c = null;
        Result? result = null;
        JsonObject? update = null;
        double clock = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string? line;
        while ((line = Console.ReadLine()) != null)
        {
            var output = new JsonObject { ["code"] = "OK" };
            try
            {
                var p = JsonNode.Parse(line)!;
                string S(string k) => p[k]?.GetValue<string>() ?? "";
                switch (S("op"))
                {
                    case "init":
                        clock = p["time"]!.GetValue<double>();
                        c = new Client(
                            S("config"),
                            new()
                            {
                                HttpClient =
                                    null,
                                Clock = () =>
                                    DateTimeOffset.FromUnixTimeMilliseconds((long)(clock * 1000)),
                                Fingerprint =
                                    p["automatic"]?.GetValue<bool>()==true ? null : (p["fingerprint"]?.GetValue<string>() ?? new string('a',64)),
                                Version = p["unversioned"]?.GetValue<bool>()==true ? "" : (p["version"]?.GetValue<string>() ?? "1.0.0"),
                                CacheDir =
                                    p["cache_dir"]?.GetValue<string>()
                                    ?? Path.Combine(Path.GetTempPath(), "authgo-" + Guid.NewGuid()),
                            }
                        );
                        output["status"] = "ready";
                        break;
                    case "clock":
                        clock += p["seconds"]!.GetValue<double>();
                        break;
                    case "check":
                    case "activate":
                    case "verify":
                    case "heartbeat":
                        result = S("op") switch
                        {
                            "check" => c!.Check(S("key")),
                            "activate" => c!.Activate(S("key")),
                            "verify" => c!.Verify(),
                            _ => c!.Heartbeat(),
                        };
                        output["status"] = result.Status;
                        break;
                    case "guard_check":result=c!.GuardCheck(S("key"));output["status"]=result.Status;break;
                    case "trial_info":output["is_trial"]=result!.IsTrial;break;
                    case "release_seat": c!.ReleaseSeat();break;
                    case "entitlement": output["maintenance_until"]=result!.MaintenanceUntil;output["latest_entitled_version"]=result.LatestEntitledVersion;break;
                    case "validate": c!.Validate(result!.Ticket());break;
                    case "identity": output["fingerprint"]=(string)typeof(Client).GetField("fp",System.Reflection.BindingFlags.NonPublic|System.Reflection.BindingFlags.Instance)!.GetValue(c)!;break;
                    case "cache_warning": output["cache_warning"]=result!.CacheWarning!=null;break;
                    case "deactivate":
                        c!.Deactivate();
                        break;
                    case "announcements":
                        output["count"] = c!.Announcements().Count;
                        break;
                    case "check_update":
                        update = c!.CheckUpdate(p["version"]?.GetValue<string>() ?? "1.0.0");
                        output["available"] = update["available"]!.DeepClone();
                        output["version"] = update["version"]?.DeepClone();
                        output["docker_image"] = update["docker_image"]?.DeepClone(); output["docker_pull"] = update["docker_pull"]?.DeepClone();
                        break;
                    default:
                        throw new Exception();
                }
            }
            catch (AuthGoException e)
            {
                output = new() { ["code"] = e.Code };
                if(e.LatestVersion!="")output["latest_version"]=e.LatestVersion;
                if(e.Code=="MAINTENANCE_EXPIRED")output["latest_entitled_version"]=e.LatestEntitledVersion;
            }
            catch (Exception e)
            {
                output = new() { ["code"] = "RUNNER_ERROR", ["detail"] = e.GetType().Name };
            }
            Console.WriteLine(output.ToJsonString());
        }
    }
}
