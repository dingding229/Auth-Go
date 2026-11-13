using AuthGo;

const string AuthConfig = "authgo2.请在构建时替换为后台接入配置";
var client = new Client(AuthConfig);
var result = client.Check(Environment.GetEnvironmentVariable("AUTHGO_LICENSE")!);
Console.WriteLine(result.Status);
