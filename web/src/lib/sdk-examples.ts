import { minimalGoExample } from "./sdk-example";
export const sdkLanguages = [
  "Go",
  "Python",
  "Node.js",
  "Java",
  "C#",
  "PHP",
  "Rust",
  "其他语言",
] as const;
export type SDKLanguage = (typeof sdkLanguages)[number];
export const sdkExamples: Record<
  Exclude<SDKLanguage, "其他语言">,
  { install: string; code: string }
> = {
  Go: {
    install: "在消费项目的go.mod中：replace authgo/sdk => /本仓库/sdk/go",
    code: minimalGoExample,
  },
  Python: {
    install: "python -m pip install /本仓库/sdk/python",
    code: 'import os\nimport authgo\n\nAUTH_CONFIG = "authgo2.请在构建时替换为后台接入配置"\nclient = authgo.Client(AUTH_CONFIG)\nresult = client.check(os.environ["AUTHGO_LICENSE"])\nprint(result.status)\n',
  },
  "Node.js": {
    install: "npm install /本仓库/sdk/node（Node.js 22+，ES modules）",
    code: 'import { Client } from "authgo";\n\nconst AUTH_CONFIG = "authgo2.请在构建时替换为后台接入配置";\nconst client = new Client(AUTH_CONFIG);\nconst result = await client.check(process.env.AUTHGO_LICENSE);\nconsole.log(result.status);\n',
  },
  Java: {
    install:
      "javac -d out /本仓库/sdk/java/src/main/java/io/authgo/*.java Main.java\njava -cp out Main（JDK 17+）",
    code: 'import io.authgo.Client;\n\npublic class Main {\n  private static final String AUTH_CONFIG = "authgo2.请在构建时替换为后台接入配置";\n  public static void main(String[] args) {\n    var client = new Client(AUTH_CONFIG);\n    var result = client.check(System.getenv("AUTHGO_LICENSE"));\n    System.out.println(result.status);\n  }\n}\n',
  },
  "C#": {
    install:
      "dotnet add reference /本仓库/sdk/csharp/AuthGo/AuthGo.csproj（.NET 8）",
    code: 'using AuthGo;\n\nconst string AuthConfig = "authgo2.请在构建时替换为后台接入配置";\nvar client = new Client(AuthConfig);\nvar result = client.Check(Environment.GetEnvironmentVariable("AUTHGO_LICENSE")!);\nConsole.WriteLine(result.Status);\n',
  },
  PHP: {
    install:
      "require /本仓库/sdk/php/src/Client.php（PHP 8.1+，启用sodium与openssl）",
    code: '<?php\nrequire __DIR__ . "/sdk/php/src/Client.php";\n\nconst AUTH_CONFIG = "authgo2.请在构建时替换为后台接入配置";\n$client = new AuthGo\\Client(AUTH_CONFIG);\n$result = $client->check(getenv("AUTHGO_LICENSE"));\necho $result->status, PHP_EOL;\n',
  },
  Rust: {
    install: '在Cargo.toml中添加：authgo = { path = "/本仓库/sdk/rust" }',
    code: 'const AUTH_CONFIG: &str = "authgo2.请在构建时替换为后台接入配置";\nfn main() -> Result<(), Box<dyn std::error::Error>> {\n    let client = authgo::Client::new(AUTH_CONFIG)?;\n    let result = client.check(&std::env::var("AUTHGO_LICENSE")?)?;\n    println!("{}", result.status);\n    Ok(())\n}\n',
  },
};
