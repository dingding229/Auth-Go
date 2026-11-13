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

// client is the SDK client created with the compiled-in connection configuration.
export const announcementExamples: Record<
  Exclude<SDKLanguage, "其他语言">,
  string
> = {
  Go: `items, err := client.Announcements(context.Background())
if err != nil {
    log.Print("公告暂不可用")
} else {
    for _, note := range items { log.Printf("%s\\n%s", note.Title, note.Content) }
}`,
  Python: `try:
    for note in client.announcements():
        print(note.get("title", ""))
        print(note.get("content", ""))
except Exception:
    print("公告暂不可用")`,
  "Node.js": `try {
  for (const note of await client.announcements()) {
    console.log(note.title);
    console.log(note.content);
  }
} catch { console.warn("公告暂不可用"); }`,
  Java: `try {
  for (Object item : client.announcements()) {
    var note = (java.util.Map<?, ?>) item;
    System.out.println(note.get("title"));
    System.out.println(note.get("content"));
  }
} catch (RuntimeException error) { System.err.println("公告暂不可用"); }`,
  "C#": `try {
  foreach (var note in client.Announcements()) {
    Console.WriteLine(note?["title"]);
    Console.WriteLine(note?["content"]);
  }
} catch (Exception) { Console.Error.WriteLine("公告暂不可用"); }`,
  PHP: `try {
    foreach ($client->announcements() as $note) {
        echo $note['title'], PHP_EOL;
        echo $note['content'], PHP_EOL;
    }
} catch (Throwable $error) { echo "公告暂不可用", PHP_EOL; }`,
  Rust: `match client.announcements() {
    Ok(items) => {
        if let Some(notes) = items.as_array() {
            for note in notes { println!("{}\\n{}", note["title"].as_str().unwrap_or(""), note["content"].as_str().unwrap_or("")); }
        }
    }
    Err(_) => eprintln!("公告暂不可用"),
}`,
};
