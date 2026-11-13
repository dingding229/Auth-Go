import templates from "./docker-templates.json";
import protectedTemplates from "./protected-templates.json";
export type DockerLanguage =
  "Go" | "Python" | "Node.js" | "Java" | "C#" | "PHP" | "Rust";
export type PHPMode = "cli" | "fpm" | "apache";
export const dockerLanguages: DockerLanguage[] = [
  "Go",
  "Python",
  "Node.js",
  "Java",
  "C#",
  "PHP",
  "Rust",
];
export const phpModes = [
  { label: "常驻CLI", value: "cli" },
  { label: "请求式FPM", value: "fpm" },
  { label: "请求式Apache", value: "apache" },
];
const keys = {
  Go: "go",
  Python: "python",
  "Node.js": "node",
  Java: "java",
  "C#": "csharp",
  PHP: "php",
  Rust: "rust",
} as const;
export function dockerTemplate(
  language: DockerLanguage,
  mode: PHPMode = "cli",
): { directory: string; files: Record<string, string> } {
  const key =
    language === "PHP" && mode !== "cli"
      ? (`php-${mode}` as "php-fpm" | "php-apache")
      : keys[language];
  return templates[key];
}
export function validDockerImage(image: string): boolean {
  return (
    image.length <= 255 &&
    /^(docker\.io\/)?[a-z0-9][a-z0-9_-]*\/[a-z0-9]+([._-]+[a-z0-9]+)*$/.test(
      image,
    )
  );
}
function safeImage(image: string) {
  if (!validDockerImage(image))
    throw new Error(
      "请填写Docker Hub镜像名，例如your-org/your-app（不含标签）",
    );
  return image;
}
// Preserve all runtime security/mount settings from the tested compose, removing
// only developer build sections and replacing image references for delivery.
export function customerCompose(
  language: DockerLanguage,
  mode: PHPMode,
  image: string,
  encryption?: EncryptionBuild,
): string {
  image = safeImage(image);
  const source = (
    encryption
      ? protectedTemplate(language, mode, encryption)
      : dockerTemplate(language, mode)
  ).files["docker-compose.yml"]!;
  let build = false;
  return source
    .split("\n")
    .filter((line) => {
      if (/^ {4}build:/.test(line)) {
        build = true;
        return false;
      }
      if (build && /^(?: {6}|\s*$)/.test(line)) return false;
      build = false;
      return true;
    })
    .map((line) => {
      if (!/^ {4}image:/.test(line)) return line;
      return `    image: ${image}${line.includes("fpm-nginx") ? "-nginx" : ""}:latest`;
    })
    .join("\n");
}
export function githubActions(
  language: DockerLanguage,
  mode: PHPMode,
  image: string,
  encryption?: EncryptionBuild,
): string {
  if (encryption) validateEncryptionBuild(encryption);
  image = safeImage(image).replace(/^docker\.io\//, "");
  const dir = (
    encryption
      ? protectedTemplate(language, mode, encryption)
      : dockerTemplate(language, mode)
  ).directory;
  return `name: Publish Docker image
on:
  push:
    tags: ['v*']
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
${encryption ? "      - uses: docker/setup-qemu-action@v3\n" : ""}      - uses: docker/setup-buildx-action@v3
      - uses: docker/login-action@v3
        with:
          username: \${{ secrets.DOCKERHUB_USERNAME }}
          password: \${{ secrets.DOCKERHUB_TOKEN }}
      - name: Read version
        id: release
        run: echo "version=\${GITHUB_REF_NAME#v}" >> "$GITHUB_OUTPUT"
      - name: Build and push
        uses: docker/build-push-action@v6
        with:
          context: .
          file: ${dir}/Dockerfile
          push: true
${encryption ? "          platforms: linux/amd64,linux/arm64\n" : ""}          tags: |
            ${image}:\${{ github.ref_name }}
            ${image}:latest
          build-args: |
            AUTHGO_CONFIG=\${{ vars.AUTHGO_CONFIG }}
            VERSION=\${{ steps.release.outputs.version }}
${encryption ? `            AUTHGO_TOOLS_IMAGE=${encryption.toolsImage}:${encryption.toolsVersion}\n            PAYLOAD_PUBLIC_KEY=${encryption.publicKey}\n            PAYLOAD_KEY_ID=${encryption.keyId}\n            PAYLOAD_APP_KEY=${encryption.appKey}\n` : ""}
${
  language === "PHP" && mode === "fpm"
    ? `      - name: Build and push FPM nginx
        uses: docker/build-push-action@v6
        with:
          context: .
          file: ${dir}/Dockerfile.nginx
          push: true
${encryption ? "          platforms: linux/amd64,linux/arm64\n" : ""}
          tags: |
            ${image}-nginx:\${{ github.ref_name }}
            ${image}-nginx:latest
`
    : ""
}`;
}
// Core integration only. Full tested lifecycle programs are provided alongside
// Dockerfiles, so signals and process exit stay in the business application.
export const guardSnippets: Record<DockerLanguage, string> = {
  Go: `// authConfig和version由Dockerfile的链接参数写入；ctx由业务信号上下文提供。
guard, err := sdk.StartGuard(ctx, sdk.GuardOptions{Config: authConfig, Version: version})
if err != nil { return sdk.ExitLicense }
defer guard.Close(context.Background())
// 业务入口调用guard.Require("")；同时等待ctx.Done()和guard.Done()。
select {
case <-ctx.Done(): return 0
case <-guard.Done(): return sdk.ExitLicense
}
`,
  Python: `from authgo import start_guard, EXIT_LICENSE
from _authgo_build import CONFIG, VERSION

guard = start_guard(config=CONFIG, version=VERSION)
try:
    guard.require("")  # 业务入口，不联网
    # 业务循环同时等待停止信号与guard.done，最终失败返回EXIT_LICENSE。
finally:
    guard.close()  # 正常停止释放席位，错误由业务记录
`,
  "Node.js": `import { startGuard, EXIT_LICENSE } from "authgo";
import build from "./authgo-build.json" with { type: "json" };
const guard = await startGuard({ config: build.config, version: build.version });
try {
  guard.require(""); // 业务入口，不联网
  // 与业务SIGTERM停止信号同时等待guard.done，失败返回EXIT_LICENSE。
} finally {
  await guard.close();
}
`,
  Java: `import io.authgo.Guard;
import io.authgo.GuardOptions;
// build为打进jar的authgo-build.properties；业务自行处理SIGTERM。
var opts = new GuardOptions();
opts.config = build.getProperty("config");
opts.version = build.getProperty("version");
try (var guard = Guard.start(opts)) {
  guard.require("");
  // 业务循环同时等待停止信号和guard.done()，失败返回Guard.EXIT_LICENSE。
}
`,
  "C#": `using AuthGo;
// Build由Dockerfile生成，ct由业务的SIGTERM处理器取消。
await using var guard = await Guard.StartAsync(new GuardOptions {
  Config = Build.Config, Version = Build.Version
}, ct);
guard.Require("");
// 业务循环同时等待停止信号与guard.Done，失败返回Guard.ExitLicense。
`,
  PHP: `<?php
require '/app/sdk/Client.php';
require '/app/authgo-build.php';
$guard = AuthGo\\start_guard(['config'=>CONFIG, 'version'=>VERSION]);
try {
    $guard->require(); // 关键业务入口，不联网
    // 常驻业务循环反复调用tick()；最终失败由业务exit(AuthGo\\EXIT_LICENSE)。
    $guard->tick();
} finally {
    $guard->close(); // 业务收到SIGTERM后关闭、释放；SDK不处理信号
}
`,
  Rust: `use authgo::{Guard, GuardOptions, EXIT_LICENSE};
let guard = Guard::start(GuardOptions {
    config: env!("AUTHGO_CONFIG").into(),
    version: env!("CARGO_PKG_VERSION").into(),
    ..Default::default()
})?;
guard.require("")?;
// 业务循环同时等待停止信号和guard.done()；最终失败返回EXIT_LICENSE。
guard.close()?;
`,
};
export function guardCode(language: DockerLanguage, mode: PHPMode): string {
  if (language === "PHP" && mode !== "cli")
    return dockerTemplate(language, mode).files["index.php"]!;
  return guardSnippets[language];
}
export { templates as dockerTemplates };

export interface EncryptionBuild {
  toolsImage: string;
  toolsVersion: string;
  keyId: string;
  publicKey: string;
  appKey: string;
}
export function validateEncryptionBuild(e: EncryptionBuild): void {
  if (
    !/^(?:[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?\/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)+$/.test(
      e.toolsImage,
    ) ||
    e.toolsImage.length > 255 ||
    !/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(e.toolsVersion)
  )
    throw new Error("请先在系统设置配置有效工具镜像名和版本");
  if (
    !/^[a-z0-9_-]{1,128}$/.test(e.keyId) ||
    !/^[A-Za-z0-9_-]{43}$/.test(e.publicKey) ||
    !/^[A-Za-z0-9_-]{1,256}$/.test(e.appKey)
  )
    throw new Error("请读取当前有效打包公钥及软件标识");
}
export function protectedTemplate(
  language: DockerLanguage,
  mode: PHPMode,
  e: EncryptionBuild,
): { directory: string; files: Record<string, string> } {
  validateEncryptionBuild(e);
  const key =
    language === "PHP" && mode !== "cli" ? `php-${mode}` : keys[language];
  const source = (
    protectedTemplates as Record<
      string,
      { directory: string; files: Record<string, string> }
    >
  )[key];
  if (!source) throw new Error("加密示例尚未就绪");
  const files = { ...source.files };
  for (const [arg, value] of Object.entries({
    AUTHGO_TOOLS_IMAGE: `${e.toolsImage}:${e.toolsVersion}`,
    PAYLOAD_PUBLIC_KEY: e.publicKey,
    PAYLOAD_KEY_ID: e.keyId,
    PAYLOAD_APP_KEY: e.appKey,
  }))
    files.Dockerfile = files.Dockerfile!.replace(
      new RegExp(`^ARG ${arg}(?:=.*)?$`, "gm"),
      `ARG ${arg}=${value}`,
    );
  return { directory: source.directory, files };
}
export function sealedGuardCode(
  language: DockerLanguage,
  mode: PHPMode,
): string {
  const snippets: Record<DockerLanguage, string> = {
    Go: guardSnippets.Go,
    Rust: guardSnippets.Rust,
    Python:
      'guard = start_guard(config=CONFIG, version=VERSION)\ntry:\n    guard.install_sealed("core")\n    import core\nfinally:\n    guard.close()\n',
    "Node.js":
      'const guard = await startGuard({config: build.config, version: build.version});\ntry {\n  const core = await guard.requireSealed("core");\n} finally { await guard.close(); }\n',
    Java: '// Bootstrap owns Guard, memory ClassLoader and protected main lifecycle.\npublic static void main(String[] args) throws Exception {\n  var options = new io.authgo.GuardOptions();\n  options.config = CONFIG; options.version = VERSION;\n  io.authgo.Bootstrap.run(options, "app", args);\n}\n',
    "C#": '// Business.csproj: include $(AuthGoSdkDir)/AuthGo.Watermark.cs (see generated Core.csproj).\n// Do not enable PublishTrimmed, PublishAot or PublishSingleFile.\n// Bootstrap owns Guard and in-memory AssemblyLoadContext.\nreturn await AuthGo.Bootstrap.RunAsync(new AuthGo.GuardOptions { Config=Build.Config, Version=Build.Version }, args, "app");\n',
    PHP: '$guard = AuthGo\\Guard::start(["config"=>CONFIG, "version"=>VERSION]);\n$guard->installSealed("core");\nrequire "authgo-sealed://core/bootstrap.php";\n// CLI: event loop tick(); request modes: controller catches errors and returns 503.\n',
  };
  return (
    snippets[language] +
    (language === "PHP" && mode !== "cli"
      ? "// FPM/Apache: no worker exit; opcache disabled for this protected request.\n"
      : "")
  );
}
export { protectedTemplates };
