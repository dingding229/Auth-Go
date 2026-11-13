import { expect, it } from "vitest";
import { readFileSync } from "node:fs";
import {
  protectedTemplates,
  protectedTemplate,
  sealedGuardCode,
  githubActions,
  dockerLanguages,
  validateEncryptionBuild,
} from "../src/lib/docker-wizard";
const build = {
  toolsImage: "registry.example.com/team/authgo-tools",
  toolsVersion: "v1.0.0",
  keyId: "pk_test",
  publicKey: "a".repeat(43),
  appKey: "app_test",
};
it("七语言及PHP模式与真实加密示例一致，最终Dockerfile包含打包步骤", () => {
  for (const [name, template] of Object.entries(protectedTemplates) as [
    string,
    { directory: string; files: Record<string, string> },
  ][]) {
    expect(template.files.Dockerfile, name).toContain("authgo-pack");
    if (template.files["Dockerfile.nginx"])
      expect(template.files["Dockerfile.nginx.dockerignore"]).toContain(
        `!${template.directory}/nginx.conf.template`,
      );
    for (const [path, source] of Object.entries(template.files))
      expect(source).toBe(
        readFileSync(`../${template.directory}/${path}`, "utf8"),
      );
  }
  expect(Object.keys(protectedTemplates)).toHaveLength(9);
});
it.each(dockerLanguages)(
  "%s加密向导使用当前工具镜像、公钥、buildx每架构打包",
  (language) => {
    const template = protectedTemplate(language, "cli", build),
      actions = githubActions(
        language,
        "cli",
        "example-org/example-app",
        build,
      );
    expect(template.files.Dockerfile).toContain(
      "ARG AUTHGO_TOOLS_IMAGE=registry.example.com/team/authgo-tools:v1.0.0",
    );
    expect(actions).toContain("platforms: linux/amd64,linux/arm64");
    for (const value of [
      build.publicKey,
      build.keyId,
      build.appKey,
      "AUTHGO_TOOLS_IMAGE=registry.example.com/team/authgo-tools:v1.0.0",
    ])
      expect(actions).toContain(value);
    expect(
      sealedGuardCode(language, "cli").trim().split("\n").length,
    ).toBeLessThanOrEqual(20);
    expect(actions).not.toContain("AUTHGO_LICENSE=");
  },
);
it("不接受工具镜像或key的换行/命令注入，无配置不可伪造加密代码", () => {
  for (const key of Object.keys(build))
    expect(() =>
      validateEncryptionBuild({ ...build, [key]: "bad\nRUN echo injected" }),
    ).toThrow();
  expect(() =>
    validateEncryptionBuild({ ...build, toolsVersion: "" }),
  ).toThrow();
});
