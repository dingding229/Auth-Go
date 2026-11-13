import { expect, it } from "vitest";
import { readFileSync } from "node:fs";
import {
  protectedTemplates,
  protectedTemplate,
  sealedGuardCode,
  githubActions,
  customerCompose,
  dockerLanguages,
  validateEncryptionBuild,
} from "../src/lib/docker-wizard";
const build = {
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
    expect(template.files.Dockerfile, name).toContain(
      "ARG AUTHGO_TOOLS_IMAGE=docker.io/dingding229/authgo:1.0.0",
    );
    expect(template.files["docker-compose.yml"], name).not.toContain(
      "AUTHGO_TOOLS_IMAGE",
    );
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
  "%s加密向导固定从主镜像打包并保留当前公钥与多架构构建",
  (language) => {
    const template = protectedTemplate(language, "cli", build),
      actions = githubActions(
        language,
        "cli",
        "example-org/example-app",
        build,
      );
    expect(template.files.Dockerfile).toContain(
      "FROM docker.io/dingding229/authgo:1.0.0 AS tools",
    );
    expect(actions).toContain("platforms: linux/amd64,linux/arm64");
    for (const value of [build.publicKey, build.keyId, build.appKey])
      expect(actions).toContain(value);
    expect(template.files.Dockerfile).not.toContain("AUTHGO_TOOLS_IMAGE");
    expect(actions).not.toContain("AUTHGO_TOOLS_IMAGE");
    expect(
      customerCompose(language, "cli", "example-org/example-app", build),
    ).not.toContain("AUTHGO_TOOLS_IMAGE");
    expect(
      sealedGuardCode(language, "cli").trim().split("\n").length,
    ).toBeLessThanOrEqual(20);
    expect(actions).not.toContain("AUTHGO_LICENSE=");
  },
);
it("不接受打包公钥或软件标识的换行和命令注入，无配置不可伪造加密代码", () => {
  for (const key of Object.keys(build))
    expect(() =>
      validateEncryptionBuild({ ...build, [key]: "bad\nRUN echo injected" }),
    ).toThrow();
  expect(() => validateEncryptionBuild({ ...build, publicKey: "" })).toThrow();
});

it("手动复制与服务端自动同步使用同一份加密 FPM 工作流契约", () => {
  const workflow = githubActions("PHP", "fpm", "example/app", {
    keyId: "key_test",
    publicKey: "a".repeat(43),
    appKey: "app_test",
  });
  expect(workflow).toBe(
    readFileSync(
      "../server/internal/publishing/testdata/php-fpm-workflow.yml",
      "utf8",
    ),
  );
});
