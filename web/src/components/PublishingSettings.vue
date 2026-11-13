<script setup lang="ts">
import { onMounted, ref } from "vue";
import { get, patch, post } from "../lib/http";
import { useTask, useLoadTask, confirmAction } from "../composables/tasks";
import { record, type Row } from "../lib/json";
import RequestNotice from "./RequestNotice.vue";
const task = useTask(),
  loadTask = useLoadTask();
const verified = ref("");
const settings = ref<Row>(),
  username = ref(""),
  github = ref(""),
  docker = ref("");
async function load() {
  await loadTask.run(async () => {
    const loadedSettings = await get<Row>("/system/publishing");
    username.value = String(loadedSettings.docker_username || "");
    github.value = docker.value = "";
    settings.value = loadedSettings;
  });
}
onMounted(load);
async function save() {
  await task.run(async () => {
    verified.value = "";
    const body: Row = { docker_username: username.value.trim() };
    if (github.value) body.github_token = github.value;
    if (docker.value) body.docker_token = docker.value;
    try {
      settings.value = await patch("/system/publishing", body, {
        timeout: 25_000,
      });
    } finally {
      github.value = docker.value = "";
    }
  }, "发布凭据已保存");
}
async function clear(kind: "github_token" | "docker_token") {
  const name =
    kind === "github_token" ? "GitHub 访问令牌" : "Docker Hub 访问令牌";
  await task.run(async () => {
    await confirmAction(
      `清除 AuthGo 保存的${name}后，后台自动发布将无法使用，直到重新填写。此操作不会删除仓库已同步的 Secrets；如需撤销令牌，请在对应平台吊销。`,
      `清除 ${name}`,
      { action: `清除 ${name}`, danger: true },
    );
    verified.value = "";
    settings.value = await patch("/system/publishing", { [kind]: "" });
    github.value = docker.value = "";
  }, "令牌已清除");
}
async function verify() {
  verified.value = "";
  await task.run(async () => {
    const result = await post<Row>(
      "/system/publishing/verify",
      {},
      { timeout: 25_000 },
    );
    const gh = record(result.github),
      hub = record(result.docker_hub);
    if (!gh.valid || !hub.valid)
      throw new Error([gh.error, hub.error].filter(Boolean).join("；"));
    verified.value = `已验证：GitHub ${gh.login}，Docker Hub ${hub.username}`;
  });
}
</script>
<template>
  <section class="publishing-settings">
    <h2>GitHub 与 Docker Hub 发布</h2>
    <p>
      构建由 GitHub Actions 完成。AuthGo 不构建镜像，也不需要 Docker 套接字。
    </p>
    <p>
      GitHub 使用 fine-grained
      PAT，仅选择目标仓库：Contents、Secrets、Variables、Actions、Workflows
      读写，Metadata 只读。Docker Hub 令牌需要 Read &amp; Write。
    </p>
    <p>
      保存新令牌时会联网验证，失败不保存。两个令牌加密保存，只能写入，不会回显；留空保持已保存值。清除仅删除本服务保存值，不删除仓库
      Secrets，也不代替平台令牌吊销。
    </p>
    <p v-if="loadTask.busy.value && !settings" role="status">
      正在读取发布设置…
    </p>
    <request-notice
      :error="loadTask.error.value"
      :busy="loadTask.busy.value"
      @retry="load"
    />
    <request-notice :error="task.error.value" />
    <el-form v-if="settings" label-position="top" @submit.prevent="save">
      <el-form-item label="GitHub 访问令牌">
        <el-input
          v-model="github"
          type="password"
          autocomplete="new-password"
          :maxlength="4096"
        />
        <span>已设置：{{ settings.has_github_token ? "是" : "否" }}</span>
        <el-button
          v-if="settings.has_github_token"
          :disabled="task.busy.value"
          @click="clear('github_token')"
        >
          清除 GitHub 访问令牌
        </el-button>
      </el-form-item>
      <el-form-item label="Docker Hub 用户名">
        <el-input v-model="username" :maxlength="128" />
      </el-form-item>
      <el-form-item label="Docker Hub 访问令牌">
        <el-input
          v-model="docker"
          type="password"
          autocomplete="new-password"
          :maxlength="4096"
        />
        <span>已设置：{{ settings.has_docker_token ? "是" : "否" }}</span>
        <el-button
          v-if="settings.has_docker_token"
          :disabled="task.busy.value"
          @click="clear('docker_token')"
        >
          清除 Docker Hub 访问令牌
        </el-button>
      </el-form-item>
      <div class="action-toolbar">
        <el-button
          type="primary"
          native-type="submit"
          :loading="task.busy.value"
        >
          保存发布凭据
        </el-button>
        <el-button :loading="task.busy.value" @click="verify">
          验证
        </el-button>
      </div>
      <p v-if="verified" role="status">
        {{ verified }}
      </p>
    </el-form>
  </section>
</template>
