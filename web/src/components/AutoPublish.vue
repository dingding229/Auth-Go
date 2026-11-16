<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { get, post, patch } from "../lib/http";
import { useTask, useLoadTask, confirmAction } from "../composables/tasks";
import { dateText, rows, type Row } from "../lib/json";
import RequestNotice from "./RequestNotice.vue";
const props = defineProps<{
  id: string;
  language: string;
  mode: string;
  encrypted: boolean;
  ready: boolean;
}>();
const emit = defineEmits<{
  "saved-encryption": [value: boolean];
  selection: [value: { language: string; mode: string; encrypted: boolean }];
}>();
const task = useTask(),
  loadTask = useLoadTask(),
  runTask = useLoadTask();
const savedEncryption = ref<boolean>();
const repository = ref(""),
  branch = ref("main"),
  saved = ref(""),
  loaded = ref(false),
  version = ref(""),
  runs = ref<Row[]>([]);
const config = computed(() => ({
  repository: repository.value.trim(),
  branch: branch.value.trim() || "main",
  language: props.language,
  mode: props.language === "PHP" ? props.mode : "cli",
  encrypted: props.encrypted,
}));
const awaitingRun = ref(false);
let previousRuns = new Set<string>();
const dirty = computed(() => JSON.stringify(config.value) !== saved.value);
const busy = computed(
  () => task.busy.value || loadTask.busy.value || runTask.busy.value,
);
const active = computed(() =>
  runs.value.some((run) => run.status !== "completed"),
);
let generation = 0;
async function loadRuns() {
  const serial = generation,
    id = props.id;
  await runTask.run(async () => {
    const result = await get(`/applications/${id}/publishing/runs`);
    if (serial === generation) {
      runs.value = rows(result.items);
      if (runs.value.some((run) => !previousRuns.has(String(run.id))))
        awaitingRun.value = false;
    }
  });
  if (id !== props.id && loaded.value && repository.value) void loadRuns();
}
async function load() {
  const serial = ++generation,
    id = props.id;
  loaded.value = false;
  await loadTask.run(async () => {
    const result = await get(`/applications/${id}/publishing`);
    if (serial !== generation) return;
    repository.value = String(result.repository || "");
    branch.value = String(result.branch || "main");
    saved.value = JSON.stringify({
      repository: repository.value,
      branch: branch.value,
      language: result.language || "Go",
      mode: result.mode || "cli",
      encrypted: Boolean(result.encrypted),
    });
    emit("selection", {
      language: String(result.language || "Go"),
      mode: String(result.mode || "cli"),
      encrypted: Boolean(result.encrypted),
    });
    savedEncryption.value = Boolean(result.encrypted);
    emit("saved-encryption", savedEncryption.value);
    loaded.value = true;
    if (repository.value) void loadRuns();
  });
  // A new software selection must not be lost behind an earlier in-flight load.
  if (id !== props.id) void load();
}
watch(
  () => props.id,
  () => {
    runs.value = [];
    awaitingRun.value = false;
    repository.value = "";
    void load();
  },
  { immediate: true },
);
const timer = setInterval(() => {
  if ((active.value || awaitingRun.value) && !busy.value) void loadRuns();
}, 5000);
onBeforeUnmount(() => {
  generation++;
  clearInterval(timer);
});
async function save() {
  await task.run(async () => {
    if (
      !/^[A-Za-z0-9][A-Za-z0-9-]*\/[A-Za-z0-9_.-]+$/.test(
        config.value.repository,
      )
    )
      throw new Error("请填写 owner/repo 格式的 GitHub 仓库");
    const serial = generation,
      id = props.id,
      body = { ...config.value };
    await patch(`/applications/${id}/publishing`, body);
    if (serial === generation) {
      saved.value = JSON.stringify(body);
      savedEncryption.value = body.encrypted;
      emit("saved-encryption", body.encrypted);
      branch.value = body.branch;
      runs.value = [];
      awaitingRun.value = false;
      previousRuns.clear();
      void loadRuns();
    }
  }, "仓库与构建选项已保存，请同步配置到仓库");
}
async function action(kind: "test" | "sync" | "dispatch") {
  await task.run(
    async () => {
      const id = props.id,
        serial = generation;
      if (dirty.value) throw new Error("请先保存仓库与构建选项");
      if (kind === "sync") {
        await confirmAction(
          `将向 GitHub 仓库 ${config.value.repository} 写入或覆盖工作流文件 .github/workflows/authgo-publish.yml，并同步发布 Secrets 与 Variable。确认继续？`,
          "同步配置到仓库",
          { action: "同步配置到仓库", danger: true },
        );
        if (serial !== generation || dirty.value)
          throw new Error("仓库配置已变化，请重新确认");
      }
      if (kind === "dispatch")
        previousRuns = new Set(runs.value.map((run) => String(run.id)));
      await post(
        `/applications/${id}/publishing/${kind}`,
        kind === "dispatch" ? { version: version.value.trim() } : {},
      );
      if (serial === generation && kind !== "test") {
        if (kind === "dispatch") awaitingRun.value = true;
        void loadRuns();
      }
    },
    kind === "test"
      ? "GitHub 仓库、分支及模板文件均可访问"
      : kind === "sync"
        ? "工作流、两个 Secret 和 AUTHGO_CONFIG 已同步"
        : "发布请求已提交，请查看 GitHub 运行状态",
  );
}
function runText(run: Row) {
  const values: Record<string, string> = {
    queued: "排队中",
    in_progress: "构建中",
    completed: "已结束",
    waiting: "等待中",
    pending: "等待中",
    requested: "已请求",
    success: "成功",
    failure: "失败",
    cancelled: "已取消",
    skipped: "已跳过",
    timed_out: "超时",
    action_required: "需要操作",
    neutral: "中性",
    stale: "已失效",
    startup_failure: "启动失败",
  };
  const status = values[String(run.status)] || "未知状态";
  return run.conclusion
    ? `${status} · ${values[String(run.conclusion)] || "未知结论"}`
    : status;
}
</script>
<template>
  <section class="auto-publish">
    <h3>自动构建并发布到 Docker Hub</h3>
    <p>
      先在系统设置的“GitHub 与 Docker Hub
      发布”中保存全局凭据，再把上一步的模板文件放进目标仓库。
      同步只写固定工作流，不会上传业务代码或 Dockerfile。
    </p>
    <p v-if="loadTask.busy.value && !loaded" role="status">
      正在读取发布配置…
    </p>
    <request-notice
      :error="loadTask.error.value"
      :busy="loadTask.busy.value"
      @retry="load"
    />
    <request-notice :error="task.error.value" />
    <el-form v-if="loaded" label-position="top" @submit.prevent="save">
      <el-form-item label="GitHub 仓库（owner/repo）">
        <el-input v-model="repository" :maxlength="140" />
      </el-form-item>
      <el-form-item label="发布分支">
        <el-input v-model="branch" :maxlength="200" />
      </el-form-item>
      <p>
        构建选项：{{ language }} / {{ language === "PHP" ? mode : "cli" }}，
        {{
          encrypted ? "代码加密" : "不加密"
        }}。修改语言或加密选项后须重新保存并同步。
      </p>
      <p
        v-if="savedEncryption !== undefined && encrypted !== savedEncryption"
        class="field-hint"
      >
        自动发布：保存仓库配置后才生效
      </p>
      <div class="action-toolbar">
        <el-button native-type="submit" :loading="task.busy.value">
          保存仓库与构建选项
        </el-button>
      </div>
      <div class="action-toolbar">
        <el-button
          :disabled="busy || dirty || !repository || !ready"
          @click="action('test')"
        >
          测试连接
        </el-button>
        <el-button
          :disabled="busy || dirty || !repository || !ready"
          @click="action('sync')"
        >
          同步配置到仓库
        </el-button>
      </div>
    </el-form>
    <el-form
      v-if="loaded"
      label-position="top"
      @submit.prevent="action('dispatch')"
    >
      <el-form-item label="发布版本号">
        <el-input v-model="version" placeholder="例如 1.0.0" :maxlength="128" />
      </el-form-item>
      <el-button
        type="primary"
        native-type="submit"
        :disabled="busy || dirty || !repository || !ready || !version.trim()"
      >
        发布新版本
      </el-button>
    </el-form>
    <p>
      同步会更新
      .github/workflows/authgo-publish.yml；手动运行要求此工作流也已存在于默认分支。
      失败时可重试同步；触发结果不明确时先查看 GitHub，避免重复发布。
    </p>
    <h4>最近运行</h4>
    <p v-if="awaitingRun" role="status">
      发布请求已接收，正在等待 GitHub 创建运行。
    </p>
    <el-button :disabled="busy || !repository" @click="loadRuns">
      刷新运行状态
    </el-button>
    <request-notice
      :error="runTask.error.value"
      :busy="runTask.busy.value"
      @retry="loadRuns"
    />
    <ul>
      <li v-for="run in runs" :key="String(run.id)">
        <a :href="String(run.url)" target="_blank" rel="noopener noreferrer">
          {{ runText(run) }} · {{ dateText(run.created_at) }}
        </a>
      </li>
    </ul>
    <p>
      运行中自动刷新。构建成功后，Docker Hub
      版本同步会按现有轮询自动收录新标签。
    </p>
  </section>
</template>
