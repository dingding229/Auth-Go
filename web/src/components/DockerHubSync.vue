<script setup lang="ts">
import { computed, ref, watch, onBeforeUnmount } from "vue";
import { get, post } from "../lib/http";
import { useTask } from "../composables/tasks";
import { dateText, type Row } from "../lib/json";
import RequestNotice from "./RequestNotice.vue";
const props = defineProps<{ id: string; image?: string }>();
const task = useTask(),
  state = ref<Row>(),
  connection = ref<Row>(),
  loading = ref(false),
  loadError = ref("");
const busy = computed(() => loading.value || task.busy.value);
let serial = 0;
async function load(background = false) {
  const current = ++serial,
    id = props.id;
  loading.value = true;
  if (!background) loadError.value = "";
  try {
    const result = await get(`/applications/${id}/dockerhub`);
    if (current === serial) {
      state.value = result;
      loadError.value = "";
    }
  } catch (error) {
    if (current === serial)
      loadError.value =
        error instanceof Error ? error.message : "无法读取同步状态";
  } finally {
    if (current === serial) loading.value = false;
  }
}
watch(
  () => [props.id, props.image],
  () => {
    state.value = undefined;
    connection.value = undefined;
    void load();
  },
  { immediate: true },
);
const timer = setInterval(() => {
  if (state.value?.configured && !busy.value) void load(true);
}, 5000);
onBeforeUnmount(() => {
  serial++;
  clearInterval(timer);
});
async function action(kind: "test" | "sync") {
  await task.run(
    async () => {
      const current = serial,
        id = props.id,
        result = await post(`/applications/${id}/dockerhub/${kind}`, {});
      if (current !== serial || id !== props.id) return;
      if (kind === "test") connection.value = result;
      const status = await get(`/applications/${id}/dockerhub`);
      if (current === serial && id === props.id) state.value = status;
    },
    kind === "test"
      ? "Docker Hub连接正常"
      : "Docker Hub同步已启动，可刷新查看结果",
  );
  // Sync failures retain their last successful result; load the persisted error/backoff.
  if (task.error.value) {
    const error = task.error.value;
    try {
      state.value = await get(`/applications/${props.id}/dockerhub`);
    } catch {
      /* Original error stays visible. */
    }
    task.error.value = error;
  }
}
</script>
<template>
  <div class="docker-hub-sync">
    <h3>Docker Hub版本同步</h3>
    <p class="muted">
      只读取公开仓库的正式版本标签，不下载镜像，无需令牌。使用系统设置中的轮询间隔，手动同步在后台执行，最长约90秒。
    </p>
    <request-notice :error="loadError" :busy="loading" @retry="load()" />
    <request-notice :error="task.error.value" />
    <p v-if="state && !state.configured">
      保存Docker
      Hub镜像名后自动开始同步；清空镜像名只停止同步，不删除已收录版本。
    </p>
    <template v-else-if="state">
      <p>
        {{ state.image }} ·
        {{ state.running ? "正在后台同步…" : state.last_result || "尚未同步" }}
      </p>
      <p>
        最近成功同步：{{ dateText(state.last_sync_at) }} · 下次同步：{{
          dateText(state.next_sync_at)
        }}
      </p>
      <p>
        收录版本：{{ state.collected ?? 0 }} · 已忽略标签：{{
          state.ignored ?? 0
        }}
      </p>
      <el-alert
        v-if="state.last_error"
        :title="String(state.last_error)"
        type="error"
        :closable="false"
      />
      <p v-if="connection">
        总标签数：{{ connection.total_tags }} · 首页可接受标签：{{
          connection.accepted_tags
        }}
        · 首页已忽略：{{ connection.ignored_tags }}
      </p>
      <div class="action-toolbar">
        <el-button
          :loading="busy"
          :disabled="!!state.running"
          @click="action('test')"
        >
          测试连接
        </el-button>
        <el-button
          :loading="busy"
          :disabled="!!state.running"
          @click="action('sync')"
        >
          立即同步
        </el-button>
        <el-button :loading="busy" @click="load()">
          刷新同步状态
        </el-button>
      </div>
    </template>
    <el-skeleton v-else-if="busy" :rows="3" animated />
  </div>
</template>
