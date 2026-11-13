<script setup lang="ts">
import NumberInput from "./NumberInput.vue";
import { ref, onMounted } from "vue";
import { get, post } from "../lib/http";
import { useTask, confirmAction, useLoadTask } from "../composables/tasks";
import { type Row } from "../lib/json";
import CopyField from "./CopyField.vue";
import RequestNotice from "./RequestNotice.vue";
const task = useTask(),
  loadTask = useLoadTask(),
  key = ref<Row>(),
  hours = ref(24);
async function load() {
  await loadTask.run(async () => {
    key.value = await get("/applications/gateway");
  });
}
async function rotate() {
  await task.run(async () => {
    await confirmAction(
      "更新全局通信密钥后，旧接入配置仅在过渡期内有效。必须重新构建并发布所有客户镜像。确认继续？",
      "更新通信配置（全局）",
      { action: "更新通信配置（全局）", danger: true },
    );
    key.value = await post("/applications/gateway/rotate", {
      overlap_hours: hours.value,
    });
  }, "通信配置已更新，请重新构建客户镜像");
}
onMounted(load);
</script>
<template>
  <details class="technical-options">
    <summary>全局通信密钥（高级）</summary>
    <request-notice
      :error="loadTask.error.value"
      :busy="loadTask.busy.value"
      @retry="load"
    />
    <p>
      通信密钥属于构建时信任根。轮换后须重新构建客户镜像；不得从环境变量或文件替换配置。
    </p>
    <copy-field v-if="key" :value="key.public_key" label="网关公钥" /><el-form
      label-position="top"
      @submit.prevent="rotate"
    >
      <request-notice :error="task.error.value" />
      <el-form-item label="旧配置过渡时长（小时）">
        <number-input v-model="hours" :min="1" :max="8760" />
      </el-form-item><el-button native-type="submit" :loading="task.busy.value" type="danger">
        更新通信配置（全局）
      </el-button>
    </el-form>
  </details>
</template>
