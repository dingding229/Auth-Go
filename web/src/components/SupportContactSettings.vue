<script setup lang="ts">
import { onMounted, ref } from "vue";
import { supportSettings, saveSupportSettings } from "../lib/http";
import { useTask, useLoadTask } from "../composables/tasks";
import SectionPanel from "./SectionPanel.vue";
import RequestNotice from "./RequestNotice.vue";
const task = useTask(),
  loadTask = useLoadTask(),
  value = ref(""),
  loaded = ref(false);
async function load() {
  await loadTask.run(async () => {
    const result = await supportSettings();
    value.value =
      typeof result.support_contact === "string" ? result.support_contact : "";
    loaded.value = true;
  });
}
async function save() {
  await task.run(async () => {
    if ([...value.value].length > 200)
      throw new Error("支持联系方式最多 200 字");
    const result = await saveSupportSettings(value.value);
    value.value = result.support_contact;
  }, "支持联系方式已保存");
}
onMounted(load);
</script>
<template>
  <section-panel title="支持联系方式">
    <p class="muted">
      可填写支持邮箱、工单地址或其他联系方式，将显示在用户中心页脚和到期待处理事项中。选填，纯文本，最多
      200 字。
    </p>
    <request-notice
      :error="loadTask.error.value"
      :busy="loadTask.busy.value"
      @retry="load"
    />
    <el-skeleton v-if="loadTask.busy.value && !loaded" :rows="2" animated />
    <el-form v-if="loaded" label-position="top" @submit.prevent="save">
      <request-notice :error="task.error.value" />
      <el-form-item label="支持联系方式">
        <el-input
          v-model="value"
          type="textarea"
          :rows="3"
          maxlength="200"
          show-word-limit
          :disabled="task.busy.value"
          placeholder="例如：支持邮箱 support@example.com"
        />
      </el-form-item><el-button
        type="primary"
        native-type="submit"
        :loading="task.busy.value"
      >
        保存支持联系方式
      </el-button>
    </el-form>
  </section-panel>
</template>
