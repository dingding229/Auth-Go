<script setup lang="ts">
import SectionPanel from "./SectionPanel.vue";
import RequestNotice from "./RequestNotice.vue";
import { ref, onMounted } from "vue";
import { get, patch } from "../lib/http";
import type { Row } from "../lib/json";
import { field, type Field } from "../lib/schema";
import SchemaEditor from "./SchemaEditor.vue";
import { useTask, useLoadTask } from "../composables/tasks";
const task = useTask(),
  loadTask = useLoadTask(),
  settings = ref<Row>();
const fields: Field[] = [
  field("poll_minutes", "版本轮询间隔（分钟）", {
    type: "number",
    default: 10,
    min: 5,
    max: 1440,
    required: true,
    hint: "Docker Hub版本同步间隔，最短5分钟。",
  }),
];
async function load() {
  await loadTask.run(async () => {
    settings.value = await get("/system/updates");
  });
}
async function save(body: Row) {
  await task.run(async () => {
    await patch("/system/updates", body);
    await load();
  }, "更新设置已保存");
}
onMounted(load);
</script>
<template>
  <section-panel>
    <h2>自动版本更新</h2>
    <request-notice
      :error="loadTask.error.value"
      :busy="loadTask.busy.value"
      @retry="load"
    />
    <request-notice :error="task.error.value" />
    <schema-editor
      v-if="settings"
      :fields="fields"
      :initial="settings"
      :busy="task.busy.value"
      @save="save"
      @cancel="load"
    />
  </section-panel>
</template>
