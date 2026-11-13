<script setup lang="ts">
import { watch, reactive } from "vue";
import { get, patch } from "../lib/http";
import { useTask, useLoadTask } from "../composables/tasks";
import SectionPanel from "./SectionPanel.vue";
import RequestNotice from "./RequestNotice.vue";
const props = defineProps<{ id: string }>(),
  task = useTask(),
  loadTask = useLoadTask();
const settings = reactive({
  trial_enabled: false,
});
async function load() {
  await loadTask.run(async () => {
    Object.assign(settings, await get(`/applications/${props.id}/trial`));
  });
}
async function save() {
  await task.run(async () => {
    await patch(`/applications/${props.id}/trial`, settings);
  }, "试用设置已保存");
}
watch(() => props.id, load, { immediate: true });
</script>
<template>
  <section-panel title="免授权码试用">
    <request-notice
      :error="loadTask.error.value"
      :busy="loadTask.busy.value"
      @retry="load"
    />
    <el-form label-position="top" @submit.prevent="save">
      <request-notice :error="task.error.value" />
      <el-form-item label="允许客户免授权码试用">
        <el-switch v-model="settings.trial_enabled" />
        <p class="field-hint">
          客户不填写AUTHGO_LICENSE即可试用。试用不提供断网宽限，同一网络共用一个试用；关闭后已发放的试用继续有效。
        </p>
      </el-form-item>
      <p class="field-hint">
        试用天数由系统设置统一配置，试用功能项为空，所有软件使用同一规则。
      </p>
      <el-button type="primary" native-type="submit" :loading="task.busy.value">
        保存试用设置
      </el-button>
    </el-form>
  </section-panel>
</template>
