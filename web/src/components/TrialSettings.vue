<script setup lang="ts">
import NumberInput from "./NumberInput.vue";
import { watch, reactive } from "vue";
import { get, patch } from "../lib/http";
import { useTask, useLoadTask } from "../composables/tasks";
import TemplateSelect from "./TemplateSelect.vue";
import { idText, parseJSON } from "../lib/json";
import SectionPanel from "./SectionPanel.vue";
import RequestNotice from "./RequestNotice.vue";
const props = defineProps<{ id: string }>(),
  task = useTask(),
  loadTask = useLoadTask();
const settings = reactive({
  trial_enabled: false,
  trial_days: 14,
  trial_template_id: null as unknown,
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
          客户不填写AUTHGO_LICENSE即可试用。关闭后已发放的试用继续有效。
        </p>
      </el-form-item>
      <el-form-item label="试用天数">
        <number-input
          v-model="settings.trial_days"
          :min="1"
          :max="365"
          :precision="0"
        />
        <p class="field-hint">
          试用同时运行1个实例，需要稳定联网，不提供断网宽限。同一网络共用一个试用。
        </p>
      </el-form-item>
      <template-select
        :app-id="id"
        :model-value="idText(settings.trial_template_id)"
        label="试用功能模板"
        @update:model-value="
          settings.trial_template_id = $event ? parseJSON($event) : null
        "
      />
      <p v-if="!settings.trial_template_id" class="field-hint">
        不使用模板，功能项为空
      </p>
      <p class="field-hint">
        试用仅复制模板的功能项；实例数固定为1，有效期仍使用试用天数。已发放的试用不受模板修改影响。
      </p>
      <el-button type="primary" native-type="submit" :loading="task.busy.value">
        保存试用设置
      </el-button>
    </el-form>
  </section-panel>
</template>
