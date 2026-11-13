<script setup lang="ts">
import { ref, watch } from "vue";
import type { Values } from "../lib/schema";
import { idText, stringify, type Row } from "../lib/json";
import TemplateSelect from "./TemplateSelect.vue";
const props = defineProps<{ values: Values }>();
const emit = defineEmits<{ applied: [values: Row] }>();
const selected = ref(""),
  applied = ref(false);
watch(
  () => props.values.app_id,
  () => {
    selected.value = "";
    applied.value = false;
  },
);
function apply(t: Row) {
  const values: Row = { features: stringify(t.features ?? {}, 2) };
  if (t.default_max_activations != null)
    values.max_activations = Number(t.default_max_activations);
  if (t.default_days != null) {
    values.validity_rule = "fixed_days";
    values.duration_days = Number(t.default_days);
  }
  if (t.default_maintenance_days != null)
    values.maintenance_days = Number(t.default_maintenance_days);
  emit("applied", values);
  applied.value = true;
}
</script>
<template>
  <template-select
    v-model="selected"
    :app-id="idText(values.app_id)"
    label="功能模板（可选）"
    hide-empty
    @selected="apply"
  />
  <p v-if="applied" class="field-hint wide-field" role="status">
    已填入模板内容，可继续修改
  </p>
</template>
