<script setup lang="ts">
import DataTable from "./DataTable.vue";
import { computed } from "vue";
import { record, text } from "../lib/json";
const props = defineProps<{ value: unknown }>();
function display(value: unknown): string {
  if (Array.isArray(value)) return value.map(display).join("、") || "—";
  if (value !== null && typeof value === "object")
    return (
      Object.entries(record(value))
        .map(([key, v]) => `${key}：${display(v)}`)
        .join("；") || "—"
    );
  return text(value);
}
const entries = computed(() =>
  Object.entries(record(props.value)).map(([name, value]) => ({
    name,
    value: display(value),
  })),
);
</script>
<template>
  <section
    v-if="entries.length"
    class="license-features"
    aria-label="授权功能项"
  >
    <h3>授权功能项</h3>
    <data-table
      :items="entries"
      :columns="[
        { key: 'name', title: '功能项', width: 110 },
        { key: 'value', title: '值', width: 130 },
      ]"
    />
  </section>
</template>
