<script setup lang="ts">
import { computed } from "vue";
import CrudPanel from "./CrudPanel.vue";
import { field, type Spec } from "../lib/schema";
const props = defineProps<{ id: string }>();
const spec = computed<Spec>(() => ({
  key: "feature_templates",
  title: "功能模板",
  singular: "功能模板",
  path: `/applications/${props.id}/templates`,
  search: false,
  fields: [
    field("name", "模板名称", {
      required: true,
      hint: "同一软件内唯一，1至64个字符。",
    }),
    field("features", "功能项（JSON对象）", {
      type: "json",
      default: "{}",
      required: true,
    }),
    field("default_max_activations", "默认实例数", {
      type: "number",
      nullable: true,
      min: 1,
      max: 1000000,
      hint: "留空不填入实例数。",
    }),
    field("default_days", "默认有效天数", {
      type: "number",
      nullable: true,
      min: 1,
      max: 36500,
      hint: "留空保留发放表单的有效期规则。",
    }),
    field("default_maintenance_days", "默认维护天数", {
      type: "number",
      nullable: true,
      min: 0,
      max: 36500,
      hint: "留空不填入维护天数，0表示不限。",
    }),
  ],
  columns: [
    { key: "name", title: "名称" },
    { key: "features", title: "功能项" },
    { key: "default_max_activations", title: "默认实例数" },
    { key: "default_days", title: "有效天数" },
    { key: "default_maintenance_days", title: "维护天数" },
  ],
}));
</script>
<template>
  <p class="field-hint">
    模板用于填入发放表单，填入后仍可修改。修改或删除模板不会改变已发放的授权。
  </p>
  <crud-panel :spec="spec" embedded edit-from-row />
</template>
