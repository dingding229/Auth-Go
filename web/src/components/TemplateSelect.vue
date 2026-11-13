<script setup lang="ts">
import { ref, watch, useId } from "vue";
import { get } from "../lib/http";
import { idText, rows, type Row } from "../lib/json";
const props = defineProps<{
  appId: string;
  modelValue: string;
  hideEmpty?: boolean;
  label: string;
}>();
const emit = defineEmits<{
  "update:modelValue": [id: string];
  selected: [value: Row];
}>();
const options = ref<Row[]>([]),
  busy = ref(false),
  error = ref("");
const selectId = useId();
let serial = 0;
async function load() {
  const n = ++serial;
  error.value = "";
  if (!props.appId) {
    busy.value = false;
    return;
  }
  busy.value = true;
  try {
    const items: Row[] = [];
    let page = 1;
    while (true) {
      const data = await get(
        `/applications/${encodeURIComponent(props.appId)}/templates`,
        { page, page_size: 100 },
      );
      if (n !== serial) return;
      const batch = rows(data.items);
      items.push(...batch);
      if (items.length >= Number(data.total) || !batch.length) break;
      page++;
    }
    options.value = items;
  } catch (e) {
    if (n === serial)
      error.value = e instanceof Error ? e.message : "读取功能模板失败";
  } finally {
    if (n === serial) busy.value = false;
  }
}
watch(
  () => props.appId,
  (_now, before) => {
    options.value = [];
    if (before !== undefined) emit("update:modelValue", "");
    void load();
  },
  { immediate: true },
);
function opened(value: boolean) {
  if (value) void load();
}
function select(value: unknown) {
  const id = String(value || "");
  emit("update:modelValue", id);
  const row = options.value.find((v) => idText(v.id) === id);
  if (row) emit("selected", row);
}
</script>
<template>
  <div
    v-if="appId && (!hideEmpty || options.length || error)"
    class="wide-field"
  >
    <label :for="selectId">{{ label }}</label>
    <el-select
      :id="selectId"
      :model-value="modelValue"
      :loading="busy"
      clearable
      placeholder="不使用模板"
      @update:model-value="select"
      @visible-change="opened"
    >
      <el-option
        v-for="item in options"
        :key="idText(item.id)"
        :value="idText(item.id)"
        :label="String(item.name)"
      />
    </el-select>
    <p v-if="error" class="field-hint" role="alert">
      {{ error }}<el-button text @click="load">
        重试
      </el-button>
    </p>
  </div>
</template>
