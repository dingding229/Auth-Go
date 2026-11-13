<script setup lang="ts">
import { onMounted, ref, watch, nextTick } from "vue";
import { get } from "../lib/http";
import { idText, text, type Page, type Row } from "../lib/json";
const props = defineProps<{
  modelValue: string;
  endpoint: string;
  params?: Row;
  disabled?: boolean;
  placeholder?: string;
}>();
const emit = defineEmits<{ "update:modelValue": [value: string] }>();
const select = ref<{ blur: () => void; focus: () => void }>();
const query = ref("");
const options = ref<Row[]>([]),
  busy = ref(false);
let serial = 0;
async function search(q = "") {
  query.value = q;
  const n = ++serial;
  busy.value = true;
  try {
    const data = await get<Page>(
      props.endpoint,
      { q, page_size: 100, ...props.params },
      { quiet: true },
    );
    if (n === serial)
      options.value = [...data.items].sort(
        (a, b) => Number(exact(b, q)) - Number(exact(a, q)),
      );
  } catch {
    if (n === serial) options.value = [];
  } finally {
    if (n === serial) busy.value = false;
  }
}
function exact(item: Row, value: string) {
  const q = value.trim().toLocaleLowerCase();
  return (
    !!q &&
    [item.name, item.username, item.email].some(
      (v) => String(v ?? "").toLocaleLowerCase() === q,
    )
  );
}
async function enter(event: KeyboardEvent) {
  if (event.isComposing) return;
  // Enter selects a candidate even before the dropdown's remote debounce opens
  // it. Prefer exact names/emails, then the option highlighted by native arrows.
  event.preventDefault();
  event.stopPropagation();
  const input = event.target as HTMLInputElement;
  const q = input.value || query.value;
  const active = input.getAttribute("aria-activedescendant");
  const hovered = active
    ? document.getElementById(active)?.dataset.resourceId
    : undefined;
  const normalized = q.trim().toLocaleLowerCase();
  const candidates = options.value.filter((item) =>
    [item.name, item.username, item.email].some((value) =>
      String(value ?? "")
        .toLocaleLowerCase()
        .includes(normalized),
    ),
  );
  const match =
    candidates.find((item) => exact(item, q)) ||
    candidates.find((item) => idText(item.id) === hovered) ||
    candidates[0];
  // A new remote query may still be loading. Do not select an old, unrelated
  // cached user (or keep a previously selected user) when Enter arrives early.
  if (!match) {
    emit("update:modelValue", "");
    return;
  }
  emit("update:modelValue", idText(match.id));
  select.value?.blur();
  await nextTick();
  select.value?.focus();
}

onMounted(() => {
  void search();
});
watch(
  () => [props.endpoint, props.params],
  () => {
    void search();
  },
  { deep: true },
);
</script>
<template>
  <el-select
    ref="select"
    default-first-option
    :reserve-keyword="false"
    :model-value="modelValue"
    :disabled="disabled"
    clearable
    filterable
    remote
    :remote-method="search"
    :loading="busy"
    :aria-busy="busy"
    :placeholder="placeholder || '输入名称搜索，最多显示100项'"
    @keydown.enter.capture="enter"
    @update:model-value="emit('update:modelValue', String($event ?? ''))"
  >
    <el-option
      v-if="modelValue && !options.some((o) => idText(o.id) === modelValue)"
      :value="modelValue"
      :label="`编号 ${modelValue}`"
    />
    <el-option
      v-for="item in options"
      :key="idText(item.id)"
      :data-resource-id="idText(item.id)"
      :value="idText(item.id)"
      :label="`${text(item.name ?? item.username)}（${idText(item.id)}）`"
    />
  </el-select>
</template>
