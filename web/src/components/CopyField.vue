<script setup lang="ts">
import { computed, ref, watch, onBeforeUnmount } from "vue";
import {
  CopyDocument,
  View,
  Hide,
  ArrowDown,
  ArrowUp,
} from "@element-plus/icons-vue";
const props = withDefaults(
  defineProps<{
    value: unknown;
    display?: string;
    sensitive?: boolean;
    compact?: boolean;
    label?: string;
    expandable?: boolean;
  }>(),
  { label: "内容", expandable: true, display: undefined },
);
const revealed = ref(false),
  expanded = ref(false),
  copied = ref(false),
  error = ref("");
const value = computed(() => String(props.value ?? ""));
let timer: ReturnType<typeof setTimeout> | undefined;
watch(value, () => {
  revealed.value = false;
  copied.value = false;
  error.value = "";
  expanded.value = false;
});
onBeforeUnmount(() => clearTimeout(timer));
async function copy() {
  error.value = "";
  try {
    await navigator.clipboard.writeText(value.value);
    copied.value = true;
    clearTimeout(timer);
    timer = setTimeout(() => (copied.value = false), 3000);
  } catch {
    error.value = "无法复制，请展开后手动选择复制";
  }
}
</script>
<template>
  <div
    class="copy-field"
    :class="{ 'is-expanded': expanded, 'is-compact': compact }"
  >
    <span class="copy-field-value" :aria-label="label">{{
      sensitive && !revealed ? "••••••••" : (display ?? value) || "—"
    }}</span>
    <span class="copy-controls">
      <el-button
        v-if="sensitive"
        text
        :aria-label="`${revealed ? '隐藏' : '显示'}${label}`"
        :aria-pressed="revealed"
        @click="revealed = !revealed"
      ><el-icon><component :is="revealed ? Hide : View" /></el-icon></el-button>
      <el-button
        v-if="expandable && value.length > 48 && (!sensitive || revealed)"
        text
        :aria-label="`${expanded ? '收起' : '展开'}${label}`"
        :aria-expanded="expanded"
        @click="expanded = !expanded"
      ><el-icon><component :is="expanded ? ArrowUp : ArrowDown" /></el-icon></el-button>
      <el-button
        text
        :aria-label="`复制${label}`"
        :disabled="!value || (sensitive && !revealed)"
        @click="copy"
      ><el-icon><CopyDocument /></el-icon></el-button>
    </span>
    <span
      v-if="copied || error"
      class="copy-feedback"
      :class="{ 'error-text': error }"
      role="status"
      aria-live="polite"
    >{{ error || "已复制" }}</span>
  </div>
</template>
