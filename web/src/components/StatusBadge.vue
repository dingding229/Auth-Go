<script setup lang="ts">
import { computed } from "vue";
import { label } from "../lib/labels";
import { statusKinds } from "../lib/status";
const props = defineProps<{
  value: unknown;
  kind?: "success" | "danger" | "warning" | "info" | "neutral";
}>();
const kind = computed(
  () => props.kind || statusKinds[String(props.value)] || "neutral",
);
</script>
<template>
  <span
    class="status-badge"
    :class="`status-${kind}`"
    role="status"
    aria-live="polite"
  >{{ label(value) }}</span>
</template>
