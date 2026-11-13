<script setup lang="ts">
import FocusOverlay from "./FocusOverlay.vue";
defineOptions({ inheritAttrs: false });
defineProps<{ modelValue: boolean; short?: boolean; title?: string }>();
const emit = defineEmits<{ "update:modelValue": [value: boolean] }>();
</script>
<template>
  <focus-overlay
    :drawer="!short"
    v-bind="$attrs"
    :model-value="modelValue"
    :title="title"
    :width="short ? '480px' : undefined"
    :size="!short ? '560px' : undefined"
    @update:model-value="emit('update:modelValue', $event)"
  >
    <slot />
  </focus-overlay>
</template>
