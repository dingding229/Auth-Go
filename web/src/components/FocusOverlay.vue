<script setup lang="ts">
import { useId, watch } from "vue";
import { ElDialog, ElDrawer } from "element-plus";
import { focusReturn } from "../lib/overlay-focus";
defineOptions({ inheritAttrs: false });
const props = defineProps<{ modelValue: boolean; drawer?: boolean }>();
const emit = defineEmits<{ "update:modelValue": [value: boolean] }>();
const owner = useId();
let focus: ReturnType<typeof focusReturn> | undefined;
watch(() => props.modelValue, (open) => {
  if (open) focus = focusReturn();
}, { immediate: true, flush: "sync" });
</script>
<template>
  <component
    :is="drawer ? ElDrawer : ElDialog"
    v-bind="$attrs"
    :model-value="modelValue"
    :data-focus-owner="owner"
    @update:model-value="emit('update:modelValue', $event)"
    @open-auto-focus="focus?.bind(owner)"
    @close-auto-focus="focus?.restore($event)"
  >
    <template v-for="(_, name) in $slots" #[name]="scope">
      <slot :name="name" v-bind="scope || {}" />
    </template>
  </component>
</template>
