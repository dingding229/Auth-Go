<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from "vue";
import { ElInputNumber } from "element-plus";
defineOptions({ inheritAttrs: false });
const control = ref<InstanceType<typeof ElInputNumber>>();
let observer: MutationObserver | undefined;
onMounted(() => {
  const root = control.value?.$el as HTMLElement | undefined;
  if (!root) return;
  const sync = () => {
    const input = root.querySelector<HTMLInputElement>("input");
    // This Element Plus release sets aria-disabled only at mount. Forms opened
    // during an async load subsequently enable the native input but retain stale
    // ARIA. Mirror the real disabled state, never bypass an actual disabled field.
    if (input) input.setAttribute("aria-disabled", String(input.matches(":disabled")));
  };
  observer = new MutationObserver(sync);
  observer.observe(root, { attributes: true, subtree: true, childList: true, attributeFilter: ["disabled"] });
  sync();
});
onBeforeUnmount(() => observer?.disconnect());
</script>
<template>
  <el-input-number ref="control" v-bind="$attrs">
    <template v-for="(_, name) in $slots" #[name]="scope">
      <slot :name="name" v-bind="scope || {}" />
    </template>
  </el-input-number>
</template>
