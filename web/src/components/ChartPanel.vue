<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, watch } from "vue";
import type { EChartsCoreOption, EChartsType } from "echarts/core";
const props = defineProps<{ option: EChartsCoreOption; label: string }>();
const element = ref<HTMLElement>();
let chart: EChartsType | undefined,
  observer: ResizeObserver | undefined,
  disposed = false;
onMounted(async () => {
  const module = await import("../lib/charts");
  if (disposed || !element.value) return;
  chart = module.init(element.value);
  chart.setOption(props.option);
  observer = new ResizeObserver(() => chart?.resize());
  observer.observe(element.value);
});
watch(
  () => props.option,
  (option) => chart?.setOption(option, true),
  { deep: true },
);
onBeforeUnmount(() => {
  disposed = true;
  observer?.disconnect();
  chart?.dispose();
});
</script>
<template>
  <div
    ref="element"
    class="chart"
    role="img"
    :aria-label="label"
  />
</template>
