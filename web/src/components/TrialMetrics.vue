<script setup lang="ts">
import { onMounted, ref } from "vue";
import { get } from "../lib/http";
import { useTask } from "../composables/tasks";
import RequestNotice from "./RequestNotice.vue";
import SectionPanel from "./SectionPanel.vue";
const counts = ref({ trial_count: 0, converted_count: 0 }),
  task = useTask();
async function load() {
  await task.run(async () => {
    counts.value = await get("/trials/stats");
  });
}
onMounted(load);
</script>
<template>
  <section-panel title="自助试用">
    <p>
      累计试用：{{ counts.trial_count }} · 已转正：{{ counts.converted_count }}
    </p>
    <request-notice
      :error="task.error.value"
      :busy="task.busy.value"
      @retry="load"
    />
  </section-panel>
</template>
