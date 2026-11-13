<script setup lang="ts">
import {onMounted,ref} from "vue";
import {get} from "../lib/http";
import {useTask} from "../composables/tasks";
import SectionPanel from "./SectionPanel.vue";
const counts=ref({trial_count:0,converted_count:0}),task=useTask();
async function load(){await task.run(async()=>{counts.value=await get("/trials/stats");});}
onMounted(load);
</script>
<template>
  <section-panel title="自助试用">
    <p>累计试用：{{ counts.trial_count }} · 已转正：{{ counts.converted_count }}</p><el-alert
      v-if="task.error.value"
      :title="task.error.value"
      type="error"
      :closable="false"
    /><el-button v-if="task.error.value" @click="load">
      重试
    </el-button>
  </section-panel>
</template>
