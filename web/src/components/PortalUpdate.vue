<script setup lang="ts">
import { ref, onMounted, watch } from "vue";
import { pget } from "../lib/http";
import { type Row } from "../lib/json";
import { useTask } from "../composables/tasks";
import SectionPanel from "./SectionPanel.vue";
import CopyField from "./CopyField.vue";
import RequestNotice from "./RequestNotice.vue";
const props = defineProps<{ license: Row }>(),
  task = useTask(),
  update = ref<Row>();
async function load() {
  if (!["active", "unused"].includes(String(props.license.status))) {
    update.value = undefined;
    return;
  }
  const id = String(props.license.id);
  await task.run(async () => {
    const next = await pget("/update");
    if (id === String(props.license.id)) update.value = next;
  });
}
watch(
  () => props.license.id,
  () => {
    update.value = undefined;
    void load();
  },
);
onMounted(load);
</script>
<template>
  <section-panel title="软件更新">
    <request-notice :error="task.error.value" @retry="load" /><el-button
      :loading="task.busy.value"
      @click="load"
    >
      检查更新
    </el-button>
    <p v-if="update?.renewal_required">
      更新版本需要续期；可继续使用维护期内发布的版本，请联系管理员续期。可用最高版本：{{
        update.latest_entitled_version || update.version
      }}
    </p>
    <template v-if="update?.available">
      <h4>{{ update.version }}{{ update.mandatory ? "（强制更新）" : "" }}</h4>
      <p class="update-notes">
        {{ update.changelog }}
      </p>
      <copy-field
        v-if="update.docker_pull"
        :value="update.docker_pull"
        label="Docker拉取命令"
      />
    </template>
    <p v-else-if="update">
      当前没有可用的新版本。
    </p>
  </section-panel>
</template>
