<script setup lang="ts">
import FocusOverlay from "./FocusOverlay.vue";
import { onMounted, ref } from "vue";
import { get, post } from "../lib/http";
import { rows, dateText, type Row } from "../lib/json";
import { field } from "../lib/schema";
import { useTask, useLoadTask } from "../composables/tasks";
import SectionPanel from "./SectionPanel.vue";
import RequestNotice from "./RequestNotice.vue";
import CopyField from "./CopyField.vue";
import SchemaEditor from "./SchemaEditor.vue";
const props = defineProps<{
    id: string;
    isTrial: boolean;
    convertedAt?: unknown;
  }>(),
  emit = defineEmits<{ changed: [] }>();
const task = useTask(),
  loadTask = useLoadTask(),
  claims = ref<Row[]>([]),
  open = ref(false);
async function load() {
  await loadTask.run(async () => {
    claims.value = rows((await get(`/licenses/${props.id}/trial`)).items);
  });
}
const fields = [
  field("user_id", "分配用户", { type: "user", required: true }),
  field("type", "正式授权类型", {
    type: "select",
    options: [
      { value: "standard", label: "标准授权" },
      { value: "subscription", label: "订阅授权" },
      { value: "perpetual", label: "永久授权" },
      { value: "floating", label: "实例授权" },
    ],
    default: "standard",
  }),
  field("days", "有效天数", {
    type: "number",
    default: 30,
    min: 1,
    max: 36500,
    visible: (v) => v.type !== "perpetual",
  }),
  field("max_activations", "允许运行实例数", {
    type: "number",
    default: 1,
    min: 1,
    max: 1000000,
  }),
  field("maintenance_days", "更新维护天数", {
    type: "number",
    default: 0,
    min: 0,
    max: 36500,
    hint: "从现在计算，0表示不限。",
  }),
];
async function convert(body: Row) {
  await task.run(async () => {
    await post(`/licenses/${props.id}/convert`, body);
    open.value = false;
    emit("changed");
  }, "试用已转为正式授权，无需重启实例");
}
onMounted(load);
</script>
<template>
  <section-panel title="试用信息">
    <p>授权来源：自助试用</p>
    <p v-if="convertedAt">
      转正时间：{{ dateText(convertedAt) }}
    </p>
    <request-notice
      :error="loadTask.error.value"
      :busy="loadTask.busy.value"
      @retry="load"
    />
    <div
      v-for="claim in claims"
      :key="String(claim.instance_id)"
      class="field-hint"
    >
      <p>申请IP：{{ claim.ip }}</p>
      <copy-field :value="claim.instance_id" label="实例标识" />
    </div>
    <el-button
      v-if="isTrial"
      @click="
        task.error.value = '';
        open = true;
      "
    >
      转为正式授权
    </el-button>
  </section-panel>
  <focus-overlay
    v-model="open"
    drawer
    title="试用转正"
    size="560px"
    destroy-on-close
  >
    <request-notice :error="task.error.value" />
    <schema-editor
      :fields="fields"
      :busy="task.busy.value"
      submit-label="转为正式授权"
      @save="convert"
      @cancel="open = false"
    />
  </focus-overlay>
</template>
