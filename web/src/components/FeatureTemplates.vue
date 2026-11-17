<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { ElMessage } from "element-plus";
import { get, post } from "../lib/http";
import { idText, type Row } from "../lib/json";
import { confirmAction, useTask } from "../composables/tasks";
import FocusOverlay from "./FocusOverlay.vue";
import RequestNotice from "./RequestNotice.vue";
import CrudPanel from "./CrudPanel.vue";
import { field, type Spec } from "../lib/schema";
const props = defineProps<{ id: string }>();
const spec = computed<Spec>(() => ({
  key: "feature_templates",
  title: "功能模板",
  singular: "功能模板",
  path: `/applications/${props.id}/templates`,
  search: false,
  fields: [
    field("name", "模板名称", {
      required: true,
      hint: "同一软件内唯一，1至64个字符。",
    }),
    field("features", "功能项（JSON对象）", {
      type: "json",
      default: "{}",
      required: true,
    }),
    field("default_max_activations", "默认实例数", {
      type: "number",
      nullable: true,
      min: 1,
      max: 1000000,
      hint: "留空不填入实例数。",
    }),
    field("default_days", "默认有效天数", {
      type: "number",
      nullable: true,
      min: 1,
      max: 36500,
      hint: "留空保留发放表单的有效期规则。",
    }),
    field("default_maintenance_days", "默认维护天数", {
      type: "number",
      nullable: true,
      min: 0,
      max: 36500,
      hint: "留空不填入维护天数，0表示不限。",
    }),
  ],
  columns: [
    { key: "name", title: "名称" },
    { key: "features", title: "功能项" },
    { key: "default_max_activations", title: "默认实例数" },
    { key: "default_days", title: "有效天数" },
    { key: "default_maintenance_days", title: "维护天数" },
  ],
}));
const selected = ref<Row>(),
  syncOpen = ref(false),
  scope = ref("linked"),
  counts = ref({ linked: 0, all: 0 }),
  ready = ref(false),
  countTask = useTask("load"),
  syncTask = useTask();
let serial = 0;
watch(
  () => props.id,
  () => {
    ++serial;
    selected.value = undefined;
    syncOpen.value = false;
    ready.value = false;
  },
);
async function openSync(row: Row) {
  const revision = ++serial,
    app = props.id;
  selected.value = row;
  syncOpen.value = true;
  ready.value = false;
  scope.value = "linked";
  counts.value = { linked: 0, all: 0 };
  syncTask.error.value = "";
  await countTask.run(async () => {
    const result = await get(
      `/applications/${app}/templates/${idText(row.id)}/counts`,
    );
    if (revision !== serial) return;
    counts.value = { linked: Number(result.linked), all: Number(result.all) };
    ready.value = true;
  });
}
async function sync() {
  const row = selected.value,
    app = props.id,
    revision = serial,
    range = scope.value;
  if (!row || !ready.value || (range === "linked" && counts.value.linked === 0))
    return;
  await syncTask.run(async () => {
    await confirmAction(
      `将用模板 ${String(row.name)} 的功能项替换${range === "linked" ? "关联授权" : "此软件全部正式授权"}当前的功能项。`,
      "同步功能模板",
      { action: "同步到授权", danger: true },
    );
    if (revision !== serial || !syncOpen.value || app !== props.id)
      throw new Error("页面已切换，请重新操作");
    const result = await post(
      `/applications/${app}/templates/${idText(row.id)}/sync`,
      { scope: range },
    );
    if (revision !== serial) return;
    ElMessage.success(`已同步 ${Number(result.count)} 个授权`);
    syncOpen.value = false;
  });
}
</script>
<template>
  <p class="field-hint">
    模板用于填入发放表单，填入后仍可修改。修改模板不会自动改变已发放的授权，需要时点击“同步到授权”。
  </p>
  <crud-panel
    :spec="spec"
    embedded
    edit-from-row
    :actions-width="216"
  >
    <template #actions="{ row }">
      <el-button
        link
        type="primary"
        :disabled="countTask.busy.value || syncTask.busy.value"
        @click="openSync(row)"
      >
        同步到授权
      </el-button>
    </template>
  </crud-panel>
  <focus-overlay
    v-model="syncOpen"
    title="同步到授权"
    width="520px"
    :close-on-click-modal="false"
  >
    <request-notice :error="countTask.error.value" />
    <request-notice :error="syncTask.error.value" />
    <el-form label-position="top" @submit.prevent="sync">
      <el-form-item label="同步范围">
        <el-radio-group
          v-model="scope"
          class="template-sync-scopes"
          :disabled="!ready || syncTask.busy.value"
        >
          <el-radio
            class="template-sync-scope"
            value="linked"
            :disabled="counts.linked === 0"
          >
            用此模板发放的授权（{{ counts.linked }} 个）
          </el-radio>
          <el-radio class="template-sync-scope" value="all">
            此软件的全部授权（{{ counts.all }} 个）
          </el-radio>
        </el-radio-group>
      </el-form-item>
      <p v-if="ready && counts.linked === 0" class="field-hint">
        还没有授权关联此模板。旧版本发放的授权没有记录来源，可选择全部授权，或在授权详情里逐个套用。
      </p>
      <p class="field-hint">
        会覆盖这些授权各自的功能项，不改变实例数、有效期和维护期，试用授权不参与同步。
      </p>
      <div class="action-toolbar">
        <el-button @click="syncOpen = false">
          取消
        </el-button>
        <el-button
          type="primary"
          native-type="submit"
          :loading="syncTask.busy.value"
          :disabled="!ready || (scope === 'linked' && counts.linked === 0)"
        >
          同步到授权
        </el-button>
      </div>
    </el-form>
  </focus-overlay>
</template>

<style scoped>
.template-sync-scopes {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 8px;
  max-width: 100%;
}
.template-sync-scope {
  height: auto;
  min-height: 44px;
  margin-right: 0;
  white-space: normal;
  overflow-wrap: anywhere;
}
</style>
