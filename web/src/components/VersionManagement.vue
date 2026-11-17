<script setup lang="ts">
import FocusOverlay from "./FocusOverlay.vue";
import { ref, watch } from "vue";
import { patch } from "../lib/http";
import { type Row, idText } from "../lib/json";
import { useCollection } from "../composables/collection";
import { useTask, confirmAction } from "../composables/tasks";
import DataTable from "./DataTable.vue";
import ListPager from "./ListPager.vue";
import RequestNotice from "./RequestNotice.vue";
import SectionPanel from "./SectionPanel.vue";
const props = defineProps<{ id: string; appKey: string }>();
const list = useCollection(() => `/applications/${props.id}/versions`),
  task = useTask(),
  saveTask = useTask(),
  selected = ref<Row>(),
  encrypted = ref(false),
  builtAt = ref("");
watch(
  () => props.id,
  () => {
    selected.value = undefined;
    builtAt.value = "";
    encrypted.value = false;
  },
);
function edit(row: Row) {
  saveTask.error.value = "";
  selected.value = row;
  encrypted.value = !!row.encrypted;
  builtAt.value = String(row.built_at || "");
}
async function disable(row: Row) {
  const result = await task.run(async () => {
    const app = props.id,
      id = idText(row.id);
    await confirmAction(
      row.disabled
        ? "重新启用后，此版本的程序可恢复在线验证。"
        : "禁用后，运行此版本的程序下次联网会被拒绝，常驻程序会停止。",
      "版本禁用",
      { action: row.disabled ? "启用版本" : "禁用版本", danger: !row.disabled },
    );
    if (app !== props.id) throw new Error("页面已切换，请重新操作");
    await patch(`/versions/${id}`, { disabled: !row.disabled });
    if (app === props.id) await list.load();
    return true;
  });
  return result === true;
}

async function save() {
  const row = selected.value;
  if (!row || row.build_verified) return;
  await saveTask.run(async () => {
    const app = props.id,
      id = idText(row.id);
    if (encrypted.value && !Number.isFinite(Date.parse(builtAt.value)))
      throw new Error("请填写有效RFC3339构建时间");
    await patch(`/versions/${id}`, {
      encrypted: encrypted.value,
      built_at: encrypted.value ? new Date(builtAt.value).toISOString() : null,
    });
    if (app !== props.id) return;
    selected.value = undefined;
    await list.load();
  }, "构建元数据已登记");
}
</script>
<template>
  <section-panel title="已发布版本">
    <p class="field-hint">
      未加密的版本，或尚未有实例解锁的加密版本，可手动登记；加密版本首次解锁后自动更正。构建元数据仅用于展示，不是信任源。
    </p>
    <request-notice :error="list.error.value" @retry="list.load()" />
    <request-notice :error="task.error.value" />
    <data-table
      :error="list.error.value"
      :items="
        list.items.value.map((row) => ({
          ...row,
          source_label: row.source === 'docker' ? 'Docker Hub' : '手动',
        }))
      "
      :loading="list.loading.value"
      :actions-width="220"
      :columns="[
        { key: 'version', title: '版本' },
        { key: 'source_label', title: '来源' },
        { key: 'encrypted', title: '代码加密' },
        { key: 'built_at', title: '构建时间', date: true },
        { key: 'disabled', title: '禁用' },
      ]"
    >
      <template #cell-encrypted="{ row }">
        {{ row.encrypted ? "是" : "否" }}
        <el-tag v-if="row.build_verified" type="success" size="small">
          已由构建确认
        </el-tag>
      </template>
      <template #cell-disabled="{ row }">
        <el-switch
          :aria-label="`${row.disabled ? '启用' : '禁用'}版本${row.version}`"
          :model-value="Boolean(row.disabled)"
          :before-change="() => disable(row)"
          :disabled="task.busy.value || saveTask.busy.value"
        />
      </template>
      <template #actions="{ row }">
        <el-button
          :disabled="task.busy.value || saveTask.busy.value"
          @click="edit(row)"
        >
          构建元数据
        </el-button>
        <el-button
          :disabled="task.busy.value || saveTask.busy.value"
          @click="disable(row)"
        >
          {{ row.disabled ? "启用版本" : "禁用版本" }}
        </el-button>
      </template>
    </data-table>
    <list-pager
      v-model:page="list.page.value"
      v-model:size="list.size.value"
      :total="list.total.value"
      @change="list.load()"
    />
    <focus-overlay
      :model-value="!!selected"
      title="登记代码加密构建元数据"
      @close="selected = undefined"
    >
      <el-form label-position="top" @submit.prevent="save">
        <request-notice :error="saveTask.error.value" />
        <p v-if="selected?.build_verified" class="field-hint">
          由加密构建的首次解锁自动登记，多架构保留最早构建时间，不可手动修改。
        </p>
        <el-form-item label="此版本已进行代码加密">
          <el-switch
            v-model="encrypted"
            :disabled="!!selected?.build_verified"
          />
        </el-form-item>
        <el-form-item v-if="encrypted" label="构建时间（RFC3339）" required>
          <el-input v-model="builtAt" :readonly="!!selected?.build_verified" />
        </el-form-item>
        <el-button
          v-if="!selected?.build_verified"
          native-type="submit"
          :loading="saveTask.busy.value"
        >
          保存构建元数据
        </el-button>
      </el-form>
    </focus-overlay>
  </section-panel>
</template>
