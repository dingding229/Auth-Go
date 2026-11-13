<script setup lang="ts">
import { computed, ref, watch, onBeforeUnmount } from "vue";
import { fetchAll } from "../lib/http";
import type { Row } from "../lib/json";
import { instanceOnline } from "../lib/presentation";
import RequestNotice from "./RequestNotice.vue";
import SectionPanel from "./SectionPanel.vue";
import DataTable from "./DataTable.vue";
import CopyField from "./CopyField.vue";
import ListPager from "./ListPager.vue";
const props = defineProps<{
  licenseId: string;
  ready: boolean;
  busy: boolean;
}>();
const emit = defineEmits<{
  manage: [row: Row, action: "release-seat" | "offline" | "unbind"];
}>();
let bindingRequest: AbortController | undefined;
const activations = {
  items: ref<Row[]>([]),
  loading: ref(false),
  error: ref(""),
  hasLoaded: ref(false),
  load: loadBindings,
};
async function loadBindings() {
  bindingRequest?.abort();
  const current = new AbortController();
  bindingRequest = current;
  activations.loading.value = true;
  activations.error.value = "";
  try {
    const collected = await fetchAll(
      "admin",
      `/licenses/${encodeURIComponent(props.licenseId)}/activations`,
      {},
      current.signal,
    );
    if (!current.signal.aborted) {
      activations.items.value = collected;
      activations.hasLoaded.value = true;
    }
  } catch (error) {
    if (!current.signal.aborted && bindingRequest === current) {
      const message = error instanceof Error ? error.message : "读取失败";
      activations.error.value = activations.hasLoaded.value
        ? `刷新失败，显示上次成功读取的数据：${message}`
        : message;
    }
  } finally {
    if (bindingRequest === current) activations.loading.value = false;
  }
}
onBeforeUnmount(() => bindingRequest?.abort());
watch(
  () => props.licenseId,
  () => {
    activations.items.value = [];
    activations.hasLoaded.value = false;
    void loadBindings();
  },
  { immediate: true },
);
const devicePage = ref(1),
  deviceSize = ref(20),
  keyPage = ref(1),
  keySize = ref(20);
const boundDevices = computed(() =>
  activations.items.value
    .filter((row) => row.kind === "floating")
    .map((row) => ({
      ...row,
      online_status: instanceOnline(row) ? "online" : "offline_instance",
    })),
);
const keyActivations = computed(() =>
  activations.items.value
    .filter((row) => row.kind === "key")
    .map((row) => ({ ...row, online_status: row.status })),
);
for (const [items, page, size] of [
  [boundDevices, devicePage, deviceSize],
  [keyActivations, keyPage, keySize],
] as const) {
  watch([() => items.value.length, size], () => {
    page.value = Math.max(
      1,
      Math.min(page.value, Math.ceil(items.value.length / size.value)),
    );
  });
}
const detailActivationColumns = [
  { key: "instance_id", title: "实例 ID", mono: true, width: 168 },
  { key: "hostname", title: "实例名称", width: 112 },
  { key: "created_at", title: "首次心跳", date: true, width: 144 },
  { key: "os", title: "系统", width: 80 },
  { key: "online_status", title: "状态", state: true, width: 88 },
  { key: "last_ip", title: "最近IP", mono: true, width: 120 },
  { key: "last_seen_at", title: "最近心跳", date: true, width: 144 },
];
defineExpose({ load: loadBindings });
</script>
<template>
  <section-panel>
    <request-notice
      :error="activations.error.value"
      @retry="activations.load()"
    />
    <data-table
      v-if="boundDevices.length || !keyActivations.length"
      :items="
        boundDevices.slice(
          (devicePage - 1) * deviceSize,
          devicePage * deviceSize,
        )
      "
      empty="还没有运行实例"
      :columns="detailActivationColumns"
      :actions-width="208"
      :loading="activations.loading.value"
    >
      <template #cell-instance_id="{ row }">
        <copy-field
          :value="row.instance_id"
          label="实例 ID"
          compact
          :expandable="false"
        />
      </template>
      <template #actions="{ row }">
        <el-button
          v-if="row.status === 'active'"
          link
          :disabled="!ready || busy"
          @click.stop="emit('manage', row, 'release-seat')"
        >
          释放席位
        </el-button>
        <span v-else class="muted">无可用操作</span>
      </template>
    </data-table>
    <list-pager
      v-if="boundDevices.length"
      v-model:page="devicePage"
      v-model:size="deviceSize"
      :total="boundDevices.length"
    />
    <details
      :class="boundDevices.length ? 'technical-options' : 'activation-section'"
      :open="
        activations.items.value.length > 0 &&
          activations.items.value.every((row) => row.kind === 'key')
      "
    >
      <summary>激活</summary>
      <data-table
        :items="
          keyActivations.slice((keyPage - 1) * keySize, keyPage * keySize)
        "
        empty="还没有授权码激活"
        :columns="detailActivationColumns"
        :actions-width="208"
        :loading="activations.loading.value"
      >
        <template #cell-instance_id="{ row }">
          <copy-field
            :value="row.instance_id"
            label="实例 ID"
            compact
            :expandable="false"
          />
        </template>
        <template #actions="{ row }">
          <template v-if="row.status === 'active'">
            <el-button
              link
              type="warning"
              :disabled="!ready || busy"
              @click.stop="emit('manage', row, 'offline')"
            >
              标记下线
            </el-button>
            <el-button
              link
              type="danger"
              :disabled="!ready || busy"
              @click.stop="emit('manage', row, 'unbind')"
            >
              停用激活
            </el-button>
          </template>
          <span v-else class="muted">无可用操作</span>
        </template>
      </data-table>
      <list-pager
        v-if="keyActivations.length"
        v-model:page="keyPage"
        v-model:size="keySize"
        :total="keyActivations.length"
      />
    </details>
  </section-panel>
</template>
