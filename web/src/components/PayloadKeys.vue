<script setup lang="ts">
import { computed, ref, shallowRef, watch } from "vue";
import { get, post } from "../lib/http";
import { rows, dateText, type Row } from "../lib/json";
import { useTask, confirmAction, useLoadTask } from "../composables/tasks";
import CopyField from "./CopyField.vue";
import DataTable from "./DataTable.vue";
import KeyValueItem from "./KeyValueItem.vue";
import KeyValueList from "./KeyValueList.vue";
import RequestNotice from "./RequestNotice.vue";
import SectionPanel from "./SectionPanel.vue";
import StatusBadge from "./StatusBadge.vue";
const props = defineProps<{ id: string; appKey: string }>();
const emit = defineEmits<{ change: [key: Row | undefined] }>();
const task = shallowRef(useTask()),
  loadTask = shallowRef(useLoadTask()),
  keys = ref<Row[]>([]),
  loaded = ref(false);
const current = computed(() => keys.value.find((key) => key.is_current));
const history = computed(() =>
  keys.value.map((key) => ({
    ...key,
    id: key.key_id,
    status: key.is_current ? "当前" : "历史",
  })),
);
const quote = (value: unknown) => `'${String(value).replaceAll("'", "'\\''")}'`;
const command = computed(() =>
  current.value
    ? `authgo-pack --public-key ${quote(current.value.public_key)} --key-id ${quote(current.value.key_id)} --app-key ${quote(props.appKey)} --version '<版本号>' --config '<构建时接入配置>' --python 'core=<内容目录>' --out '<输出目录>'`
    : "",
);
const protectCommand = computed(() =>
  command.value.replace(
    "--python 'core=<内容目录>'",
    "--protect '<编译后的ELF程序>'",
  ),
);
let generation = 0;
async function fetchKeys() {
  const serial = ++generation,
    id = props.id;
  const result = rows(
    (await get(`/applications/${encodeURIComponent(id)}/payload-keys`)).items,
  );
  if (serial !== generation || id !== props.id) return;
  keys.value = result;
  loaded.value = true;
  emit("change", current.value);
}
async function load() {
  await loadTask.value.run(fetchKeys);
}
watch(
  () => props.id,
  () => {
    generation++;
    // A pending confirmation/request belongs to its original application.
    // New targets must be able to load independently of that old task.
    task.value = useTask();
    loadTask.value = useLoadTask();
    keys.value = [];
    emit("change", undefined);
    loaded.value = false;
    void load();
  },
  { immediate: true },
);
async function generate() {
  const id = props.id,
    operation = task.value;
  const isCurrentTarget = () => id === props.id && operation === task.value;
  await operation.run(async () => {
    try {
      if (current.value)
        await confirmAction(
          "旧版本仍可解开；新构建必须使用新的公钥和密钥编号。确认轮换打包密钥？",
          "轮换打包密钥",
          { action: "轮换打包密钥" },
        );
      if (!isCurrentTarget()) throw "cancel";
      await post(`/applications/${encodeURIComponent(id)}/payload-keys`, {});
      // An already-issued request may finish for the original target, but it
      // must not refresh the new target or emit keys into its generated files.
      if (!isCurrentTarget()) throw "cancel";
      await load();
      if (!isCurrentTarget()) throw "cancel";
    } catch (error) {
      if (!isCurrentTarget()) throw "cancel";
      throw error;
    }
  }, "打包密钥已生成");
}
</script>
<template>
  <section-panel title="打包密钥">
    <template #actions>
      <el-button
        v-if="loaded"
        :type="current ? 'default' : 'primary'"
        :loading="task.busy.value"
        @click="generate"
      >
        {{ current ? "轮换密钥" : "生成打包密钥" }}
      </el-button>
    </template>
    <p class="field-hint">
      不加密代码的程序不需要这一步。打包公钥可公开；私钥由服务端保管，不提供导出。
    </p>
    <request-notice
      :error="loadTask.error.value"
      :busy="loadTask.busy.value"
      @retry="load"
    />
    <request-notice :error="task.error.value" />
    <p v-if="loadTask.busy.value && !loaded" role="status">
      正在读取打包密钥…
    </p>
    <p v-else-if="loaded && !current" class="field-hint">
      还没有打包密钥，生成后即可用于加密构建。
    </p>
    <template v-if="current">
      <key-value-list>
        <key-value-item label="当前密钥编号">
          <copy-field :value="current.key_id" label="打包密钥编号" />
        </key-value-item>
        <key-value-item label="公钥">
          <copy-field :value="current.public_key" label="打包公钥" />
        </key-value-item>
        <key-value-item label="创建时间">
          {{ dateText(current.created_at) }}
        </key-value-item>
      </key-value-list>
      <section-panel title="打包命令">
        <p class="field-hint">
          替换版本号、接入配置和内容路径；内容参数按程序语言选择。新构建使用当前公钥，轮换不影响已发布版本。
        </p>
        <copy-field :value="command" label="打包命令" />
        <p class="field-hint">
          Go、Rust 的 ELF
          程序可整体加密；只在中间构建阶段运行，最终镜像仅复制替换后的程序。
        </p>
        <copy-field :value="protectCommand" label="Go、Rust 整体加密命令" />
      </section-panel>
      <section-panel title="密钥历史">
        <data-table
          :items="history"
          :columns="[
            { key: 'key_id', title: '密钥编号', mono: true },
            { key: 'created_at', title: '创建时间', date: true },
            { key: 'status', title: '状态' },
          ]"
        >
          <template #cell-key_id="{ row }">
            <copy-field :value="row.key_id" label="密钥编号" />
          </template>
          <template #cell-status="{ row }">
            <status-badge
              :value="row.status"
              :kind="row.is_current ? 'success' : 'neutral'"
            />
          </template>
        </data-table>
      </section-panel>
    </template>
  </section-panel>
</template>
