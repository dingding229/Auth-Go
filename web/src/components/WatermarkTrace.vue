<script setup lang="ts">
import { adminPage } from "../lib/runtime";
import { computed, onBeforeUnmount, ref, useId, watch } from "vue";
import { RouterLink } from "vue-router";
import { get, post } from "../lib/http";
import { dateText } from "../lib/json";
import type {
  WatermarkResult,
  WatermarkProgress,
  WatermarkWorkerRequest,
  WatermarkWorkerResponse,
} from "../lib/watermark-scan";
import SectionPanel from "./SectionPanel.vue";
import RequestNotice from "./RequestNotice.vue";
import KeyValueList from "./KeyValueList.vue";
import KeyValueItem from "./KeyValueItem.vue";
import CopyField from "./CopyField.vue";

interface Tag {
  key_id: string;
  tag: string;
}
interface Trace {
  found: boolean;
  license_id?: string | number;
  user_id?: string | number;
  user_name?: string;
  is_trial?: boolean;
  source_ip?: string;
  created_at?: string;
  key_id?: string;
  sources?: { ip: string; instance_id?: string; created_at?: string }[];
}
const props = defineProps<{ id: string }>();
const inputId = useId(),
  manualId = useId();
const tags = ref<Tag[]>([]),
  tagsBusy = ref(false),
  tagsError = ref("");
const selected = ref<File>(),
  fileInput = ref<HTMLInputElement>();
const scanning = ref(false),
  cancelling = ref(false),
  scanError = ref("");
const progress = ref<WatermarkProgress>(),
  result = ref<WatermarkResult>();
const manual = ref(""),
  manualError = ref("");
const trace = ref<Trace>(),
  queryBusy = ref(false),
  queryError = ref("");
let generation = 0,
  tagGeneration = 0,
  disposed = false,
  worker: Worker | undefined;
let retryValue: string | undefined;
const percent = computed(() => {
  if (!progress.value?.total) return 0;
  return Math.min(
    99,
    Math.floor((progress.value.bytes / progress.value.total) * 100),
  );
});
const summary = computed(() => {
  switch (result.value?.status) {
    case "found":
      return "已提取有效非零水印。";
    case "zero":
      return "没有水印，可能是用密钥直接解出的，无法查到来源。";
    case "none":
      return "文件里没有水印，可能不是这个软件，或水印已被抹掉。";
    case "ambiguous":
      return "多个非零水印出现次数并列，来源有歧义，未自动查询。";
    case "partial":
      return "文件未扫描完，仅显示已扫描的结果，未自动查询。";
    case "cancelled":
      return "扫描已取消，结果不完整，未自动查询。";
    default:
      return "";
  }
});
function endWorker() {
  worker?.terminate();
  worker = undefined;
  scanning.value = false;
  cancelling.value = false;
}
/** Every selection, manual edit and application switch invalidates both worker
 * callbacks and HTTP continuations. Never consult a newer id after an await. */
function invalidate() {
  generation++;
  endWorker();
  progress.value = undefined;
  result.value = undefined;
  trace.value = undefined;
  scanError.value = "";
  queryError.value = "";
  queryBusy.value = false;
  retryValue = undefined;
}
function clearSelection() {
  selected.value = undefined;
  if (fileInput.value) fileInput.value.value = "";
}
async function readTags(id: string): Promise<Tag[]> {
  const response = await get<{ items: Tag[] }>(
    `/applications/${encodeURIComponent(id)}/watermark-tags`,
    undefined,
    { quiet: true },
  );
  if (
    !Array.isArray(response.items) ||
    response.items.length > 65535 ||
    response.items.some(
      (t) =>
        !t ||
        typeof t.key_id !== "string" ||
        typeof t.tag !== "string" ||
        !/^[0-9a-f]{32}$/.test(t.tag),
    )
  )
    throw new Error("invalid tags");
  return response.items;
}
async function loadTags() {
  const serial = ++tagGeneration,
    id = props.id;
  invalidate();
  clearSelection();
  tags.value = [];
  tagsBusy.value = true;
  tagsError.value = "";
  try {
    const items = await readTags(id);
    if (disposed || serial !== tagGeneration || id !== props.id) return;
    tags.value = items;
  } catch {
    if (!disposed && serial === tagGeneration && id === props.id)
      tagsError.value = "读取软件标记失败，请重试。";
  } finally {
    if (!disposed && serial === tagGeneration && id === props.id)
      tagsBusy.value = false;
  }
}
async function query(value: string, serial: number) {
  const id = props.id;
  if (
    disposed ||
    serial !== generation ||
    !/^[0-9a-f]{64}$/.test(value) ||
    /^0+$/.test(value)
  )
    return;
  queryBusy.value = true;
  queryError.value = "";
  trace.value = undefined;
  retryValue = value;
  try {
    const response = await post<Trace>(
      `/applications/${encodeURIComponent(id)}/watermark-trace`,
      { watermark: value },
    );
    if (disposed || serial !== generation || id !== props.id) return;
    if (typeof response?.found !== "boolean") throw new Error("invalid trace");
    trace.value = response;
  } catch {
    if (!disposed && serial === generation && id === props.id)
      queryError.value = "查询授权来源失败，请重试。";
  } finally {
    if (!disposed && serial === generation && id === props.id)
      queryBusy.value = false;
  }
}
function retryQuery() {
  if (retryValue && !queryBusy.value) void query(retryValue, generation);
}
function startScan() {
  const file = selected.value;
  invalidate();
  if (!file || tagsBusy.value || !tags.value.length) return;
  const serial = generation,
    id = props.id;
  scanning.value = true;
  try {
    const job = new Worker(
      new URL("../lib/watermark-worker.ts", import.meta.url),
      { type: "module" },
    );
    worker = job;
    const current = () =>
      !disposed && serial === generation && id === props.id && worker === job;
    job.onmessage = (event: MessageEvent<WatermarkWorkerResponse>) => {
      if (!current() || event.data.id !== serial) return;
      if (event.data.type === "progress") {
        progress.value = event.data.progress;
        return;
      }
      const completed = { ...event.data.result };
      if (cancelling.value) {
        completed.status = "cancelled";
        completed.complete = false;
        delete completed.watermark;
      }
      result.value = completed;
      endWorker();
      // Partial/ambiguous/zero/cancelled results must never issue an auto query.
      const found = result.value;
      if (found.status === "found" && found.complete && found.watermark)
        void query(found.watermark, serial);
    };
    job.onerror = (event) => {
      event.preventDefault();
      if (!current()) return;
      endWorker();
      scanError.value =
        "本地扫描失败，请重新扫描；若浏览器不支持 Worker，请更换浏览器或手动查询。";
    };
    job.onmessageerror = () => {
      if (!current()) return;
      endWorker();
      scanError.value = "无法读取本地扫描结果，请重试。";
    };
    const message: WatermarkWorkerRequest = {
      type: "scan",
      id: serial,
      file,
      tags: [...new Set(tags.value.map((t) => t.tag))],
    };
    job.postMessage(message);
  } catch {
    endWorker();
    scanError.value =
      "无法启动本地扫描，请更换支持 Worker 的浏览器或手动查询。";
  }
}
async function choose(file?: File) {
  invalidate();
  selected.value = file;
  manual.value = "";
  manualError.value = "";
  if (!file) return;
  // Refresh at selection time: a key may have rotated in another browser.
  const serial = generation,
    readSerial = ++tagGeneration,
    id = props.id;
  const current = () =>
    !disposed &&
    serial === generation &&
    readSerial === tagGeneration &&
    id === props.id;
  tagsBusy.value = true;
  tagsError.value = "";
  try {
    const items = await readTags(id);
    if (!current()) return;
    tags.value = items;
  } catch {
    if (current()) tagsError.value = "读取软件标记失败，请重试。";
    return;
  } finally {
    if (current()) tagsBusy.value = false;
  }
  if (current()) startScan();
}
function onFile(event: Event) {
  choose((event.target as HTMLInputElement).files?.[0]);
  // Permit selecting the same file again after failure/cancellation.
  if (fileInput.value) fileInput.value.value = "";
}
function drop(event: DragEvent) {
  if (tagsBusy.value || !tags.value.length) return;
  if ((event.dataTransfer?.files.length ?? 0) !== 1) {
    invalidate();
    clearSelection();
    scanError.value = "请一次选择一个本地文件。";
    return;
  }
  choose(event.dataTransfer?.files[0]);
}
function cancelScan() {
  if (!worker || !scanning.value || cancelling.value) return;
  cancelling.value = true;
  worker.postMessage({
    type: "cancel",
    id: generation,
  } satisfies WatermarkWorkerRequest);
}
function editManual(value: string) {
  invalidate();
  clearSelection();
  manual.value = value;
  manualError.value = "";
}
function manualQuery() {
  const value = manual.value.trim();
  invalidate();
  clearSelection();
  manualError.value = "";
  if (!/^[0-9a-f]{64}$/.test(value)) {
    manualError.value = "请输入 64 位小写十六进制水印值。";
    return;
  }
  if (/^0+$/.test(value)) {
    manualError.value = "全 0 水印无法识别授权来源，未发起查询。";
    return;
  }
  void query(value, generation);
}
watch(
  () => props.id,
  () => {
    manual.value = "";
    manualError.value = "";
    void loadTags();
  },
  { immediate: true, flush: "sync" },
);
onBeforeUnmount(() => {
  disposed = true;
  tagGeneration++;
  invalidate();
  selected.value = undefined;
});
</script>

<template>
  <section-panel title="水印追查">
    <template #actions>
      <el-button
        :loading="tagsBusy"
        @click="loadTags()"
      >
        重新读取软件标记
      </el-button>
    </template>
    <div class="watermark-trace">
      <p class="field-hint">
        仅用于代码加密程序的泄露追查，不阻止导出。文件在浏览器本地扫描，不上传文件、文件名或内容片段；只提交提取出的水印值。
      </p>
      <request-notice :error="tagsError" :busy="tagsBusy" @retry="loadTags" />
      <p v-if="tagsBusy" role="status">
        正在读取所有打包密钥的软件标记…
      </p>
      <p v-else-if="!tagsError && !tags.length" class="field-hint">
        还没有软件标记，请先在上方生成打包密钥。已有水印值也可在更多选项中查询。
      </p>
      <div class="trace-drop" @dragover.prevent @drop.prevent="drop">
        <label :for="inputId"> 选择泄露文件（也可拖入一个文件） </label>
        <input
          :id="inputId"
          ref="fileInput"
          type="file"
          :disabled="tagsBusy || !tags.length"
          @change="onFile"
        />
        <p class="field-hint">
          支持大文件分块读取；ZIP、JAR 及嵌套 JAR
          逐条目解压，不扫描压缩容器本身。累计展开上限 512 MiB，单条目 128
          MiB、嵌套 4 层、条目 4096 个；其他格式按原始字节扫描。
        </p>
      </div>
      <div
        v-if="scanning"
        class="scan-progress"
        role="status"
        aria-live="polite"
      >
        <label>
          本地扫描进度
          <progress
            :value="percent"
            max="100"
            :aria-label="`本地读取进度 ${percent}%`"
          />
        </label>
        <p>
          {{ percent }}% · 已读取
          {{ ((progress?.bytes ?? 0) / 1048576).toFixed(1) }} MiB · 已展开
          {{ ((progress?.expanded ?? 0) / 1048576).toFixed(1) }} MiB · 已检查
          {{ progress?.entries ?? 0 }} 个归档条目
        </p>
        <el-button :disabled="cancelling" @click="cancelScan">
          {{ cancelling ? "正在取消…" : "取消扫描" }}
        </el-button>
      </div>
      <request-notice :error="scanError" @retry="startScan" />
      <div
        v-if="result"
        class="trace-result"
        role="status"
        aria-live="polite"
      >
        <p v-if="!trace && !queryBusy && !queryError">
          {{ summary }}
        </p>
        <p>
          一致非零槽位 {{ result.count }} / 全部槽位 {{ result.slots }} ·
          零值槽位 {{ result.zeros }} ·
          {{ result.complete ? "扫描完整" : "扫描不完整" }}
        </p>
        <ul v-if="result.warnings.length" class="trace-warnings">
          <li v-for="warning in result.warnings" :key="warning">
            {{ warning }}
          </li>
        </ul>
        <details v-if="result.candidates.length">
          <summary>查看非零候选水印（{{ result.candidates.length }}）</summary>
          <ul class="trace-candidates">
            <li
              v-for="candidate in result.candidates"
              :key="candidate.watermark"
            >
              <copy-field :value="candidate.watermark" label="候选水印" />
              <span>{{ candidate.count }} 个槽位</span>
            </li>
          </ul>
        </details>
        <el-button v-if="selected && !scanning" @click="startScan">
          重新扫描
        </el-button>
      </div>
      <p v-if="queryBusy" role="status">
        正在查询授权来源…
      </p>
      <request-notice
        :error="queryError"
        :busy="queryBusy"
        @retry="retryQuery"
      />
      <div
        v-if="trace"
        class="trace-result"
        role="status"
        aria-live="polite"
      >
        <p v-if="!trace.found">
          找到水印但查不到授权：不属于这个软件的授权，或授权已删除。
        </p>
        <template v-else>
          <h3>
            已找到授权来源
            <span v-if="trace.is_trial"> · 自助试用 </span>
          </h3>
          <key-value-list>
            <key-value-item label="授权">
              <router-link
                v-if="trace.license_id != null"
                :to="adminPage(`/licenses/${encodeURIComponent(String(trace.license_id))}`)"
              >
                授权 #{{ trace.license_id }}
              </router-link>
              <span v-else> 未返回授权编号 </span>
            </key-value-item>
            <key-value-item label="客户">
              <router-link
                v-if="trace.user_id != null"
                :to="adminPage(`/users/${encodeURIComponent(String(trace.user_id))}`)"
              >
                {{ trace.user_name || `客户 #${trace.user_id}` }}
              </router-link>
              <span v-else>
                {{ trace.user_name || "未关联客户" }}
              </span>
            </key-value-item>
            <key-value-item label="打包密钥编号">
              {{ trace.key_id || "—" }}
            </key-value-item>
            <key-value-item label="来源 IP">
              {{ trace.source_ip || "—" }}
            </key-value-item>
            <key-value-item label="创建时间">
              {{ dateText(trace.created_at) }}
            </key-value-item>
          </key-value-list>
          <div v-if="trace.is_trial" class="trace-sources">
            <h3>试用来源记录</h3>
            <ul v-if="trace.sources?.length">
              <li v-for="(source, index) in trace.sources" :key="index">
                <p>来源 IP：{{ source.ip || "—" }}</p>
                <p>实例：{{ source.instance_id || "—" }}</p>
                <p>时间：{{ dateText(source.created_at) }}</p>
              </li>
            </ul>
            <p v-else>
              没有返回额外来源记录，请查看上方来源 IP 和授权详情。
            </p>
          </div>
        </template>
      </div>
      <details class="technical-options">
        <summary>更多选项：手动查询与软件标记</summary>
        <form class="trace-manual" @submit.prevent="manualQuery">
          <label :for="manualId">
            水印值（64 位小写十六进制，不是授权码）
          </label>
          <el-input
            :id="manualId"
            :model-value="manual"
            :maxlength="64"
            autocomplete="off"
            :spellcheck="false"
            :aria-invalid="!!manualError"
            :aria-describedby="manualError ? `${manualId}-error` : undefined"
            @update:model-value="editManual"
          />
          <p v-if="manualError" :id="`${manualId}-error`" role="alert">
            {{ manualError }}
          </p>
          <el-button native-type="submit" :loading="queryBusy">
            查询水印值
          </el-button>
        </form>
        <h3>所有打包密钥的软件标记</h3>
        <ul class="trace-tags">
          <li v-for="item in tags" :key="item.key_id">
            <p>密钥编号：{{ item.key_id }}</p>
            <copy-field :value="item.tag" label="软件标记" />
          </li>
        </ul>
      </details>
    </div>
  </section-panel>
</template>

<style scoped>
.watermark-trace {
  display: grid;
  gap: 16px;
  min-width: 0;
  overflow-wrap: anywhere;
}
.watermark-trace p {
  margin: 0;
}
.trace-drop,
.trace-result {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 16px;
  min-width: 0;
}
.trace-drop {
  display: grid;
  gap: 12px;
  background: var(--subtle);
}
.trace-drop label,
.trace-manual label {
  font-weight: 600;
}
.trace-drop input {
  width: 100%;
  min-width: 0;
  min-height: 44px;
  font: inherit;
}
.trace-drop input:focus-visible,
summary:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 3px;
}
.trace-result,
.scan-progress,
.trace-manual {
  display: grid;
  gap: 12px;
  min-width: 0;
}
.scan-progress label {
  display: grid;
  gap: 8px;
}
progress {
  width: 100%;
  accent-color: var(--brand);
}
.trace-warnings {
  color: var(--warning);
}
.trace-candidates,
.trace-tags,
.trace-sources ul {
  display: grid;
  gap: 12px;
  margin: 0;
  padding: 0;
  list-style: none;
  min-width: 0;
}
.trace-candidates li,
.trace-tags li,
.trace-sources li {
  min-width: 0;
  display: grid;
  gap: 8px;
  padding-block: 8px;
  border-bottom: 1px solid var(--line);
}
.trace-manual {
  margin-top: 16px;
}
summary {
  cursor: pointer;
  min-height: 44px;
  padding-block: 10px;
}
@media (max-width: 767px) {
  .trace-drop,
  .trace-result {
    padding: 12px;
  }
  .watermark-trace {
    gap: 12px;
  }
}
</style>
