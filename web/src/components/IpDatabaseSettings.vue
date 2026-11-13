<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { ElMessage } from "element-plus";
import { dateText } from "../lib/json";
import {
  ipDatabaseStatus,
  ipDatabaseAction,
  uploadIpDatabase,
  type IpDatabaseStatus,
} from "../lib/http";
import { confirmAction, useTask, useLoadTask } from "../composables/tasks";
import SectionPanel from "./SectionPanel.vue";
import RequestNotice from "./RequestNotice.vue";
import IpAttribution from "./IpAttribution.vue";
const status = ref<IpDatabaseStatus>();
const task = useTask(),
  loadTask = useLoadTask();
const operation = ref("");
const progress = ref(0);
const cityInput = ref<HTMLInputElement>();
const asnInput = ref<HTMLInputElement>();
const usingDBIP = computed(
  () =>
    !!status.value?.enabled &&
    [status.value.city, status.value.asn].some((db) => db?.source === "db-ip"),
);
const files = computed(() =>
  (["city", "asn"] as const).map((kind) => ({
    kind,
    title: kind === "city" ? "City 地理位置库" : "ASN 网络信息库",
    db: status.value?.[kind],
  })),
);
function size(bytes: number) {
  return bytes < 1048576
    ? `${(bytes / 1024).toFixed(1)} KiB`
    : `${(bytes / 1048576).toFixed(1)} MiB`;
}
function load() {
  return loadTask.run(async () => {
    status.value = await ipDatabaseStatus();
  });
}
async function act(action: "enable" | "update" | "delete") {
  if (task.busy.value) return;
  await task.run(async () => {
    if (action === "delete")
      await confirmAction(
        "停用后将停止本地 IP 信息查询和自动更新，并删除服务器上的 City、ASN 数据库文件。现有授权、实例和日志不受影响。确认停用并删除？",
        "停用并删除 IP 库",
        { action: "停用并删除 IP 库", danger: true },
      );
    operation.value = action;
    status.value = await ipDatabaseAction(action);
    if (action === "enable" && !status.value.enabled)
      ElMessage.info("数据库暂未发布，请稍后重试。现有文件不会被替换。");
  });
  operation.value = "";
}
async function upload(kind: "city" | "asn", event: Event) {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  input.value = "";
  if (!file || task.busy.value) return;
  if (!/\.mmdb$/i.test(file.name)) {
    task.error.value = "请选择 .mmdb 文件";
    return;
  }
  if (file.size > 512 * 1024 * 1024) {
    task.error.value = "MMDB 超过 512 MiB 上限";
    return;
  }
  progress.value = 0;
  operation.value = kind;
  await task.run(async () => {
    status.value = await uploadIpDatabase(kind, file, (percent) => {
      progress.value = percent;
    });
  }, "IP 库已上传并启用");
  operation.value = "";
}
onMounted(load);
</script>
<template>
  <section-panel title="IP 库">
    <p class="muted ipdb-description">
      IP 地理位置和 ASN 查询在本地完成，IP
      不会发送给第三方。默认关闭；启用后才联网下载，DB-IP
      库之后每月自动更新。上传的库不会被自动更新覆盖。
    </p>
    <request-notice
      :error="loadTask.error.value"
      :busy="loadTask.busy.value"
      @retry="load"
    />
    <request-notice :error="task.error.value" />
    <el-skeleton v-if="!status && loadTask.busy.value" :rows="3" animated />
    <template v-if="status">
      <div class="ipdb-toolbar">
        <strong>{{ status.enabled ? "已启用" : "未启用" }}</strong>
        <el-button :disabled="task.busy.value" @click="load">
          刷新状态
        </el-button>
        <el-button
          v-if="!status.enabled"
          type="primary"
          :loading="operation === 'enable'"
          :disabled="task.busy.value"
          @click="act('enable')"
        >
          启用并下载
        </el-button>
        <el-button
          v-else
          :loading="operation === 'update'"
          :disabled="task.busy.value"
          @click="act('update')"
        >
          立即更新
        </el-button>
        <el-button
          type="danger"
          plain
          :loading="operation === 'delete'"
          :disabled="task.busy.value"
          @click="act('delete')"
        >
          停用并删除
        </el-button>
      </div>
      <p v-if="status.last_error" class="ipdb-error" role="alert">
        {{ status.last_error }}
      </p>
      <p v-if="status.updated_at" class="muted">
        最近操作：{{ dateText(status.updated_at, true) }}
      </p>
      <div class="ipdb-files">
        <section v-for="file in files" :key="file.kind" class="ipdb-file">
          <h3>{{ file.title }}</h3>
          <dl class="ipdb-status">
            <dt>来源</dt>
            <dd>
              {{
                file.db?.source === "db-ip"
                  ? "DB-IP Lite"
                  : file.db?.source === "upload"
                    ? "管理员上传"
                    : "未安装"
              }}
            </dd>
            <dt>数据日期</dt>
            <dd>{{ dateText(file.db?.data_date) }}</dd>
            <dt>文件大小</dt>
            <dd>{{ file.db ? size(file.db.size) : "—" }}</dd>
            <dt>最近更新</dt>
            <dd>{{ dateText(file.db?.updated_at, true) }}</dd>
          </dl>
          <el-button
            :loading="operation === file.kind"
            :disabled="task.busy.value"
            @click="
              file.kind === 'city' ? cityInput?.click() : asnInput?.click()
            "
          >
            上传 {{ file.kind === "city" ? "City" : "ASN" }} 库
          </el-button>
        </section>
      </div>
      <input
        ref="cityInput"
        class="visually-hidden"
        type="file"
        accept=".mmdb"
        aria-label="选择 City MMDB 文件"
        :disabled="task.busy.value"
        @change="upload('city', $event)"
      />
      <input
        ref="asnInput"
        class="visually-hidden"
        type="file"
        accept=".mmdb"
        aria-label="选择 ASN MMDB 文件"
        :disabled="task.busy.value"
        @change="upload('asn', $event)"
      />
      <p class="muted">
        支持未压缩的 .mmdb 文件，每个文件最大 512 MiB；City 和 ASN
        可以分别上传。
      </p>
      <p
        v-if="operation === 'enable' || operation === 'update'"
        class="muted"
        role="status"
        aria-live="polite"
      >
        正在下载并校验数据库，可能需要数分钟，请勿关闭页面。失败时保留原有数据库。
      </p>
      <div
        v-if="operation === 'city' || operation === 'asn'"
        role="status"
        aria-live="polite"
      >
        <el-progress :percentage="progress" />
        <p class="muted">
          {{
            progress >= 100 ? "上传完成，正在校验数据库…" : "正在上传数据库…"
          }}
        </p>
      </div>
      <ip-attribution :visible="usingDBIP" />
    </template>
  </section-panel>
</template>
