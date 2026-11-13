<script setup lang="ts">
import FocusOverlay from "../../components/FocusOverlay.vue";
import { adminPage } from "../../lib/runtime";
import RequestNotice from "../../components/RequestNotice.vue";
import SectionPanel from "../../components/SectionPanel.vue";
import { computed, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { ElMessage } from "element-plus";
import { useCollection } from "../../composables/collection";
import { confirmAction, useTask } from "../../composables/tasks";
import { download, post, get } from "../../lib/http";
import { idText, rows, type Row, cleanParams } from "../../lib/json";
import { field, licenseFields } from "../../lib/schema";
import { licenseRequest } from "../../lib/validity";
import { maintenanceText } from "../../lib/maintenance";
import { instanceUsage } from "../../lib/presentation";
import { opts } from "../../lib/labels";
import PageHeading from "../../components/PageHeading.vue";
import FilterBar from "../../components/FilterBar.vue";
import DataTable from "../../components/DataTable.vue";
import ListPager from "../../components/ListPager.vue";
import LicenseTemplatePicker from "../../components/LicenseTemplatePicker.vue";
import SchemaEditor from "../../components/SchemaEditor.vue";
import JsonBlock from "../../components/JsonBlock.vue";
import StatusBadge from "../../components/StatusBadge.vue";
import { WarningFilled } from "@element-plus/icons-vue";
const route = useRoute(),
  router = useRouter(),
  list = useCollection("/licenses"),
  task = useTask();
const open = ref(false),
  initial = ref<Row>({}),
  singleSoftware = ref(false),
  generated = ref<Row[]>([]),
  generatedBatch = ref<Row>(),
  report = ref<Row>(),
  fileInput = ref<HTMLInputElement>();
const filters = [
  field("suspected_sharing", "疑似共享", {
    type: "select",
    advanced: true,
    options: [{ value: "true", label: "仅疑似共享" }],
  }),
  field("source", "授权来源", {
    type: "select",
    options: [{ value: "self_trial", label: "自助试用" }],
    advanced: true,
  }),
  field("user_id", "用户", {
    type: "resource",
    resource: "/users",
    advanced: true,
  }),
  field("app_id", "软件", {
    type: "resource",
    resource: "/applications",
    advanced: true,
  }),

  field("status", "状态", {
    type: "select",
    options: opts(["unused", "active", "expired", "suspended", "revoked"]),
  }),
  field("type", "授权类型", {
    advanced: true,
    type: "select",
    options: opts([
      "trial",
      "standard",
      "subscription",
      "perpetual",
      "floating",
    ]),
  }),
  field("batch_id", "批次号", { advanced: true }),
  field("expires_from", "到期开始", { type: "date", advanced: true }),
  field("expires_to", "到期结束", { type: "date", advanced: true }),
];
watch(
  () => route.query,
  async (query) => {
    const { create: intent, ...filters } = query;
    list.query.value = { ...filters };
    void list.load(true);
    if (intent === "1") {
      // Consume the UI-only intent before opening, so refresh/closing cannot
      // reopen the drawer and the flag never reaches list/export API queries.
      await router.replace({ query: filters });
      await create(idText(filters.app_id));
    }
  },
  { immediate: true },
);
const fields = computed(() => [
  ...licenseFields.map((f) =>
    f.key === "app_id" ? { ...f, hideControl: singleSoftware.value } : f,
  ),
  field("count", "生成数量", {
    type: "number",
    default: 1,
    min: 1,
    max: 10000,
  }),
]);
async function create(appId = idText(list.query.value.app_id)) {
  await task.run(async () => {
    const apps = await get("/applications", { page_size: 2 });
    const items = rows(apps.items);
    singleSoftware.value = Number(apps.total) === 1;
    const next: Row = {
      user_id: idText(route.query.user_id || list.query.value.user_id),
      app_id:
        appId || (Number(apps.total) === 1 && items[0] ? items[0].id : ""),
    };

    initial.value = next;
    open.value = true;
  });
}
async function search() {
  const query = Object.fromEntries(
    Object.entries(cleanParams(list.query.value)).map(([key, value]) => [
      key,
      String(value),
    ]),
  );
  if (JSON.stringify(query) === JSON.stringify(route.query))
    await list.load(true);
  else await router.replace({ query });
}
const tableItems = computed<Row[]>(() =>
  list.items.value.map((row) => ({
    ...row,
    user_name: row.user_name || "未分配",
  })),
);
async function save(body: Row) {
  await task.run(async () => {
    const request = licenseRequest(body);
    const result = await post(request.path, request.data);
    open.value = false;
    await list.load(true);
    const created: Row[] = [];
    generatedBatch.value = undefined;
    if (request.path === "/licenses") created.push(result);
    else {
      generatedBatch.value = { ...result };
      for (
        let page = 1;
        created.length < Number(result.count);
        page++
      ) {
        const data = await get("/licenses", {
          batch_id: result.batch_id,
          page,
          page_size: 100,
        });
        const items = rows(data.items);
        if (!items.length) break;
        created.push(...items);
      }
    }
    // Publish one complete result. Import-report transitions must not own it.
    generated.value = created;
  }, "授权已创建");
}
async function copyGenerated() {
  await task.run(async () => {
    await navigator.clipboard.writeText(
      generated.value.map((r) => String(r.key)).join("\n"),
    );
    ElMessage.success("授权码已复制");
  });
}
async function exportCSV() {
  await task.run(() =>
    download("admin", "/licenses/export", "授权.csv", {
      params: list.query.value,
    }),
  );
}
async function importCSV(event: Event) {
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  input.value = "";
  if (!file) return;
  await task.run(async () => {
    if (file.size > 16 * 1024 * 1024) throw new Error("CSV文件不能超过16MB");
    await confirmAction(
      `确认导入文件“${file.name}”？仅当所有行通过校验才会提交。`,
      "导入授权", { action: "导入授权CSV" },
    );
    const form = new FormData();
    form.append("file", file);
    report.value = await post("/licenses/import", form);
    await list.load(true);
    if (Number(report.value?.failed) > 0)
      ElMessage.warning("导入校验未通过，请查看逐行报告");
    else ElMessage.success("导入成功");
  });
}
</script>
<template>
  <page-heading
    title="授权"
    description="发放、检索和维护软件授权；吊销后无法恢复。"
  >
    <el-button @click="exportCSV">
      导出筛选结果
    </el-button>
    <el-button @click="fileInput?.click()">
      导入CSV
    </el-button><el-button type="primary" @click="create()">
      创建授权
    </el-button>
  </page-heading>
  <input
    ref="fileInput"
    class="visually-hidden"
    type="file"
    accept=".csv,text/csv"
    aria-label="选择授权CSV文件"
    @change="importCSV"
  />
  <section-panel>
    <filter-bar
      v-model="list.query.value"
      :fields="filters"
      search-placeholder="用户姓名、邮箱或授权码"
      :busy="list.loading.value"
      @search="search"
    /><request-notice v-if="!open" :error="task.error.value" />
    <request-notice :error="list.error.value" @retry="list.load()" />
    <data-table
      :error="list.error.value"
      :row-href="(row) => adminPage(`/licenses/${idText(row.id)}`)"
      empty="还没有授权"
      empty-action="创建授权"
      :filtered="
        Object.values(list.query.value).some((v) => v !== '' && v != null)
      "
      :items="tableItems"
      :actions-width="82"
      :actions-fixed="false"
      :loading="list.loading.value"
      :columns="[
        { key: 'key', title: '授权码', mono: true, width: 190 },
        { key: 'user_name', title: '用户', width: 80 },
        { key: 'app_name', title: '软件名称', width: 80 },
        { key: 'status', title: '状态', state: true, width: 100 },
        { key: 'expires_at', title: '到期时间', date: true, width: 132 },
        ...(tableItems.some((row) => row.maintenance_until)
          ? [{ key: 'maintenance_until', title: '维护期到期', width: 168 }]
          : []),
        { key: 'online_instances', title: '实例数', width: 88 },
      ]"
      @empty-action="create()"
      @clear="
        list.query.value = {};
        search();
      "
    >
      <template #cell-status="{ row }">
        <span class="sharing-status"><status-badge :value="row.status" /><el-tooltip
          v-if="row.suspected_sharing"
          content="疑似共享：查看授权详情中的共享检测"
          placement="top"
        ><el-icon
          class="sharing-mark"
          role="img"
          aria-label="疑似共享"
          tabindex="0"
        ><WarningFilled /></el-icon></el-tooltip></span>
      </template>
      <template #cell-maintenance_until="{ row }">
        {{ maintenanceText(row.maintenance_until) }}
      </template>
      <template #cell-online_instances="{ row }">
        {{ instanceUsage(row) }}
      </template>
    </data-table>
    <list-pager
      v-model:page="list.page.value"
      v-model:size="list.size.value"
      :total="list.total.value"
      @change="list.load()"
    />
  </section-panel>
  <focus-overlay
    v-model="open"
    drawer
    title="发放授权"
    size="560px"
    destroy-on-close
    :close-on-click-modal="false"
  >
    <request-notice :error="task.error.value" />
    <schema-editor
      submit-label="创建授权"
      :fields="fields"
      :initial="initial"
      :busy="task.busy.value"
      @save="save"
      @cancel="open = false"
    >
      <template #after-field="{ field: current, values }">
        <license-template-picker
          v-if="current.key === 'app_id'"
          :values="values"
          @applied="Object.assign(values, $event)"
        />
      </template>
    </schema-editor>
  </focus-overlay>
  <focus-overlay
    :model-value="generated.length > 0"
    title="授权已生成"
    width="480px"
    @update:model-value="(value: boolean) => { if (!value) { generated = []; generatedBatch = undefined; } }"
  >
    <p v-if="generatedBatch" class="muted">
      本批生成{{ generatedBatch.count }}条授权。批次号：<span class="code-value">{{ generatedBatch.batch_id }}</span>
    </p>
    <el-input
      :model-value="generated.map((r) => String(r.key)).join('\n')"
      type="textarea"
      readonly
      :rows="Math.min(12, generated.length + 1)"
      aria-label="生成的授权码"
    />
    <el-button type="primary" @click="copyGenerated">
      {{ generated.length === 1 ? "一键复制授权码" : "复制全部授权码" }}
    </el-button>
    <el-button
      v-if="generated.length === 1"
      @click="router.push(adminPage(`/licenses/${idText(generated[0]!.id)}`))"
    >
      查看详情
    </el-button>
    <el-button
      v-if="generatedBatch?.batch_id"
      @click="
        task.run(() =>
          download(
            'admin',
            `/licenses/batches/${encodeURIComponent(String(generatedBatch!.batch_id))}/export`,
            '批次授权.csv',
          ),
        )
      "
    >
      下载批次CSV
    </el-button>
  </focus-overlay>
  <focus-overlay
    :model-value="!!report && generated.length === 0"
    title="批次与导入报告"
    width="480px"
    @update:model-value="report = undefined"
  >
    <template v-if="report">
      <el-alert
        v-if="Number(report.failed) > 0"
        title="有无效行，本次未提交导入。请修正后重试。"
        type="warning"
        :closable="false"
      /><json-block
        :value="
          Object.fromEntries(
            Object.entries(report).filter(([key]) => key !== 'errors'),
          )
        "
        title="处理结果"
      /><el-button
        v-if="report.batch_id"
        @click="
          task.run(() =>
            download(
              'admin',
              `/licenses/batches/${encodeURIComponent(String(report!.batch_id))}/export`,
              '批次授权.csv',
            ),
          )
        "
      >
        导出此批次
      </el-button><data-table
        v-if="report.errors"
        :items="rows(report.errors)"
        :columns="[
          { key: 'row', title: '行号' },
          { key: 'code', title: '错误码' },
          { key: 'message', title: '说明', width: 400 },
        ]"
      />
    </template>
  </focus-overlay>
</template>
