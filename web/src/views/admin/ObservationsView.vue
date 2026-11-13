<script setup lang="ts">
import FocusOverlay from "../../components/FocusOverlay.vue";
import { adminPage } from "../../lib/runtime";
import IpInfo from "../../components/IpInfo.vue";
import RequestNotice from "../../components/RequestNotice.vue";
import SectionPanel from "../../components/SectionPanel.vue";
import { computed, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { useCollection } from "../../composables/collection";
import StatusBadge from "../../components/StatusBadge.vue";
import { keyTail } from "../../lib/presentation";
import { idText, type Row } from "../../lib/json";
import { field, type Field } from "../../lib/schema";
import type { Column } from "../../components/DataTable.vue";
import PageHeading from "../../components/PageHeading.vue";
import FilterBar from "../../components/FilterBar.vue";
import DataTable from "../../components/DataTable.vue";
import ListPager from "../../components/ListPager.vue";
import JsonBlock from "../../components/JsonBlock.vue";
const route = useRoute(),
  router = useRouter(),
  selected = ref<Row>();
const mode = computed(() => route.path.split("/").at(-1)!);
const listPaths = {
  "verify-logs": "/verify-logs",
  "audit-logs": "/audit-logs",
} as const;
const list = useCollection(() => {
  const path = listPaths[mode.value as keyof typeof listPaths];
  if (!path) throw new Error("未知日志页面");
  return path;
});
watch(
  () => route.query,
  (q) => {
    list.query.value = { ...q };
    void list.load(true);
  },
  { immediate: true },
);
const filters = computed<Field[]>(() => {
  const dates = [
    field("from", "开始时间", { type: "date", advanced: true }),
    field("to", "结束时间", { type: "date", advanced: true }),
  ];
  if (mode.value === "audit-logs")
    return [
      field("operator", "操作者"),
      field("action", "动作"),
      field("resource", "资源类型"),
      field("resource_id", "资源编号"),
      field("ip", "来源IP", { advanced: true }),
      field("status_code", "HTTP状态码"),
      ...dates,
    ];
  return [
    field("app_id", "软件", {
      type: "resource",
      resource: "/applications",
      advanced: true,
    }),
    field("license_id", "授权编号", { advanced: true }),
    field("code", "错误码", { advanced: true }),
    field("success", "结果", {
      type: "select",
      options: [
        { value: "true", label: "通过" },
        { value: "false", label: "失败" },
      ],
    }),
    field("ip", "来源IP", { advanced: true }),
    ...dates,
  ];
});
const columns = computed<Column[]>(() => [
  { key: "created_at", title: "时间", date: true, seconds: true, width: 164 },
  {
    key: mode.value === "verify-logs" ? "license_key" : "resource",
    title: "对象",
    width: 140,
    mono: true,
  },
  { key: "action", title: "动作", enum: true, width: 160 },
  ...(mode.value === "verify-logs"
    ? [{ key: "license_source", title: "授权来源", enum: true, width: 120 }]
    : []),
  { key: "ip", title: "来源 IP", width: 180 },
  {
    key: mode.value === "verify-logs" ? "code" : "status_code",
    title: "结果",
    enum: mode.value === "verify-logs",
    width: 140,
  },
]);
</script>
<template>
  <page-heading
    :title="String(route.meta.title)"
    description="查询真实记录，详情仅向已认证管理员开放。"
  >
    <el-button :loading="list.loading.value" @click="list.load()">
      刷新
    </el-button>
  </page-heading>
  <section-panel>
    <filter-bar
      v-model="list.query.value"
      :fields="filters"
      :search="mode !== 'audit-logs'"
      :busy="list.loading.value"
      @search="list.load(true)"
    />
    <request-notice :error="list.error.value" @retry="list.load()" />
    <data-table
      :error="list.error.value"
      clickable
      :filtered="
        Object.values(list.query.value).some((v) => v !== '' && v != null)
      "
      :empty="mode === 'verify-logs' ? '还没有验证记录' : '还没有审计记录'"
      :items="list.items.value"
      :columns="columns"
      :loading="list.loading.value"
      @select="selected = $event"
      @clear="
        list.query.value = {};
        list.load(true);
      "
    >
      <template #cell-license_key="{ row }">
        <router-link
          v-if="row.license_id"
          :to="adminPage(`/licenses/${idText(row.license_id)}`)"
        >{{ keyTail(row.license_key) }}</router-link><span v-else>—</span>
      </template>
      <template #cell-license_source="{ row }">
        {{
          row.license_source === "self_trial"
            ? "自助试用"
            : row.license_id
              ? "管理员发放"
              : "—"
        }}
      </template>
      <template #cell-code="{ row }">
        <status-badge
          :value="row.code"
          :kind="row.code === 'OK' ? 'success' : 'danger'"
        />
      </template>
      <template #cell-status_code="{ row }">
        <status-badge
          :value="`${row.status_code} ${Number(row.status_code) < 400 ? '成功' : '失败'}`"
          :kind="Number(row.status_code) < 400 ? 'success' : 'danger'"
        />
      </template>
      <template #actions="{ row }">
        <el-button link type="primary" @click="selected = row">
          详情
        </el-button><el-button
          v-if="row.license_id"
          link
          @click="router.push(adminPage(`/licenses/${idText(row.license_id)}`))"
        >
          授权
        </el-button>
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
    drawer
    :model-value="!!selected"
    title="记录详情"
    size="560px"
    @update:model-value="selected = undefined"
  >
    <IpInfo v-if="selected" :ip="selected.ip" :info="selected.ip_info" />
    <json-block
      :value="
        Object.fromEntries(
          Object.entries(selected || {}).filter(
            ([key]) => !['ip', 'ip_info'].includes(key),
          ),
        )
      "
    />
  </focus-overlay>
</template>
