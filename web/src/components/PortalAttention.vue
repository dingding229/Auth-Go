<script setup lang="ts">
import type { Row } from "../lib/json";
import { idText } from "../lib/json";
import StatusBadge from "./StatusBadge.vue";
withDefaults(
  defineProps<{ items: Row[]; loading?: boolean; support?: string }>(),
  { loading: false, support: "" },
);
function kind(row: Row) {
  return row.severity === "danger"
    ? "danger"
    : row.severity === "warning"
      ? "warning"
      : "info";
}
function severity(row: Row) {
  return row.severity === "danger"
    ? "需尽快处理"
    : row.severity === "warning"
      ? "请留意"
      : "有更新";
}
const titles: Record<string, string> = {
  expired: "授权已过期",
  expiring: "授权将在 30 天内到期",
  suspended: "授权已暂停",
  unbind_exhausted: "解绑次数已用完",
  update_available: "有可用的新版本",
  maintenance_expiring: "维护期将在 30 天内到期",
  version_disabled: "正在运行的版本已被禁用",
};
function href(row: Row) {
  const id = idText(row.license_id);
  if (!/^[1-9]\d*$/.test(id)) return "/portal/licenses";
  const tab = ["update_available", "maintenance_expiring"].includes(
    String(row.type),
  )
    ? "updates"
    : ["unbind_exhausted", "version_disabled"].includes(String(row.type))
      ? "instances"
      : "overview";
  return `/portal/licenses/${id}?tab=${tab}`;
}
function expires(row: Row) {
  return ["expired", "expiring", "maintenance_expiring"].includes(
    String(row.type),
  );
}
</script>
<template>
  <el-skeleton v-if="loading && !items.length" :rows="3" animated />
  <p v-else-if="!items.length" class="table-empty">
    目前没有需要处理的事项
  </p>
  <ul v-else class="portal-attention-list">
    <li
      v-for="(row, index) in items"
      :key="`${row.type}-${row.license_id}-${row.instance_id || index}`"
    >
      <status-badge :value="severity(row)" :kind="kind(row)" />
      <div>
        <router-link :to="href(row)">{{ row.app_name }} ·
          {{
            row.title || titles[String(row.type)] || "查看授权情况"
          }}</router-link>
        <p
          v-if="expires(row) && (row.support_contact || support)"
          class="portal-support"
        >
          支持联系方式：{{ row.support_contact || support }}
        </p>
      </div>
    </li>
  </ul>
</template>
