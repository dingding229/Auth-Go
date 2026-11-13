<script setup lang="ts">
import { adminPage } from "../lib/runtime";
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { licenseSharing, ignoreLicenseSharing } from "../lib/http";
import { dateText, idText, rows, type Row } from "../lib/json";
import { confirmAction, useTask } from "../composables/tasks";
import SectionPanel from "./SectionPanel.vue";
import DataTable from "./DataTable.vue";
import StatusBadge from "./StatusBadge.vue";
import RequestNotice from "./RequestNotice.vue";
const props = defineProps<{ licenseId: unknown }>();
const value = ref<Row>(),
  loading = ref(false),
  error = ref(""),
  task = useTask();
let request: AbortController | undefined;
function country(code: unknown) {
  const v = String(code || "");
  try {
    return (
      new Intl.DisplayNames("zh-CN", { type: "region", fallback: "none" }).of(
        v,
      ) || v
    );
  } catch {
    return v;
  }
}
const countries = computed(() =>
  rows(value.value?.countries).map((v) => ({
    ...v,
    name: `${country(v.code)} (${v.code})`,
  })),
);
const asns = computed(() =>
  rows(value.value?.asns).map((v) => ({
    ...v,
    id: v.asn,
    name: `AS${v.asn} ${v.org || ""}`.trim(),
  })),
);
async function load() {
  request?.abort();
  const current = new AbortController();
  request = current;
  loading.value = true;
  error.value = "";
  try {
    const result = await licenseSharing(
      idText(props.licenseId),
      current.signal,
    );
    if (!current.signal.aborted) value.value = result;
  } catch (e) {
    if (!current.signal.aborted)
      error.value = e instanceof Error ? e.message : "共享检测暂时不可用";
  } finally {
    if (request === current) loading.value = false;
  }
}
async function ignore() {
  const id = idText(props.licenseId);
  await task.run(async () => {
    await confirmAction(
      "确认忽略此次共享提示？未来30天不显示该授权的共享标记；到期后仍超过阈值才会再次提示。不会改变授权或校验结果。",
      "忽略共享提示",
      { action: "忽略此次共享提示" },
    );
    if (id !== idText(props.licenseId)) throw "cancel";
    const result = await ignoreLicenseSharing(id);
    if (id === idText(props.licenseId)) value.value = result;
  }, "已忽略此次提示");
}
watch(
  () => idText(props.licenseId),
  () => {
    value.value = undefined;
    void load();
  },
  { immediate: true },
);
onBeforeUnmount(() => request?.abort());
</script>
<template>
  <section-panel title="共享检测" class="sharing-panel">
    <p class="muted">
      云服务器跨区域部署、VPN 或代理可能造成误报，这里只提示，不会影响授权。
    </p>
    <request-notice
      :error="error"
      :busy="loading || task.busy.value"
      @retry="load"
    />
    <request-notice :error="task.error.value" />
    <el-skeleton v-if="loading && !value" :rows="3" animated />
    <template v-else-if="value">
      <p v-if="!value.available">
        需要先在系统设置启用 IP 库。<router-link :to="adminPage('/settings')">前往系统设置</router-link>
      </p>
      <template v-else>
        <div class="action-toolbar">
          <status-badge v-if="value.flagged" value="疑似共享" kind="warning" />
          <p v-else-if="value.ignored" class="muted">
            已忽略至 {{ dateText(value.ignored_until) }}，期间不显示提示。
          </p>
          <p v-else>
            最近 24 小时未发现异常
          </p>
          <el-button
            v-if="value.flagged"
            :loading="task.busy.value"
            @click="ignore"
          >
            忽略此次提示
          </el-button>
        </div>
        <p class="muted">
          最近更新时间：{{ dateText(value.updated_at) }}；最近来源活动：{{
            dateText(value.last_seen_at)
          }}。每小时汇总一次，阈值为超过3个国家或5个ASN。
        </p>
        <p class="muted">
          分布中的实例数按最近24小时的去重公网 IP
          统计，不等同于当前同时在线实例数。共
          {{ value.instance_count }} 个来源；未收录的国家和 ASN 不计入对应维度。
        </p>
        <h3>国家分布</h3>
        <data-table
          :items="countries"
          :columns="[
            { key: 'name', title: '国家', width: 180 },
            { key: 'count', title: '实例数', width: 100 },
          ]"
          empty="暂无国家分布"
        />
        <h3>ASN 分布</h3>
        <data-table
          :items="asns"
          :columns="[
            { key: 'name', title: 'ASN 与名称', width: 230 },
            { key: 'count', title: '实例数', width: 100 },
          ]"
          empty="暂无 ASN 分布"
        />
      </template>
    </template>
  </section-panel>
</template>
