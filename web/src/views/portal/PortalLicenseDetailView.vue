<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import axios from "axios";
import { APIError, userLicenseDetail, selectUserLicense } from "../../lib/http";
import { portalSession, selectUserPortal } from "../../lib/session";
import { record, idText, dateText, type Row } from "../../lib/json";
import CopyField from "../../components/CopyField.vue";
import KeyValueList from "../../components/KeyValueList.vue";
import KeyValueItem from "../../components/KeyValueItem.vue";
import FeatureTable from "../../components/FeatureTable.vue";
import PageHeading from "../../components/PageHeading.vue";
import SectionPanel from "../../components/SectionPanel.vue";
import RequestNotice from "../../components/RequestNotice.vue";
import StatusBadge from "../../components/StatusBadge.vue";
import PortalLicenseFacts from "../../components/PortalLicenseFacts.vue";
import PortalDeployment from "../../components/PortalDeployment.vue";
import PortalRecords from "../../components/PortalRecords.vue";
import PortalUpdate from "../../components/PortalUpdate.vue";
import PortalView from "./PortalView.vue";
import PortalInstancesView from "./PortalInstancesView.vue";
const route = useRoute(),
  router = useRouter();
const license = ref<Row>(),
  loading = ref(false),
  error = ref(""),
  notFound = ref(false);
let request: AbortController | undefined;
let serial = 0;
const tabs = computed(() => [
  { name: "overview", title: "概览" },
  { name: "instances", title: "实例" },
  { name: "updates", title: "软件更新" },
  { name: "deployment", title: "部署" },
  { name: "logs", title: "验证记录" },
  ...(portalSession.license.has_announcements
    ? [{ name: "announcements", title: "公告" }]
    : []),
]);
const tab = computed({
  get() {
    const raw = String(route.query.tab || "overview");
    const name =
      (
        {
          devices: "instances",
          activations: "instances",
          update: "updates",
        } as Record<string, string>
      )[raw] || raw;
    return tabs.value.some((t) => t.name === name) ? name : "overview";
  },
  set(name: string) {
    void router.replace({ query: { ...route.query, tab: name } });
  },
});
async function load() {
  const id = String(route.params.id || "");
  const n = ++serial;
  request?.abort();
  request = new AbortController();
  const signal = request.signal;
  const token = portalSession.token;
  license.value = undefined;
  loading.value = true;
  error.value = "";
  notFound.value = false;
  try {
    if (!/^[1-9]\d*$/.test(id) || BigInt(id) > 9223372036854775807n) {
      notFound.value = true;
      return;
    }
    const detail = await userLicenseDetail(id, signal);
    if (signal.aborted || n !== serial || token !== portalSession.token) return;
    if (idText(detail.id) !== id)
      throw new Error("授权详情格式异常，请稍后重试");
    const selected = await selectUserLicense(id, signal);
    if (signal.aborted || n !== serial || token !== portalSession.token) return;
    const current = record(selected.license);
    if (idText(current.id) !== id || typeof selected.portal_token !== "string")
      throw new Error("无法确认当前授权，请重新选择");
    selectUserPortal(selected.portal_token, current);
    license.value = detail;
  } catch (e) {
    if (signal.aborted || n !== serial || axios.isCancel(e)) return;
    if (e instanceof APIError && e.status === 404) notFound.value = true;
    else
      error.value =
        e instanceof Error ? e.message : "暂时无法加载授权，请稍后重试";
  } finally {
    if (n === serial) loading.value = false;
  }
}
watch(
  () => String(route.params.id),
  () => {
    void load();
  },
  { immediate: true },
);
onBeforeUnmount(() => {
  serial++;
  request?.abort();
  license.value = undefined;
});
</script>
<template>
  <page-heading
    :title="license ? `${license.app_name} · 授权详情` : '授权详情'"
  >
    <router-link to="/portal/licenses">返回我的授权</router-link>
  </page-heading>
  <section-panel v-if="notFound">
    <h2>无法查看该授权</h2>
    <p>该授权不存在，或不属于当前账号。请返回我的授权重新选择。</p>
    <router-link to="/portal/licenses">返回授权列表</router-link>
  </section-panel>
  <request-notice v-else-if="error" :error="error" @retry="load" />
  <el-skeleton v-else-if="loading" :rows="6" animated />
  <template v-else-if="license">
    <status-badge :value="license.status" />
    <el-tabs v-model="tab" class="portal-detail-tabs">
      <el-tab-pane
        v-for="item in tabs"
        :key="item.name"
        :name="item.name"
        :label="item.title"
      >
        <template v-if="tab === item.name">
          <section-panel v-if="item.name === 'overview'">
            <portal-license-facts :license="license" />
            <key-value-list>
              <key-value-item label="授权码">
                <copy-field
                  :value="license.key"
                  label="授权码"
                  class="portal-license-key"
                  compact
                />
              </key-value-item><key-value-item label="开始时间">
                {{ dateText(license.starts_at) }}
              </key-value-item>
            </key-value-list>
            <feature-table :value="license.features" />
          </section-panel>
          <portal-instances-view
            v-else-if="item.name === 'instances'"
            :license-id="license.id"
            embedded
          />
          <section-panel v-else-if="item.name === 'updates'">
            <portal-license-facts
              :license="license"
              :quota="false"
            /><portal-update :license="license" />
          </section-panel>
          <section-panel v-else-if="item.name === 'deployment'">
            <portal-deployment :value="license.deployment" />
          </section-panel>
          <section-panel v-else-if="item.name === 'logs'">
            <portal-records kind="logs" :license-id="license.id" />
          </section-panel>
          <section-panel v-else-if="item.name === 'announcements'">
            <portal-records kind="announcements" :license-id="license.id" />
          </section-panel>
          <portal-view v-else :mode="item.name" embedded />
        </template>
      </el-tab-pane>
    </el-tabs>
  </template>
</template>
