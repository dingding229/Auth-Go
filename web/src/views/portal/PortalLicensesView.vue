<script setup lang="ts">
import { ref } from "vue";
import { useRoute } from "vue-router";
import { useCollection } from "../../composables/collection";
import { idText } from "../../lib/json";
import PageHeading from "../../components/PageHeading.vue";
import SectionPanel from "../../components/SectionPanel.vue";
import StatusBadge from "../../components/StatusBadge.vue";
import CopyField from "../../components/CopyField.vue";
import ListPager from "../../components/ListPager.vue";
import RequestNotice from "../../components/RequestNotice.vue";
import PortalLicenseFacts from "../../components/PortalLicenseFacts.vue";
const route = useRoute();
const status = ref("");
const list = useCollection(
  "/licenses",
  () => ({ status: status.value }),
  "portal",
);
const states = [
  { value: "active", title: "使用中" },
  { value: "unused", title: "未使用" },
  { value: "expired", title: "已过期" },
  { value: "suspended", title: "已暂停" },
  { value: "revoked", title: "已吊销" },
];
function target(id: unknown) {
  const tab =
    typeof route.query.tab === "string" ? route.query.tab : "overview";
  return { path: `/portal/licenses/${idText(id)}`, query: { tab } };
}
</script>
<template>
  <page-heading title="我的授权">
    <el-button :loading="list.loading.value" @click="list.load()">
      刷新
    </el-button>
  </page-heading>
  <section-panel>
    <div class="action-toolbar">
      <el-select
        v-model="status"
        clearable
        placeholder="全部状态"
        aria-label="按授权状态筛选"
      >
        <el-option
          v-for="state in states"
          :key="state.value"
          :value="state.value"
          :label="state.title"
        />
      </el-select>
    </div>
    <request-notice :error="list.error.value" @retry="list.load()" />
    <el-skeleton
      v-if="list.loading.value && !list.items.value.length"
      :rows="4"
      animated
    />
    <p
      v-else-if="!list.error.value && !list.items.value.length"
      class="table-empty"
    >
      {{ status ? "没有符合条件的授权" : "还没有授权，请联系管理员发放" }}
    </p>
    <ul v-else-if="list.items.value.length" class="user-license-list">
      <li
        v-for="row in list.items.value"
        :key="idText(row.id)"
        class="user-license-card"
      >
        <div class="panel-heading">
          <h2>{{ row.app_name }}</h2>
          <status-badge :value="row.status" />
        </div>
        <copy-field
          :value="row.key"
          label="授权码"
          class="portal-license-key"
          compact
        />
        <portal-license-facts :license="row" />
        <router-link
          class="portal-primary-link"
          :to="target(row.id)"
        >查看授权</router-link>
      </li>
    </ul>
    <list-pager
      v-model:page="list.page.value"
      v-model:size="list.size.value"
      :total="list.total.value"
      @change="list.load()"
    />
  </section-panel>
</template>
