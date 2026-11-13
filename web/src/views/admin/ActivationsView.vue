<script setup lang="ts">
import FocusOverlay from "../../components/FocusOverlay.vue";
import { adminPage } from "../../lib/runtime";
import IpInfo from "../../components/IpInfo.vue";
import KeyValueList from "../../components/KeyValueList.vue";
import KeyValueItem from "../../components/KeyValueItem.vue";
import SectionPanel from "../../components/SectionPanel.vue";
import RequestNotice from "../../components/RequestNotice.vue";
import JsonBlock from "../../components/JsonBlock.vue";
import { computed, ref, watch, onBeforeUnmount } from "vue";
import { useRoute } from "vue-router";
import { useCollection } from "../../composables/collection";
import { useTask, confirmAction } from "../../composables/tasks";
import { get, post } from "../../lib/http";
import { idText, rows, type Row } from "../../lib/json";
import { field } from "../../lib/schema";
import { opts } from "../../lib/labels";
import { instanceOnline } from "../../lib/presentation";
import CopyField from "../../components/CopyField.vue";
import PageHeading from "../../components/PageHeading.vue";
import FilterBar from "../../components/FilterBar.vue";
import DataTable from "../../components/DataTable.vue";
import ListPager from "../../components/ListPager.vue";
const selected = ref<Row>();
const now = ref(Date.now());
const timer = setInterval(() => {
  now.value = Date.now();
}, 1000);
const route = useRoute(),
  searchFilters = ref<Row>({});
let searchSerial = 0;
onBeforeUnmount(() => {
  searchSerial++;
  clearInterval(timer);
});
async function search() {
  const serial = ++searchSerial;
  try {
    const query: Row = { kind: "floating", ...searchFilters.value };
    const q = String(query.q || "").trim();
    // The existing activation endpoint searches device fields, not license codes.
    // Resolve a complete code via the existing license search, keeping the backend contract unchanged.
    if (/^[^-]+(?:-[^-]{5}){4}$/.test(q)) {
      const matches = rows(
        (await get("/licenses", { q, page_size: 100 })).items,
      );
      const license = matches.find(
        (row) => String(row.key).toUpperCase() === q.toUpperCase(),
      );
      if (license) {
        query.license_id = license.id;
        delete query.q;
      }
    }
    if (serial !== searchSerial) return;
    list.query.value = query;
    await list.load(true);
  } catch (error) {
    if (serial === searchSerial)
      list.error.value = error instanceof Error ? error.message : "检索失败";
  }
}

const list = useCollection("/activations"),
  task = useTask();
watch(
  () => route.query,
  (query) => {
    searchFilters.value = { kind: "floating", ...query };
    void search();
  },
  { immediate: true },
);
const instanceRows = computed(() =>
  list.items.value.map((row) => ({
    ...row,
    instance_short: String(row.instance_id || "").slice(0, 8),
    online_status: instanceOnline(row, now.value)
      ? "online"
      : "offline_instance",
  })),
);
async function act(row: Row, action: string) {
  await task.run(
    async () => {
      await confirmAction(
        action === "release-seat"
          ? "释放席位会删除此实例记录并写入审计，不更改会话凭据；仍在运行的程序下次心跳可以重新竞争。需要阻止运行请暂停或吊销授权。"
          : action === "unbind"
            ? "停用当前激活会使相关会话失效。确认继续？"
            : "标记下线将使现有会话失效。确认继续？",
        action === "release-seat" ? "释放席位" : "管理激活",
        {
          action:
            action === "release-seat"
              ? "释放席位"
              : action === "unbind"
                ? "停用激活"
                : "标记下线",
        },
      );
      await post(`/activations/${idText(row.id)}/${action}`, {});
      if (selected.value && idText(selected.value.id) === idText(row.id))
        selected.value = undefined;
      await list.load();
    },
    action === "release-seat"
      ? "席位已释放"
      : action === "unbind"
        ? "已停用激活"
        : "已标记下线",
  );
}
</script>
<template>
  <page-heading
    title="实例"
    description="查看运行实例、租约在线状态和最近活动；释放后实例记录会删除，操作保留在审计日志。"
  />
  <section-panel>
    <filter-bar
      v-model="searchFilters"
      :fields="[
        field('kind', '记录类型', {
          type: 'select',
          options: opts(['floating', 'key']),
        }),
      ]"
      search-placeholder="主机名、指纹、IP或完整授权码"
      :busy="list.loading.value"
      @search="search"
    /><request-notice :error="list.error.value" :busy="list.loading.value" @retry="list.load()" />
    <request-notice :error="task.error.value" />
    <data-table
      :error="list.error.value"
      empty="还没有实例记录，请先接入程序并激活授权"
      :items="instanceRows"
      :columns="[
        { key: 'instance_short', title: '实例短号', mono: true, width: 160 },
        { key: 'license_key', title: '授权码', mono: true, width: 215 },
        { key: 'hostname', title: '主机名', width: 120 },
        { key: 'client_version', title: '客户端版本', mono: true, width: 110 },
        { key: 'last_ip', title: '最近IP', mono: true, width: 150 },
        { key: 'online_status', title: '在线状态', state: true, width: 96 },
        { key: 'last_seen_at', title: '最近在线', date: true, width: 190 },
      ]"
      clickable
      :actions-width="160"
      :actions-fixed="true"
      :loading="list.loading.value"
      @select="selected = $event"
    >
      <template #cell-instance_short="{ row }">
        <copy-field
          :value="row.instance_id"
          :display="String(row.instance_short)"
          class="instance-short"
          compact
          :expandable="false"
        />
      </template>
      <template #cell-license_key="{ row }">
        <router-link :to="adminPage(`/licenses/${idText(row.license_id)}`)">{{
          row.license_key || "—"
        }}</router-link>
      </template>
      <template #actions="{ row }">
        <el-button
          v-if="row.kind === 'floating' && row.status === 'active'"
          link
          @click.stop="act(row, 'release-seat')"
        >
          释放席位
        </el-button>
        <template v-else-if="row.status === 'active'">
          <el-button link type="warning" @click.stop="act(row, 'offline')">
            标记下线
          </el-button><el-button link type="danger" @click.stop="act(row, 'unbind')">
            停用激活
          </el-button>
        </template>
      </template>
    </data-table><list-pager
      v-model:page="list.page.value"
      v-model:size="list.size.value"
      :total="list.total.value"
      @change="list.load()"
    />
  </section-panel>
  <focus-overlay
    drawer
    :model-value="!!selected"
    title="实例详情"
    @update:model-value="selected = undefined"
  >
    <key-value-list v-if="selected">
      <key-value-item label="首次 IP">
        <IpInfo :ip="selected.first_ip" />
      </key-value-item>
      <key-value-item label="最近 IP">
        <IpInfo :ip="selected.last_ip" :info="selected.ip_info" />
      </key-value-item>
    </key-value-list>
    <json-block
      :value="
        Object.fromEntries(
          Object.entries(selected || {}).filter(
            ([key]) => !['first_ip', 'last_ip', 'ip_info'].includes(key),
          ),
        )
      "
    />
  </focus-overlay>
</template>
