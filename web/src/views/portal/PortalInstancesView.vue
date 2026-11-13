<script setup lang="ts">
import { onMounted, onBeforeUnmount, ref } from "vue";
import { useRoute } from "vue-router";
import { useCollection } from "../../composables/collection";
import { useTask, confirmAction, useLoadTask } from "../../composables/tasks";
import { ppost, pget, portalSoftwareOptions } from "../../lib/http";
import { idText, type Row } from "../../lib/json";
import { useAuth } from "../../stores/auth";
import PageHeading from "../../components/PageHeading.vue";
import SectionPanel from "../../components/SectionPanel.vue";
import DataTable from "../../components/DataTable.vue";
import ListPager from "../../components/ListPager.vue";
import RequestNotice from "../../components/RequestNotice.vue";
const props = withDefaults(
  defineProps<{ licenseId?: unknown; embedded?: boolean }>(),
  { licenseId: undefined, embedded: false },
);
const route = useRoute(),
  auth = useAuth(),
  task = useTask(),
  loadTask = useLoadTask(),
  app = ref(String(route.query.app_id || "")),
  software = ref<Row[]>([]);
const list = useCollection(
  "/user/instances",
  () => ({ license_id: props.licenseId, app_id: app.value }),
  "portal",
);
async function unbind(row: Row) {
  await task.run(async () => {
    await confirmAction(
      "删除此实例记录并保留审计，不改变会话凭据。程序仍在运行时会重新占用席位，要阻止运行请联系管理员。",
      "释放实例",
      { action: "释放实例" },
    );
    await ppost(`/user/instances/${idText(row.id)}/release-seat`, {});
    await list.load();
    auth.portal.user = await pget("/user");
  }, "实例已释放");
}
const controller = new AbortController();
async function loadSoftware() {
  if (!props.embedded)
    await loadTask.run(async () => {
      software.value = await portalSoftwareOptions(controller.signal);
    });
}
async function retry() {
  await Promise.all([list.load(), loadSoftware()]);
}
onMounted(loadSoftware);
onBeforeUnmount(() => controller.abort());
</script>
<template>
  <page-heading
    v-if="!embedded"
    title="我的实例"
    description="查看名下全部实例及最近运行情况。"
  >
    <el-button :loading="list.loading.value" @click="list.load()">
      刷新
    </el-button>
  </page-heading>
  <section-panel :title="embedded ? '授权实例' : '我的全部实例'">
    <div v-if="!embedded" class="action-toolbar">
      <el-select
        v-model="app"
        clearable
        filterable
        placeholder="全部软件"
        aria-label="按软件筛选实例"
      >
        <el-option
          v-for="item in software"
          :key="idText(item.app_id)"
          :value="idText(item.app_id)"
          :label="String(item.app_name)"
        />
      </el-select>
    </div>
    <request-notice
      :error="list.error.value || loadTask.error.value"
      @retry="retry"
    />

    <request-notice :error="task.error.value" />
    <p class="field-hint">
      程序仍在运行时会重新占用席位，要阻止运行请联系管理员。
    </p>
    <data-table
      v-if="!(list.error.value || loadTask.error.value) || list.items.value.length"
      :error="list.error.value || loadTask.error.value"
      :items="list.items.value"
      :loading="list.loading.value"
      empty="还没有实例绑定"
      :actions-width="70"
      :columns="[
        { key: 'hostname', title: '实例', width: 100 },
        { key: 'app_name', title: '软件', width: 110 },
        { key: 'last_ip', title: '最近 IP', width: 125 },
        { key: 'client_version', title: '运行版本', width: 80 },
        { key: 'last_seen_at', title: '最近在线', date: true, width: 150 },
        { key: 'status', title: '状态', state: true, width: 70 },
      ]"
    >
      <template #actions="{ row }">
        <span v-if="row.status === 'active' && row.kind === 'floating'"><el-button
          link
          type="danger"
          :disabled="task.busy.value"
          @click="unbind(row)"
        >释放实例</el-button></span>
      </template>
    </data-table>
    <list-pager
      v-model:page="list.page.value"
      v-model:size="list.size.value"
      :total="list.total.value"
      @change="list.load()"
    />
  </section-panel>
</template>
