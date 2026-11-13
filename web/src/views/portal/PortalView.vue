<script setup lang="ts">
import IpInfo from "../../components/IpInfo.vue";
import RequestNotice from "../../components/RequestNotice.vue";
import PageHeading from "../../components/PageHeading.vue";
import CopyField from "../../components/CopyField.vue";
import KeyValueItem from "../../components/KeyValueItem.vue";
import KeyValueList from "../../components/KeyValueList.vue";
import SectionPanel from "../../components/SectionPanel.vue";
import { computed, onBeforeUnmount, ref, watch } from "vue";
import { useRoute } from "vue-router";
import { useAuth } from "../../stores/auth";
import { pget, ppost } from "../../lib/http";
import { dateText, idText, rows, text, type Row } from "../../lib/json";
import { keyOnly } from "../../lib/presentation";
import { label } from "../../lib/labels";
import { useTask, confirmAction, useLoadTask } from "../../composables/tasks";
import { logColumns } from "../../lib/schema";
import PortalUpdate from "../../components/PortalUpdate.vue";
import StatusBadge from "../../components/StatusBadge.vue";
import DataTable from "../../components/DataTable.vue";
import FeatureTable from "../../components/FeatureTable.vue";
const props = withDefaults(
  defineProps<{ mode?: string; embedded?: boolean }>(),
  { mode: undefined, embedded: false },
);
const route = useRoute(),
  auth = useAuth(),
  task = useTask(),
  loadTask = useLoadTask(),
  items = ref<Row[]>([]),
  now = ref(Date.now());
const mode = computed(() => props.mode || String(route.path.split("/").at(-1))),
  license = computed(() => auth.portal.license);
const timer = setInterval(() => {
  now.value = Date.now();
}, 1000);
onBeforeUnmount(() => clearInterval(timer));
const listPaths = {
  activations: "/activations",
  logs: "/logs",
  announcements: "/announcements",
} as const;
async function load(refresh = false) {
  await loadTask.run(async () => {
    if (!refresh) items.value = [];
    if (mode.value === "license") {
      if (!refresh && auth.portal.license.id) return;
      auth.portal.license = await pget("/license");
      return;
    }

    const path = listPaths[mode.value as keyof typeof listPaths];
    if (!path) throw new Error("未知授权页面");
    items.value = rows((await pget(path)).items);
  });
}
watch(
  mode,
  () => {
    task.error.value = "";
    void load();
  },
  { immediate: true },
);
async function unbind(row: Row) {
  await task.run(async () => {
    await confirmAction(
      "删除此实例记录并保留审计，不改变会话凭据。程序仍在运行时会重新占用席位，要阻止运行请联系管理员。",
      "释放实例",
      { action: "释放实例" },
    );
    await ppost(`/activations/${idText(row.id)}/release-seat`, {});
    items.value = rows((await pget("/activations")).items);
    auth.portal.license = await pget("/license");
  }, "实例已释放");
}
</script>
<template>
  <request-notice
    :error="loadTask.error.value"
    :busy="loadTask.busy.value"
    @retry="load(true)"
  />
  <request-notice :error="task.error.value" />
  <page-heading v-if="!embedded" :title="String(route.meta.title)">
    <el-button :loading="loadTask.busy.value" @click="load(true)">
      刷新
    </el-button>
  </page-heading>
  <el-skeleton
    v-if="loadTask.busy.value && !items.length && mode !== 'license'"
    :rows="4"
    animated
  />
  <template v-if="mode === 'license'">
    <section-panel class="license-banner">
      <div class="panel-heading">
        <h2>{{ label(license.type) }}授权</h2>
        <status-badge :value="license.status" />
      </div>
      <key-value-list :column="1" border>
        <key-value-item label="授权码">
          <copy-field
            :value="license.key"
            label="授权码"
            class="portal-license-key"
            compact
          />
        </key-value-item><key-value-item label="开始时间">
          {{ dateText(license.starts_at) }}
        </key-value-item><key-value-item v-if="license.maintenance_until" label="更新维护期">
          {{ dateText(license.maintenance_until) }}
        </key-value-item><key-value-item label="到期时间">
          {{
            license.expires_at ? dateText(license.expires_at) : "永久或尚未起算"
          }}
        </key-value-item><key-value-item label="验证方式">
          {{
            Array.isArray(license.verify_methods)
              ? license.verify_methods.map(label).join("、")
              : "—"
          }}
        </key-value-item><key-value-item label="剩余可绑定数">
          {{ keyOnly(license) ? "不限" : text(license.remaining_activations) }}
        </key-value-item>
      </key-value-list>
      <p class="field-hint">
        剩余可绑定数是当前容量快照，实际激活仍需满足全部授权策略。
      </p>
      <feature-table :value="license.features" />
      <portal-update
        v-if="!embedded"
        :key="String(license.id)"
        :license="license"
      />
    </section-panel>
  </template>
  <template v-else-if="mode === 'activations'">
    <div v-loading="loadTask.busy.value || task.busy.value" class="device-grid">
      <article
        v-for="device in items"
        :key="idText(device.id)"
        class="device-card"
      >
        <div class="panel-heading">
          <h3>{{ device.hostname || label(device.kind) }}</h3>
          <status-badge :value="device.status" />
        </div>
        <dl>
          <dt>实例 ID</dt>
          <dd>{{ text(device.instance_id) }}</dd>
          <dt>操作系统</dt>
          <dd>{{ text(device.os) }}</dd>
          <dt>最近IP</dt>
          <dd><IpInfo :ip="device.last_ip" :info="device.ip_info" /></dd>
          <dt>最近在线</dt>
          <dd>{{ dateText(device.last_seen_at) }}</dd>
        </dl>
        <el-button
          v-if="device.status === 'active' && device.kind === 'floating'"
          type="danger"
          plain
          :disabled="license.status === 'revoked'"
          :loading="task.busy.value"
          @click="unbind(device)"
        >
          释放实例
        </el-button>
      </article>
    </div>
    <el-empty
      v-if="!loadTask.busy.value && !loadTask.error.value && !items.length"
      description="还没有实例绑定；请先在软件中激活授权。"
    />
  </template>

  <section-panel v-else-if="mode === 'logs'">
    <p class="muted">
      最近50条记录；来源IP已部分隐藏。
    </p>
    <data-table
      v-if="!loadTask.error.value || items.length"
      :items="items"
      :columns="
        logColumns.filter((c) => !['license_id', 'device'].includes(c.key))
      "
      :loading="loadTask.busy.value"
    />
  </section-panel>
  <section-panel v-else-if="mode === 'announcements'">
    <article v-for="a in items" :key="idText(a.id)" class="announcement">
      <h2>{{ a.title }}</h2>
      <p class="muted">
        {{ dateText(a.published_at) }}
      </p>
      <div class="announcement-body">
        {{ a.content }}
      </div>
    </article>
    <el-empty
      v-if="!loadTask.busy.value && !loadTask.error.value && !items.length"
      description="软件尚未发布公告"
    />
  </section-panel>
</template>
