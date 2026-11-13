<script setup lang="ts">
import { useCollection } from "../composables/collection";
import { dateText, idText } from "../lib/json";
import DataTable from "./DataTable.vue";
import ListPager from "./ListPager.vue";
import RequestNotice from "./RequestNotice.vue";
import CopyField from "./CopyField.vue";
const props = withDefaults(
  defineProps<{
    kind: "logs" | "updates" | "announcements";
    licenseId?: unknown;
    pageSize?: number;
  }>(),
  { licenseId: undefined, pageSize: undefined },
);
const list = useCollection(
  () => `/user/${props.kind}`,
  () => ({ license_id: props.licenseId }),
  "portal",
  props.pageSize ?? (props.kind === "logs" ? 10 : 20),
);
defineExpose({ refresh: list.load });
</script>
<template>
  <request-notice
    :error="list.error.value"
    :busy="list.loading.value"
    @retry="list.load()"
  />
  <template v-if="!list.error.value || list.items.value.length">
    <data-table
      v-if="kind === 'logs'"
      :error="list.error.value"
      :items="list.items.value"
      :loading="list.loading.value"
      empty="还没有验证记录"
      :columns="[
        { key: 'app_name', title: '软件', width: 140 },
        {
          key: 'created_at',
          title: '时间',
          date: true,
          seconds: true,
          width: 180,
        },
        { key: 'code', title: '结果', enum: true, width: 130 },
        { key: 'action', title: '操作', enum: true },
        { key: 'ip', title: '来源 IP', width: 180 },
        { key: 'client_version', title: '运行版本' },
      ]"
    />
    <template v-else>
      <el-skeleton
        v-if="list.loading.value && !list.items.value.length"
        :rows="4"
        animated
      />
      <p v-else-if="!list.items.value.length" class="table-empty">
        {{ kind === "updates" ? "软件尚未发布更新" : "软件尚未发布公告" }}
      </p>
      <article
        v-for="row in list.items.value"
        :key="idText(row.id ?? row.app_id)"
        class="portal-record"
      >
        <h2>
          {{ row.app_name
          }}<template v-if="kind === 'updates'">
            ·
            <template v-if="row.version">
              当前最新版本
              <span class="code-value">{{ row.version }}</span>
            </template><template v-else>
              暂无可用版本
            </template>
          </template>
        </h2>
        <template v-if="kind === 'updates'">
          <p v-if="row.version" class="muted">
            发布时间：{{ dateText(row.published_at) }}
          </p>
          <p v-if="row.latest_entitled_version">
            可用版本到
            <span class="code-value">{{ row.latest_entitled_version }}</span>
          </p>
          <p v-if="row.maintenance_until">
            更新维护期：{{ dateText(row.maintenance_until) }}
          </p>
          <p v-if="row.renewal_required" class="warning-text">
            需要续期，请联系软件提供方。
          </p>
          <p v-if="row.docker_pull">
            <copy-field :value="row.docker_pull" label="Docker 拉取命令" />
          </p>
          <div v-if="row.version" class="announcement-body">
            {{ row.changelog || "暂无更新说明" }}
          </div>
          <router-link
            :to="`/portal/licenses/${idText(row.license_id)}?tab=updates`"
          >查看授权的软件更新</router-link>
        </template>
        <template v-else>
          <h3>{{ row.title }}</h3>
          <p class="muted">
            {{ dateText(row.published_at) }}
          </p>
          <div class="announcement-body">
            {{ row.content }}
          </div>
        </template>
      </article>
    </template>
    <list-pager
      v-model:page="list.page.value"
      v-model:size="list.size.value"
      :total="list.total.value"
      :sizes="kind === 'logs' ? [10, 20, 50, 100] : [20, 50, 100]"
      @change="list.load()"
    />
  </template>
</template>
