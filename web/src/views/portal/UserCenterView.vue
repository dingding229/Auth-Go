<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useAuth } from "../../stores/auth";
import { pget } from "../../lib/http";
import { dateText } from "../../lib/json";
import { useLoadTask } from "../../composables/tasks";
import { useCollection } from "../../composables/collection";
import PageHeading from "../../components/PageHeading.vue";
import SectionPanel from "../../components/SectionPanel.vue";
import RequestNotice from "../../components/RequestNotice.vue";
import PortalAttention from "../../components/PortalAttention.vue";
import PortalRecords from "../../components/PortalRecords.vue";
import ListPager from "../../components/ListPager.vue";
const auth = useAuth(),
  task = useLoadTask();
const attention = useCollection("/user/attention", {}, "portal");
const logs = ref<{ refresh: () => Promise<void> }>();
async function load() {
  await task.run(async () => {
    auth.portal.user = await pget("/user");
  });
}
async function refresh() {
  await Promise.all([load(), attention.load(), logs.value?.refresh()]);
}
onMounted(load);
</script>
<template>
  <page-heading
    title="我的概览"
    description="查看全部授权、需要处理的事项和最近运行情况。"
  >
    <el-button :loading="task.busy.value" @click="refresh">
      刷新
    </el-button>
  </page-heading>
  <request-notice :error="task.error.value" @retry="load" />
  <div class="user-overview-stats">
    <article class="stat-card">
      <span>名下授权数量</span>
      <p class="stat-number">
        {{ auth.portal.user.license_count ?? "—" }}
      </p>
    </article>
    <article class="stat-card">
      <span>最近到期</span>
      <p class="stat-number stat-date">
        {{
          auth.portal.user.next_expires_at
            ? dateText(auth.portal.user.next_expires_at)
            : "—"
        }}
      </p>
    </article>
    <article class="stat-card">
      <span>实例总数</span>
      <p class="stat-number">
        {{ auth.portal.user.instances_total ?? "—" }}
      </p>
    </article>
  </div>
  <div class="portal-shortcuts">
    <router-link to="/portal/licenses">我的全部授权</router-link><router-link to="/portal/instances">我的全部实例</router-link><router-link to="/portal/account">账号安全与修改密码</router-link>
  </div>
  <p
    v-if="!task.error.value && auth.portal.user.license_count === 0"
    class="muted"
  >
    还没有授权，请联系管理员发放
  </p>
  <p
    v-if="!task.error.value && auth.portal.user.instances_total === 0"
    class="muted"
  >
    还没有实例绑定
  </p>
  <section-panel title="待处理">
    <request-notice :error="attention.error.value" @retry="attention.load()" />
    <portal-attention
      v-if="!attention.error.value || attention.items.value.length"
      :items="attention.items.value"
      :loading="attention.loading.value"
      :support="auth.portal.supportContact"
    />
    <list-pager
      v-if="attention.total.value > attention.size.value"
      v-model:page="attention.page.value"
      v-model:size="attention.size.value"
      :total="attention.total.value"
      @change="attention.load()"
    />
  </section-panel>
  <section-panel id="recent-logs" title="最近验证">
    <portal-records ref="logs" kind="logs" :page-size="10" />
  </section-panel>
</template>
