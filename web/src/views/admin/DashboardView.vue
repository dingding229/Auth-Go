<script setup lang="ts">
import { adminPage } from "../../lib/runtime";
import TrialMetrics from "../../components/TrialMetrics.vue";
import SharingCount from "../../components/SharingCount.vue";
import RequestNotice from "../../components/RequestNotice.vue";
import SectionPanel from "../../components/SectionPanel.vue";
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { get } from "../../lib/http";
import { record, rows, type Row, idText } from "../../lib/json";
import { label } from "../../lib/labels";
import { useLoadTask } from "../../composables/tasks";
import {
  issueLicenseLocation,
  integrationLocation,
} from "../../lib/navigation";
import PageHeading from "../../components/PageHeading.vue";
import DataTable from "../../components/DataTable.vue";
import ChartPanel from "../../components/ChartPanel.vue";
const task = useLoadTask(),
  router = useRouter(),
  overview = ref<Row>(),
  trend = ref<Row[]>([]),
  failures = ref<Row[]>([]),
  firstApplicationId = ref(""),
  firstUserId = ref("");
const counts = computed(() => record(overview.value?.counts));
async function load() {
  await task.run(async () => {
    const [o, t, f] = await Promise.all([
      get("/stats/overview"),
      get("/stats/trend"),
      get("/stats/failures"),
    ]);
    overview.value = o;
    trend.value = rows(t.items);
    failures.value = rows(f.items);
    firstApplicationId.value = "";
    firstUserId.value = "";
    if (
      Number(record(o.counts).users_total) > 0 &&
      Number(record(o.counts).licenses_total) === 0
    ) {
      const users = await get("/users", { page_size: 1 });
      firstUserId.value = idText(rows(users.items)[0]?.id);
    }
    if (
      Number(record(o.counts).applications_total) > 0 &&
      Number(record(o.counts).licenses_total) === 0
    ) {
      const apps = await get("/applications", {
        page_size: 1,
        sort_by: "created_at",
        sort_order: "asc",
      });
      firstApplicationId.value = idText(rows(apps.items)[0]?.id);
    }
  });
}
onMounted(() => {
  void load();
});
const color = (name: string) =>
  getComputedStyle(document.documentElement).getPropertyValue(name).trim();
const trendOption = computed(() => ({
  animation: false,
  textStyle: {
    color: color("--ink-3"),
    fontSize: 12,
    fontFamily: getComputedStyle(document.documentElement).getPropertyValue(
      "--font-body",
    ),
  },
  aria: { enabled: true },
  color: [color("--brand"), color("--danger")],
  tooltip: { trigger: "axis" },
  legend: { bottom: 0, data: ["验证总数", "失败次数"] },
  grid: { left: 48, right: 20, top: 20, bottom: 55 },
  xAxis: {
    type: "category",
    data: trend.value.map((v) => String(v.day).slice(5)),
    boundaryGap: false,
  },
  yAxis: { type: "value", minInterval: 1 },
  series: [
    {
      name: "验证总数",
      type: "line",
      data: trend.value.map((v) => Number(v.total)),
      showSymbol: false,
      areaStyle: { color: color("--brand-tint") },
      smooth: false,
    },
    {
      name: "失败次数",
      type: "line",
      data: trend.value.map((v) => Number(v.failed)),
      showSymbol: false,
      lineStyle: { type: "dashed" },
    },
  ],
}));
const failureOption = computed(() => ({
  animation: false,
  textStyle: {
    color: color("--ink-3"),
    fontSize: 12,
    fontFamily: getComputedStyle(document.documentElement).getPropertyValue(
      "--font-body",
    ),
  },
  aria: { enabled: true },
  color: [color("--brand")],
  tooltip: { trigger: "axis" },
  grid: { left: 8, right: 24, top: 16, bottom: 16, containLabel: true },
  xAxis: { type: "value", minInterval: 1 },
  yAxis: {
    type: "category",
    data: failures.value.map((v) => label(v.code)),
    axisLabel: {
      width: 128,
      overflow: "truncate",
      color: color("--ink-2"),
      fontSize: 12,
    },
  },
  series: [
    {
      type: "bar",
      barMaxWidth: 16,
      data: failures.value.map((v) => Number(v.count)),
    },
  ],
}));
const onboardingSteps = computed(() => {
  const hasApp = Number(counts.value.applications_total) > 0,
    hasUser = Number(counts.value.users_total) > 0;
  return [
    {
      title: "添加软件",
      complete: hasApp,
      current: !hasApp,
      to: adminPage("/applications"),
    },
    {
      title: "添加用户",
      complete: hasUser,
      current: hasApp && !hasUser,
      to: hasApp ? adminPage("/users") : undefined,
    },
    {
      title: "发放授权",
      complete: false,
      current: hasApp && hasUser,
      to:
        firstApplicationId.value && firstUserId.value
          ? issueLicenseLocation(firstApplicationId.value, firstUserId.value)
          : undefined,
    },
    {
      title: "接入程序",
      complete: false,
      current: false,
      to: firstApplicationId.value
        ? integrationLocation(firstApplicationId.value)
        : undefined,
    },
  ];
});
const cards = computed(() => {
  const total = trend.value.reduce((sum, v) => sum + Number(v.total || 0), 0),
    failed = trend.value.reduce((sum, v) => sum + Number(v.failed || 0), 0);
  return [
    {
      key: "active",
      title: "有效授权",
      value: counts.value.licenses_active ?? 0,
      hint: "当前可正常使用的授权",
    },
    {
      key: "checks",
      title: "近30天验证次数",
      value: total,
      hint: "按已保留的验证日志统计",
    },
    {
      key: "failure",
      title: "验证失败率",
      value: total ? `${((failed / total) * 100).toFixed(1)}%` : "0.0%",
      hint: "近30天失败次数占比",
    },
    {
      key: "online",
      title: "在线实例",
      value: counts.value.online_instances ?? 0,
      hint: "租约尚未到期的运行实例",
    },
    {
      key: "expiry",
      title: "7天内到期",
      value: counts.value.licenses_expiring ?? 0,
      hint: "及时联系用户处理续期",
    },
  ];
});
</script>
<template>
  <page-heading
    title="概览"
    description="观察授权生命周期。验证统计基于已保留日志，按UTC自然日计算；采样或清理会影响数量。"
  >
    <el-button :loading="task.busy.value" @click="load">
      刷新数据
    </el-button>
  </page-heading>
  <trial-metrics />
  <sharing-count :count="counts.suspected_sharing" />
  <request-notice :error="task.error.value" @retry="load()" />
  <section-panel
    v-if="
      overview &&
        (!Number(counts.applications_total) || !Number(counts.licenses_total))
    "
  >
    <h2>三分钟上手</h2>
    <p>
      按顺序完成软件、用户、授权和程序接入；发出第一份授权后此提示自动隐藏。
    </p>
    <ol class="onboarding-steps" aria-label="上手步骤">
      <li v-for="(step, index) in onboardingSteps" :key="step.title">
        <button
          class="onboarding-step"
          :class="{ 'is-complete': step.complete }"
          :aria-current="step.current ? 'step' : undefined"
          :disabled="!step.to"
          @click="step.to && router.push(step.to)"
        >
          <span class="step-marker" aria-hidden="true">{{
            step.complete ? "✓" : index + 1
          }}</span>
          <span>{{ step.title
          }}<span
            v-if="step.complete"
            class="visually-hidden"
          >（已完成）</span></span>
        </button>
      </li>
    </ol>
  </section-panel>
  <div class="stat-grid" :aria-busy="task.busy.value">
    <article v-for="card in cards" :key="card.key" class="stat-card">
      <span class="stat-label">{{ card.title }}</span>
      <el-skeleton-item
        v-if="!overview && task.busy.value"
        variant="text"
        class="stat-number-skeleton"
      />
      <p v-else class="stat-number">
        {{ overview ? card.value : "—" }}
      </p>
      <span class="stat-hint">{{ card.hint }}</span>
    </article>
  </div>
  <div class="detail-grid">
    <section-panel>
      <div class="panel-heading">
        <h2>近30天验证趋势</h2>
        <span class="muted">今日失败率
          {{
            overview
              ? `${(Number(overview.today_failure_rate) * 100).toFixed(1)}%`
              : "—"
          }}</span>
      </div>
      <el-skeleton
        v-if="!overview && task.busy.value"
        :rows="5"
        animated
        class="chart"
      />
      <chart-panel
        v-else-if="overview"
        :option="trendOption"
        label="近三十天验证总数与失败次数折线图"
      />
      <details>
        <summary>查看趋势数据表</summary>
        <data-table
          :error="task.error.value"
          :items="trend"
          :columns="[
            { key: 'day', title: '日期' },
            { key: 'total', title: '验证次数' },
            { key: 'failed', title: '失败次数' },
          ]"
        />
      </details>
    </section-panel>
    <section-panel>
      <h2>失败原因分布</h2>
      <el-skeleton
        v-if="!overview && task.busy.value"
        :rows="5"
        animated
        class="chart"
      />
      <chart-panel
        v-else-if="failures.length"
        :option="failureOption"
        label="近三十天验证失败原因分布"
      /><el-empty
        v-else-if="overview"
        :description="overview ? '近30天暂无失败记录' : '数据尚未加载'"
      />
      <details v-if="failures.length">
        <summary>查看失败原因数据表</summary>
        <data-table
          :error="task.error.value"
          :items="failures"
          :columns="[
            { key: 'code', title: '错误码', enum: true },
            { key: 'count', title: '次数' },
          ]"
        />
      </details>
    </section-panel>
    <section-panel class="full-width">
      <div class="panel-heading">
        <h2>即将到期的授权</h2>
        <router-link :to="adminPage('/licenses')">查看全部授权</router-link>
      </div>
      <data-table
        :error="task.error.value"
        :loading="task.busy.value"
        :row-href="(row) => adminPage(`/licenses/${idText(row.id)}`)"
        :items="rows(overview?.expiring)"
        empty="7 天内没有到期的授权"
        :actions-width="82"
        :actions-fixed="false"
        :columns="[
          { key: 'key', title: '授权码', mono: true, width: 210 },
          { key: 'app_name', title: '软件名称', width: 100 },
          { key: 'type', title: '类型', enum: true, width: 90 },
          { key: 'expires_at', title: '到期时间', date: true, width: 140 },
        ]"
      />
    </section-panel>
  </div>
</template>
