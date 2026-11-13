<script setup lang="ts">
import FocusOverlay from "../../components/FocusOverlay.vue";
import PayloadKeys from "../../components/PayloadKeys.vue";
import WatermarkTrace from "../../components/WatermarkTrace.vue";
import FeatureTemplates from "../../components/FeatureTemplates.vue";
import TrialSettings from "../../components/TrialSettings.vue";
import RequestNotice from "../../components/RequestNotice.vue";
import KeyValueItem from "../../components/KeyValueItem.vue";
import KeyValueList from "../../components/KeyValueList.vue";
import SectionPanel from "../../components/SectionPanel.vue";
import { computed, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { get, post, download } from "../../lib/http";
import { idText } from "../../lib/json";
import type { Row } from "../../lib/json";
import { useTask, confirmAction } from "../../composables/tasks";
import { useAdminDetail } from "../../composables/admin-detail";
import { announcementSpec, versionSpec } from "../../lib/schema";
import PageHeading from "../../components/PageHeading.vue";
import CrudPanel from "../../components/CrudPanel.vue";
import ConnectionConfig from "../../components/ConnectionConfig.vue";
import VersionManagement from "../../components/VersionManagement.vue";
import CopyField from "../../components/CopyField.vue";
import StatusBadge from "../../components/StatusBadge.vue";
const route = useRoute(),
  router = useRouter(),
  task = useTask(),
  app = ref<Row>(),
  secret = ref(""),
  secretOpen = ref(false);
const activeTab = computed({
  get: () =>
    ["releases", "versions", "templates", "payload-keys"].includes(
      String(route.query.tab),
    )
      ? String(route.query.tab)
      : "integration",
  set: (tab: string) => {
    void router.replace({ query: { ...route.query, tab } });
  },
});
const id = computed(() => String(route.params.id));
const detail = useAdminDetail("/applications", id, app, () => {
  secret.value = "";
  secretOpen.value = false;
  task.error.value = "";
});
const load = detail.load;
async function reveal() {
  await task.run(async () => {
    const selected = detail.capture();
    await confirmAction(
      "查看软件密钥将写入审计记录。请勿把密钥用于公开页面或不受信任的环境。",
      "查看敏感密钥",
      { action: "查看软件密钥" },
    );
    selected.check();
    const result = await get(`/applications/${selected.id}/secret`);
    if (!selected.current()) return;
    secret.value = String(result.app_secret);
    secretOpen.value = true;
  });
}
async function rotate(kind: string) {
  await task.run(async () => {
    const selected = detail.capture();
    await confirmAction(
      kind === "secret"
        ? "接入配置已编译在程序里。重新生成AppSecret后已发布镜像的配置全部失效，必须重新构建并发版；旧HMAC密钥将立即失效。"
        : "将生成新的签名密钥对，仅保留上一个公钥用于过渡。确认继续？",
      "轮换软件密钥",
      {
        action: kind === "secret" ? "重新生成 AppSecret" : "轮换签名密钥对",
        danger: true,
      },
    );
    selected.check();
    const result = await post(
      `/applications/${selected.id}/${kind === "secret" ? "rotate-secret" : "rotate-key-pair"}`,
      {},
    );
    selected.commit(result);
  }, "密钥已轮换");
}
</script>
<template>
  <page-heading
    :title="String(app?.name || '软件工作台')"
    description="查看软件资料、接入程序，并维护功能模板、公告与版本。"
  >
    <template #status>
      <status-badge v-if="app" :value="app.status" />
    </template>
    <el-button :loading="task.busy.value" @click="load">
      刷新
    </el-button>
  </page-heading>
  <el-skeleton
    v-if="detail.loading.value && !app"
    :rows="5"
    animated
    aria-label="正在加载资料"
  /><request-notice :error="detail.error.value" @retry="load()" />
  <request-notice :error="task.error.value" />
  <template v-if="app">
    <section-panel>
      <p v-if="app.description">
        {{ app.description }}
      </p>
      <key-value-list>
        <key-value-item label="App Key">
          <copy-field :value="app.app_key" label="App Key" compact />
        </key-value-item>
      </key-value-list>
    </section-panel>
    <trial-settings :id="id" />
    <el-tabs v-model="activeTab">
      <el-tab-pane name="integration" label="接入程序" lazy>
        <section-panel>
          <connection-config :id="id" />
          <details class="technical-options">
            <summary>高级</summary>
            <section-panel>
              <div class="panel-heading">
                <h2>接入信息</h2>
                <status-badge :value="app.status" />
              </div>
              <key-value-list :column="2" border>
                <key-value-item label="软件编号">
                  {{ idText(app.id) }}
                </key-value-item><key-value-item label="联网检查频率">
                  {{ app.next_check_in }} 秒
                </key-value-item><key-value-item label="断网继续运行（小时）">
                  {{ app.grace_hours }} 小时
                </key-value-item><key-value-item label="心跳间隔">
                  {{ app.heartbeat_interval }} 秒
                </key-value-item>
              </key-value-list>
              <div class="action-toolbar" style="margin-top: 16px">
                <el-button
                  :disabled="!detail.ready.value || task.busy.value"
                  @click="
                    task.run(() =>
                      download(
                        'admin',
                        `/applications/${id}/public-key`,
                        'public-key.pem',
                      ),
                    )
                  "
                >
                  下载公钥PEM
                </el-button><el-button
                  v-if="app.previous_public_key"
                  :disabled="!detail.ready.value || task.busy.value"
                  @click="
                    task.run(() =>
                      download(
                        'admin',
                        `/applications/${id}/public-key`,
                        'previous-public-key.pem',
                        { params: { previous: true } },
                      ),
                    )
                  "
                >
                  下载上一版公钥
                </el-button>
                <el-button
                  type="primary"
                  plain
                  :disabled="!detail.ready.value || task.busy.value"
                  @click="reveal"
                >
                  查看软件密钥
                </el-button><el-button
                  type="warning"
                  plain
                  :disabled="!detail.ready.value || task.busy.value"
                  @click="rotate('secret')"
                >
                  轮换HMAC密钥
                </el-button><el-button
                  type="warning"
                  plain
                  :disabled="!detail.ready.value || task.busy.value"
                  @click="rotate('key-pair')"
                >
                  轮换签名密钥
                </el-button>
              </div>
            </section-panel>
          </details>
        </section-panel>
      </el-tab-pane>
      <el-tab-pane name="versions" label="版本" lazy>
        <version-management :id="id" :key="id" :app-key="String(app.app_key)" />
        <details class="technical-options">
          <summary>手动添加版本</summary>
          <crud-panel
            :spec="versionSpec"
            :list-path="`/applications/${id}/versions`"
            :create-path="`/applications/${id}/versions`"
            embedded
          />
        </details>
      </el-tab-pane>
      <el-tab-pane name="releases" label="公告">
        <crud-panel
          :spec="announcementSpec"
          :list-path="`/applications/${id}/announcements`"
          :create-path="`/applications/${id}/announcements`"
          embedded
        />
      </el-tab-pane>
      <el-tab-pane name="templates" label="功能模板" lazy>
        <feature-templates :id="id" :key="id" />
      </el-tab-pane>
      <el-tab-pane name="payload-keys" label="打包密钥" lazy>
        <payload-keys :id="id" :key="id" :app-key="String(app.app_key)" />
        <watermark-trace :id="id" :key="id" />
      </el-tab-pane>
    </el-tabs>
  </template><focus-overlay
    v-model="secretOpen"
    title="软件HMAC密钥"
    width="480px"
    :close-on-click-modal="false"
    @closed="secret = ''"
  >
    <el-alert
      title="此操作已记录审计，请妥善保存密钥。"
      type="warning"
      :closable="false"
    /><copy-field :value="secret" label="软件密钥" sensitive />
  </focus-overlay>
</template>
