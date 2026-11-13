<script setup lang="ts">
import { adminPage } from "../../lib/runtime";
import { computed, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import PageHeading from "../../components/PageHeading.vue";
import SectionPanel from "../../components/SectionPanel.vue";
import SDKExamples from "../../components/SDKExamples.vue";
import ProtocolDocument from "../../components/ProtocolDocument.vue";
import { get, saveBlob } from "../../lib/http";
import { stringify, type Row } from "../../lib/json";
import { useLoadTask } from "../../composables/tasks";
import JsonBlock from "../../components/JsonBlock.vue";
import RequestNotice from "../../components/RequestNotice.vue";
const docsTask = useLoadTask(), spec = ref<Row>();
async function loadAdminDocs() {
  await docsTask.run(async () => { spec.value = await get("/docs/openapi.json"); });
}
function downloadAdminDocs() {
  if (spec.value) saveBlob(new Blob([stringify(spec.value, 2)], { type: "application/json" }), "openapi.json");
}
const route = useRoute(),
  router = useRouter();
const tabs = ["quickstart", "docker", "sdk", "offline", "protocol", "admin-api"];
const tab = computed({
  get: () =>
    tabs.includes(String(route.query.tab))
      ? String(route.query.tab)
      : "quickstart",
  set: (value: string) => {
    void router.replace({ query: { ...route.query, tab: value } });
  },
});
watch(tab, (value) => {
  if (value === "admin-api" && !spec.value && !docsTask.busy.value) void loadAdminDocs();
}, { immediate: true });
</script>
<template>
  <page-heading
    title="接入文档"
    description="从发放第一个授权到接入程序，查阅官方SDK示例与协议。"
  />
  <el-tabs v-model="tab">
    <el-tab-pane label="快速开始" name="quickstart">
      <section-panel title="四步接入">
        <ol class="docs-steps">
          <li>
            <router-link :to="adminPage('/applications')">新建软件</router-link>：只填名称，保存软件。
          </li>
          <li>
            <router-link :to="adminPage('/licenses?create=1')">发放授权</router-link>：选择用户和软件，生成授权码。
          </li>
          <li>
            <router-link :to="adminPage('/applications')">复制接入配置</router-link>：进入软件的“接入程序”，填写程序可以访问的服务地址并复制配置。
          </li>
          <li>
            <a href="#" @click.prevent="tab = 'sdk'">调用SDK</a>：将接入配置写入源码常量并构建，客户只设置AUTHGO_LICENSE，然后使用Guard维持校验和心跳；最终失败由常驻程序退出77，请求式返回503。
          </li>
        </ol>
        <p>
          配置可以公开，但必须编译进程序，不能从环境变量或文件读取；app_secret不是调用方身份凭据。固定服务地址及Ed25519公钥是信任根，不能让客户替换。AUTHGO_LICENSE是客户填入的授权码。
        </p>
      </section-panel>
    </el-tab-pane>
    <el-tab-pane label="Docker部署" name="docker" lazy>
      <section-panel><ProtocolDocument document="docker" /></section-panel>
    </el-tab-pane>
    <el-tab-pane label="SDK示例" name="sdk" lazy>
      <section-panel><SDKExamples /></section-panel>
    </el-tab-pane>
    <el-tab-pane label="离线与故障" name="offline">
      <section-panel title="联网、缓存与故障">
        <p>首次激活必须联网。已认证票据可在原签名宽限内继续使用。</p>
        <p>
          在线成功后保存已签名票据与本机加密缓存。只有连接故障或已认证的临时错误才可能使用有效缓存（包括浮动授权）；明确的授权拒绝不会进入宽限。软件默认宽限72小时，结束后停止，不提供降级模式。
        </p>
        <p>
          不使用备用清单延长宽限。超过5分钟的时钟回拨时不使用缓存回退，在线验证成功后恢复。
        </p>
        <p>
          更新检查不改变授权缓存。只提供 Docker Hub 版本检查及 docker pull
          命令；程序和镜像仍由客户自行部署。
        </p>
        <p>
          客户端由最终用户控制，混淆不能保证绝对防破解。完整规则见“协议文档”。
        </p>
      </section-panel>
    </el-tab-pane>
    <el-tab-pane label="协议文档" name="protocol" lazy>
      <section-panel>
        <ProtocolDocument />
        <p class="muted">
          管理接口文档请查看“管理API”，仅向已登录的管理员提供。
        </p>
      </section-panel>
    </el-tab-pane>
    <el-tab-pane label="管理API" name="admin-api" lazy>
      <section-panel title="管理API文档">
        <p class="muted">
          当前后台地址的 OpenAPI 文档，仅使用当前管理员身份加载。
        </p>
        <request-notice :error="docsTask.error.value" :busy="docsTask.busy.value" @retry="loadAdminDocs" />
        <template v-if="spec">
          <el-button @click="downloadAdminDocs">
            下载 OpenAPI JSON
          </el-button>
          <JsonBlock :value="spec" title="OpenAPI JSON" />
        </template>
      </section-panel>
    </el-tab-pane>
  </el-tabs>
</template>
