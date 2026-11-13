<script setup lang="ts">
import { useQueryTab } from "../../composables/query-tab";
import { ref, watch } from "vue";
import PageHeading from "../../components/PageHeading.vue";
import SectionPanel from "../../components/SectionPanel.vue";
import SDKExamples from "../../components/SDKExamples.vue";
import ProtocolDocument from "../../components/ProtocolDocument.vue";
import AdminApiReference from "../../components/AdminApiReference.vue";
import { get } from "../../lib/http";
import { saveBlob } from "../../lib/files";
import { documentTabs, type DocumentName } from "../../lib/markdown";
import { stringify, type Row } from "../../lib/json";
import { useLoadTask } from "../../composables/tasks";
import RequestNotice from "../../components/RequestNotice.vue";
const docsTask = useLoadTask(),
  spec = ref<Row>();
async function loadAdminDocs() {
  await docsTask.run(async () => {
    spec.value = await get("/docs/openapi.json");
  });
}
function downloadAdminDocs() {
  if (spec.value)
    saveBlob(
      new Blob([stringify(spec.value, 2)], { type: "application/json" }),
      "openapi.json",
    );
}
const documents: { name: DocumentName; label: string }[] = [
  { name: "quickstart", label: "快速开始" },
  { name: "docker", label: "Docker 接入" },
  { name: "customer", label: "给客户的运行说明" },
  { name: "offline", label: "离线与故障" },
  { name: "protocol", label: "协议规范" },
];
const tab = useQueryTab(documentTabs, "quickstart");
watch(
  tab,
  (value) => {
    if (value === "admin-api" && !spec.value && !docsTask.busy.value)
      void loadAdminDocs();
  },
  { immediate: true },
);
</script>
<template>
  <page-heading
    title="接入文档"
    description="从首次接入到客户运行，按需查阅 SDK 示例、故障处理与协议规范。"
  />
  <el-tabs v-model="tab" class="integration-docs-tabs">
    <el-tab-pane
      v-for="document in documents"
      :key="document.name"
      :label="document.label"
      :name="document.name"
    >
      <section-panel v-if="tab === document.name">
        <ProtocolDocument :document="document.name" />
      </section-panel>
    </el-tab-pane>
    <el-tab-pane label="SDK 示例" name="sdk">
      <section-panel v-if="tab === 'sdk'" class="document-body sdk-document">
        <SDKExamples />
      </section-panel>
    </el-tab-pane>
    <el-tab-pane label="管理 API" name="admin-api">
      <section-panel v-if="tab === 'admin-api'" title="管理 API 文档">
        <request-notice
          :error="docsTask.error.value"
          :busy="docsTask.busy.value"
          @retry="loadAdminDocs"
        />
        <el-skeleton v-if="docsTask.busy.value && !spec" :rows="8" animated />
        <template v-if="spec">
          <div class="action-toolbar">
            <el-button @click="downloadAdminDocs">
              下载 OpenAPI JSON
            </el-button>
          </div>
          <AdminApiReference :spec="spec" />
        </template>
      </section-panel>
    </el-tab-pane>
  </el-tabs>
</template>
