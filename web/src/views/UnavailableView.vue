<script setup lang="ts">
import { isAdminPage } from "../lib/runtime";
import { entryPath } from "../lib/entry";
import StatusPage from "../components/StatusPage.vue";
import { useRoute, useRouter } from "vue-router";
const route = useRoute(),
  router = useRouter();
function retry() {
  const next = String(route.query.next ?? "");
  void router.replace(
    isAdminPage(next) || next.startsWith("/portal/")
      ? next
      : entryPath(route.query.next),
  );
}
</script>
<template>
  <status-page
    title="暂时无法连接服务"
    description="登录凭据尚未清除，请检查网络或稍后重试。"
  >
    <el-button type="primary" @click="retry">
      重新加载页面
    </el-button>
  </status-page>
</template>
