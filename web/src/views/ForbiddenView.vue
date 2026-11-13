<script setup lang="ts">
import { useRoute } from "vue-router";
import { entryPath } from "../lib/entry";
const route = useRoute();
import StatusPage from "../components/StatusPage.vue";
</script>
<template>
  <status-page
    title="无权访问"
    description="当前账号无法访问此内容，请返回检查可用入口。"
  >
    <router-link :to="entryPath(route.query.next || route.path)"><el-button type="primary">返回入口</el-button></router-link>
  </status-page>
</template>
