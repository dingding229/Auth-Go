<script setup lang="ts">
import { useRoute } from "vue-router";
import { entryPath } from "../lib/entry";
const route = useRoute();
import StatusPage from "../components/StatusPage.vue";
</script>
<template>
  <status-page
    title="页面不存在"
    description="请检查地址，或返回入口继续操作。"
  >
    <router-link :to="entryPath(route.query.next || route.path)"><el-button type="primary">返回入口</el-button></router-link>
  </status-page>
</template>
