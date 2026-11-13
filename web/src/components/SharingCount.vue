<script setup lang="ts">
import { adminPage } from "../lib/runtime";
defineProps<{ count: unknown }>();
</script>
<template>
  <p v-if="Number(count) > 0" class="sharing-overview">
    <router-link :to="adminPage('/licenses?suspected_sharing=true')">疑似共享 {{ count }} 个授权 · 查看提示</router-link>
  </p>
</template>
