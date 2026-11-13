<script setup lang="ts">
defineProps<{ visible: boolean }>();
</script>
<template>
  <p v-if="visible" class="ip-attribution">
    IP 地理位置数据由
    <a
      href="https://db-ip.com"
      target="_blank"
      rel="noopener noreferrer"
    >DB-IP.com</a>
    提供
  </p>
</template>
