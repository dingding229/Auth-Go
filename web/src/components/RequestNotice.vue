<script setup lang="ts">
defineProps<{ error: string; busy?: boolean; retryLabel?: string; onRetry?: () => void }>();
</script>
<template>
  <div v-if="error" class="request-notice" role="alert">
    <p>{{ error }}</p>
    <el-button v-if="onRetry" :loading="busy" @click="onRetry">
      {{ retryLabel || "重试" }}
    </el-button>
  </div>
</template>
