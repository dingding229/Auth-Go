<script setup lang="ts">
defineProps<{ title: string; description: string }>();
</script>
<template>
  <main class="state-page">
    <h1>{{ title }}</h1>
    <p>{{ description }}</p>
    <slot />
  </main>
</template>
