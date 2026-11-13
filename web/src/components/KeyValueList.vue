<script setup lang="ts">
defineProps<{ items?: { label: string; value: unknown; mono?: boolean }[] }>();
import { text } from "../lib/json";
</script>
<template>
  <dl class="key-value-list">
    <template v-if="items">
      <div v-for="item in items" :key="item.label" class="key-value-item">
        <dt>{{ item.label }}</dt>
        <dd :class="{ 'code-value': item.mono }">
          {{ text(item.value) }}
        </dd>
      </div>
    </template><slot />
  </dl>
</template>
