<script setup lang="ts">
import { inject, provide } from "vue";
defineProps<{ title?: string }>();
const nested = inject("authgo-panel", false);
provide("authgo-panel", true);
</script>
<template>
  <section :class="nested ? 'section-group' : 'section-panel'">
    <header v-if="title || $slots.actions" class="panel-heading">
      <h2 v-if="title">
        {{ title }}
      </h2>
      <slot name="actions" />
    </header>
    <slot />
  </section>
</template>
