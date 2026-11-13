<script setup lang="ts">
import { watch, onBeforeUnmount } from "vue";
import { pageTitle } from "../lib/page-title";
import ActionMenu from "./ActionMenu";
import CopyField from "./CopyField.vue";
const props = defineProps<{
  title: string;
  description?: string;
  copy?: boolean;
  managedActions?: boolean;
}>();
watch(
  () => props.title,
  (title) => (pageTitle.value = title),
  { immediate: true },
);
onBeforeUnmount(() => (pageTitle.value = ""));
</script>
<template>
  <header class="page-heading" :class="{ 'has-copy-title': copy }">
    <div>
      <div class="page-title-line">
        <h1 :class="{ 'visually-hidden': copy }">
          {{ title }}
        </h1>
        <copy-field
          v-if="copy"
          :value="title"
          label="授权码"
          compact
          :expandable="false"
        /><slot name="status" />
      </div>
      <div
        v-if="description || $slots.description"
        class="page-heading-description"
      >
        <slot name="description">
          {{ description }}
        </slot>
        <span class="mobile-heading-status"><slot name="status" /></span>
      </div>
    </div>
    <div v-if="$slots.default" class="heading-actions">
      <slot v-if="managedActions" />
      <action-menu v-else :limit="100" keep-primary>
        <slot />
      </action-menu>
    </div>
  </header>
</template>
