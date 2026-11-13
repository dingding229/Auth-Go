<script setup lang="ts">
import { computed, useSlots, Text, Comment } from "vue";
defineProps<{ label: string }>();
const slots = useSlots();
const hasValue = computed(() =>
  slots
    .default?.()
    .some(
      (v) =>
        v.type !== Comment &&
        (v.type !== Text || String(v.children ?? "").trim()),
    ),
);
</script>
<template>
  <div class="key-value-item">
    <dt>{{ label }}</dt>
    <dd
      :class="{
        'code-value': /授权码|密钥|公钥|指纹|IP|版本|配置串/.test(label),
      }"
    >
      <slot v-if="hasValue" /><template v-else>
        —
      </template>
    </dd>
  </div>
</template>
