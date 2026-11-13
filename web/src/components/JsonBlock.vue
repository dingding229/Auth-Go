<script setup lang="ts">
import { computed } from "vue";
import { stringify } from "../lib/json";
import { copy } from "../lib/http";
const props = defineProps<{ value: unknown; title?: string }>();
const content = computed(() =>
  typeof props.value === "string"
    ? props.value
    : stringify(props.value ?? {}, 2),
);
</script>
<template>
  <section class="json-block">
    <div class="json-heading">
      <strong>{{ title || "详细数据" }}</strong><el-button size="small" @click="copy(content)">
        复制
      </el-button>
    </div>
    <pre tabindex="0">{{ content }}</pre>
  </section>
</template>
