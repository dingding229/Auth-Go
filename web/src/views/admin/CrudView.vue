<script setup lang="ts">
import FocusOverlay from "../../components/FocusOverlay.vue";
import { computed, ref } from "vue";
import { useRoute } from "vue-router";
import { specs } from "../../lib/schema";
import PageHeading from "../../components/PageHeading.vue";
import CrudPanel from "../../components/CrudPanel.vue";
import ConnectionConfig from "../../components/ConnectionConfig.vue";
import { idText, type Row } from "../../lib/json";
const panel = ref<InstanceType<typeof CrudPanel>>();
const created = ref<Row>();
const route = useRoute();
const spec = computed(() => specs[String(route.meta.resource)]!);
</script>
<template>
  <page-heading :title="spec.title" :description="spec.description">
    <el-button type="primary" @click="panel?.create()">
      新建{{ spec.singular }}
    </el-button>
  </page-heading><crud-panel
    ref="panel"
    :key="spec.key"
    :spec="spec"
    @created="spec.key === 'applications' && (created = $event)"
  />
  <focus-overlay
    :model-value="!!created"
    title="软件已创建 · 接入程序"
    width="480px"
    :close-on-click-modal="false"
    destroy-on-close
    @update:model-value="created = undefined"
  >
    <connection-config v-if="created" :id="idText(created.id)" auto-reveal />
  </focus-overlay>
</template>
