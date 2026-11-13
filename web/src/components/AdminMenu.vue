<script setup lang="ts">
import {
  DataAnalysis,
  User,
  Key,
  Monitor,
  Box,
  Document,
  Tickets,
  Setting,
  Lock,
} from "@element-plus/icons-vue";
import { computed } from "vue";
import { useRoute } from "vue-router";
import { adminPages } from "../router";
const route = useRoute();
const icons: Record<string, unknown> = {
  overview: DataAnalysis,
  users: User,
  licenses: Key,
  activations: Monitor,
  applications: Box,
  "verify-logs": Document,
  docs: Document,
  "audit-logs": Tickets,
  settings: Setting,
  profile: Lock,
};
const pages = computed(() => adminPages);
const groups = computed(() => [...new Set(pages.value.map((p) => p.section))]);
defineEmits<{ select: [] }>();
</script>
<template>
  <nav aria-label="管理菜单">
    <el-menu
      router
      :default-active="pages.find((p) => route.path.startsWith(p.path))?.path"
      @select="$emit('select')"
    >
      <template v-for="group in groups" :key="group">
        <p class="menu-group">
          {{ group }}
        </p>
        <el-menu-item
          v-for="page in pages.filter((p) => p.section === group)"
          :key="page.path"
          :index="page.path"
        >
          <el-icon aria-hidden="true">
            <component :is="icons[page.id.slice('admin-'.length)]" />
          </el-icon>{{ page.title }}
        </el-menu-item>
      </template>
    </el-menu>
  </nav>
</template>
