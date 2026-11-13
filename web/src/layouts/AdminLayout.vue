<script setup lang="ts">
import FocusOverlay from "../components/FocusOverlay.vue";
import { adminPage } from "../lib/runtime";
import { ref, onMounted, computed } from "vue";
import { useRoute, useRouter } from "vue-router";
import { useAuth } from "../stores/auth";
import { useTask } from "../composables/tasks";
import { get } from "../lib/http";
import { useUIStore } from "../stores/ui";
import { Menu, ArrowDown } from "@element-plus/icons-vue";
import { pageTitle as contentTitle } from "../lib/page-title";
import AdminMenu from "../components/AdminMenu.vue";
const route = useRoute(),
  router = useRouter(),
  auth = useAuth(),
  task = useTask(),
  menu = ref(false);
const ui = useUIStore();
const parentPage = computed(() =>
  route.params.id
    ? {
        users: { path: adminPage("/users"), title: "用户" },
        licenses: { path: adminPage("/licenses"), title: "授权" },
        applications: { path: adminPage("/applications"), title: "软件" },
      }[
        String(route.path.split("/")[2]) as
          "users" | "licenses" | "applications"
      ]
    : undefined,
);
const pageTitle = computed(
  () => contentTitle.value || String(route.meta.title || "概览"),
);
onMounted(async () => {
  try {
    ui.siteName = String(
      (await get("/system/settings", undefined, { quiet: true })).site_name,
    );
  } catch {
    /* Keep navigation available when only settings fail. */
  }
});
async function command(value: string) {
  if (value === "profile") {
    await router.push(adminPage("/profile"));
    return;
  }
  await task.run(async () => {
    try {
      await auth.logout();
    } finally {
      await router.replace(adminPage("/login"));
    }
  });
}
</script>
<template>
  <a class="skip-link" href="#main-content">跳至页面内容</a>
  <div class="admin-shell">
    <aside class="admin-sidebar">
      <router-link
        class="brand"
        :to="adminPage('')"
      ><svg
        viewBox="0 0 32 32"
        width="30"
        height="30"
        aria-hidden="true"
      >
        <path
          d="M8 14V9a8 8 0 0 1 16 0v5M5 14h22v16H5zm11 5v6"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
        /></svg><span>Auth Go<small>{{
        ui.siteName === "Auth Go" ? "授权控制台" : ui.siteName
      }}</small></span></router-link><admin-menu />
    </aside>
    <div class="admin-workspace">
      <header class="admin-topbar">
        <el-button
          class="mobile-menu"
          aria-label="打开管理菜单"
          @click="menu = true"
        >
          <el-icon><Menu /></el-icon>
        </el-button><el-breadcrumb separator="/">
          <el-breadcrumb-item v-if="parentPage" :to="parentPage.path">
            {{ parentPage.title }}
          </el-breadcrumb-item>
          <el-breadcrumb-item>{{ pageTitle }}</el-breadcrumb-item>
        </el-breadcrumb>
        <div class="user-menu">
          <el-dropdown @command="command">
            <el-button text>
              {{ auth.admin.user.username }}
              <el-icon><ArrowDown /></el-icon>
            </el-button><template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="profile">
                  个人安全设置
                </el-dropdown-item><el-dropdown-item command="logout" divided>
                  退出登录
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </header>
      <main id="main-content" class="admin-content" tabindex="-1">
        <router-view />
      </main>
    </div>
  </div>
  <focus-overlay
    v-model="menu"
    drawer
    class="navigation-drawer"
    title="授权控制台"
    direction="ltr"
    size="216px"
  >
    <admin-menu @select="menu = false" />
  </focus-overlay>
</template>
