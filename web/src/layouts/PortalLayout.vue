<script setup lang="ts">
import IpAttribution from "../components/IpAttribution.vue";
import { ArrowDown } from "@element-plus/icons-vue";
import { computed } from "vue";
import { useRouter } from "vue-router";
import { portalPages, userPortalPages } from "../lib/portal-navigation";
import { useAuth } from "../stores/auth";
const auth = useAuth(),
  router = useRouter();
const pages = computed(() =>
  auth.portal.scope === "user"
    ? userPortalPages
    : portalPages.filter((p) => {
        if (p.path === "/portal/home") return auth.portal.scope === "user";
        if (!auth.portal.license.id) return false;
        if (p.path === "/portal/announcements")
          return !!auth.portal.license.has_announcements;
        return true;
      }),
);
function logout() {
  auth.clearPortal();
  void router.replace("/portal/login");
}
</script>
<template>
  <a class="skip-link" href="#portal-content">跳至页面内容</a>
  <div class="portal-shell">
    <header class="portal-header">
      <router-link
        class="portal-brand"
        to="/portal"
      >Auth Go <span>用户中心</span></router-link>
      <nav
        class="portal-nav"
        :class="{ 'is-single': pages.length === 1 }"
        aria-label="用户中心导航"
      >
        <router-link v-for="page in pages" :key="page.path" :to="page.path">{{
          page.title
        }}</router-link>
      </nav>
      <el-dropdown trigger="click" @command="logout">
        <el-button text aria-label="账户菜单">
          {{
            auth.portal.scope === "user"
              ? auth.portal.user.name || "我的账户"
              : "我的授权"
          }}<el-icon><ArrowDown /></el-icon>
        </el-button><template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item command="logout">
              退出用户中心
            </el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
    </header>
    <div class="portal-container">
      <main id="portal-content" tabindex="-1">
        <router-view />
      </main>
      <footer class="portal-footer">
        <span>如需续期或调整授权策略，请联系软件提供方。</span>
        <p v-if="auth.portal.supportContact" class="portal-support">
          {{ auth.portal.supportContact }}
        </p>
        <IpAttribution :visible="auth.portal.ipInfoDBIP" />
      </footer>
    </div>
  </div>
</template>
