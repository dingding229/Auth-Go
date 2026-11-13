<script setup lang="ts">
import { adminPage } from "../lib/runtime";
import SectionPanel from "../components/SectionPanel.vue";
import RequestNotice from "../components/RequestNotice.vue";
import { onMounted, onBeforeUnmount, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { get, post } from "../lib/http";
import { setAdmin } from "../lib/session";
import { useTask, useLoadTask } from "../composables/tasks";
const route = useRoute(),
  router = useRouter(),
  task = useTask(),
  loadTask = useLoadTask();
let token = typeof route.query.token === "string" ? route.query.token : "";
const username = ref("admin"),
  password = ref(""),
  confirmation = ref(""),
  available = ref(false),
  stateReady = ref(false);
async function checkState() {
  await loadTask.run(async () => {
    const state = await get("/status");
    stateReady.value = true;
    if (!state.setup_required) {
      token = "";
      available.value = false;
      await router.replace("/not-found");
      return;
    }
    available.value = !!token;
  });
}
onMounted(async () => {
  // Capability stays only in this component's memory, including network retries.
  await router.replace(adminPage("/setup"));
  await checkState();
});
onBeforeUnmount(() => {
  token = "";
  password.value = "";
  confirmation.value = "";
});
async function submit() {
  if (!stateReady.value || !available.value) return;
  await task.run(async () => {
    const length = new TextEncoder().encode(password.value).length;
    if (!username.value.trim() || length < 8 || length > 72)
      throw new Error("请填写用户名和8至72字节的密码");
    if (password.value !== confirmation.value)
      throw new Error("两次密码不一致");
    const pair = await post("/auth/setup", {
      token,
      username: username.value,
      password: password.value,
    });
    token = "";
    password.value = "";
    confirmation.value = "";
    available.value = false;
    setAdmin(String(pair.access_token), String(pair.refresh_token), pair.admin);
    await router.replace(adminPage("/overview"));
  });
}
</script>
<template>
  <main class="login-page setup-page">
    <router-link class="brand" to="/">Auth Go</router-link><section-panel class="setup-card">
      <h1>首次初始化</h1>
      <p>
        1.设置管理员账号与密码<br />2.完成初始化后直接进入管理端。链接仅本次有效，请勿转发。
      </p>
      <request-notice
        :error="loadTask.error.value"
        :busy="loadTask.busy.value"
        retry-label="重试读取初始化状态"
        @retry="checkState"
      />
      <el-form v-if="available" label-position="top" @submit.prevent="submit">
        <request-notice :error="task.error.value" />
        <el-form-item label="管理员用户名" required>
          <el-input
            v-model="username"
            autocomplete="username"
            maxlength="128"
          />
        </el-form-item>
        <el-form-item label="管理员密码" required>
          <el-input
            v-model="password"
            type="password"
            show-password
            autocomplete="new-password"
          />
        </el-form-item>
        <el-form-item label="再次输入密码" required>
          <el-input
            v-model="confirmation"
            type="password"
            show-password
            autocomplete="new-password"
          />
        </el-form-item>
        <el-button
          type="primary"
          native-type="submit"
          :loading="task.busy.value"
        >
          完成初始化并登录
        </el-button>
      </el-form>
      <el-alert
        v-else-if="stateReady"
        title="请从当前服务日志获取完整初始化链接。初始化完成后此入口将关闭。"
        type="info"
        :closable="false"
      />
      <p v-else-if="task.busy.value" role="status">
        正在读取初始化状态…
      </p>
      <router-link :to="adminPage('/login')">返回登录</router-link>
    </section-panel>
  </main>
</template>
