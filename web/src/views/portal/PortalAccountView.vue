<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import { useAuth } from "../../stores/auth";
import { useTask, useLoadTask } from "../../composables/tasks";
import { pget, ppost } from "../../lib/http";
import PageHeading from "../../components/PageHeading.vue";
import SectionPanel from "../../components/SectionPanel.vue";
import KeyValueList from "../../components/KeyValueList.vue";
import RequestNotice from "../../components/RequestNotice.vue";
const auth = useAuth(),
  router = useRouter(),
  loadTask = useLoadTask(),
  task = useTask(),
  sendTask = useTask();
const oldPassword = ref(""),
  newPassword = ref(""),
  confirmation = ref(""),
  passwordError = ref(""),
  confirmationError = ref(""),
  credentialError = ref(""),
  code = ref(""),
  canEmail = ref(false),
  ready = ref(false);
let lastSent = 0;
async function load() {
  ready.value = false;
  await loadTask.run(async () => {
    const [user, options] = await Promise.all([
      pget("/user"),
      pget("/login/options"),
    ]);
    auth.portal.user = user;
    canEmail.value = options.smtp_configured === true;
    ready.value = true;
  });
}
async function send() {
  if (!ready.value || !canEmail.value || task.busy.value) return;
  await sendTask.run(async () => {
    if (Date.now() - lastSent < 60000) throw new Error("请等待60秒后重试");
    await ppost("/user/login/code", { email: auth.portal.user.email });
    lastSent = Date.now();
  }, "如该邮箱可用于验证，将收到验证码");
}
async function password() {
  if (!ready.value || task.busy.value || sendTask.busy.value) return;
  task.error.value = "";
  passwordError.value = "";
  confirmationError.value = "";
  credentialError.value = "";
  if (!oldPassword.value && !(canEmail.value && /^\d{6}$/.test(code.value))) {
    credentialError.value = canEmail.value
      ? "请填写原密码或有效的六位邮箱验证码"
      : "请填写原密码；首次设置或忘记原密码，请联系管理员重新设置密码";
    return;
  }
  const bytes = new TextEncoder().encode(newPassword.value).length;
  if (bytes < 8 || bytes > 72) {
    passwordError.value = "新密码须为8至72字节";
    return;
  }
  if (newPassword.value !== confirmation.value) {
    confirmationError.value = "两次新密码输入不一致";
    return;
  }
  await task.run(async () => {
    await ppost("/password", {
      old_password: oldPassword.value,
      new_password: newPassword.value,
      code: canEmail.value ? code.value : "",
    });
    oldPassword.value = "";
    newPassword.value = "";
    confirmation.value = "";
    code.value = "";
    auth.clearPortal();
    await router.replace("/portal/login");
  }, "密码已修改，请重新登录");
}
onMounted(load);
</script>
<template>
  <page-heading title="账号安全" />
  <request-notice
    :error="loadTask.error.value"
    :busy="loadTask.busy.value"
    @retry="load"
  />
  <el-skeleton v-if="loadTask.busy.value" :rows="4" animated />
  <section-panel title="账号资料">
    <key-value-list
      :items="[
        { label: '姓名', value: auth.portal.user.name },
        { label: '邮箱', value: auth.portal.user.email },
      ]"
    />
    <p class="muted">
      姓名和邮箱由管理员维护，如需修改请联系软件提供方。
    </p>
  </section-panel>
  <section-panel v-if="ready" title="修改用户中心密码">
    <p>修改后所有旧登录状态立即失效。</p>
    <p v-if="canEmail">
      首次设置或忘记旧密码时，可使用邮箱验证码。
    </p>
    <p v-else>
      当前未启用邮箱验证码，请填写原密码；首次设置或忘记原密码，请联系管理员重新设置密码。
    </p>
    <el-form
      class="portal-account-form"
      label-position="top"
      @submit.prevent="password"
    >
      <request-notice :error="task.error.value" />
      <el-form-item label="原密码" :error="credentialError">
        <el-input
          v-model="oldPassword"
          type="password"
          show-password
          autocomplete="current-password"
        />
      </el-form-item>
      <el-form-item v-if="canEmail" label="邮箱验证码（与原密码二选一）">
        <el-input v-model="code" maxlength="6" inputmode="numeric" /><el-button
          :loading="sendTask.busy.value"
          :disabled="task.busy.value"
          @click="send"
        >
          发送验证码
        </el-button>
      </el-form-item>
      <request-notice v-if="canEmail" :error="sendTask.error.value" />
      <el-form-item label="新密码" required :error="passwordError">
        <el-input
          v-model="newPassword"
          type="password"
          show-password
          autocomplete="new-password"
        />
      </el-form-item>
      <el-form-item label="再次输入新密码" required :error="confirmationError">
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
        :disabled="sendTask.busy.value"
      >
        保存密码并重新登录
      </el-button>
    </el-form>
  </section-panel>
</template>
