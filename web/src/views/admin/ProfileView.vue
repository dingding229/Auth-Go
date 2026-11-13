<script setup lang="ts">
import FocusOverlay from "../../components/FocusOverlay.vue";
import { adminPage } from "../../lib/runtime";
import SectionPanel from "../../components/SectionPanel.vue";
import { computed, reactive, ref } from "vue";
import { useRouter } from "vue-router";
import QRCode from "qrcode";
import { useAuth } from "../../stores/auth";
import { post } from "../../lib/http";
import { useTask } from "../../composables/tasks";
import PageHeading from "../../components/PageHeading.vue";
import CopyField from "../../components/CopyField.vue";

const auth = useAuth(),
  router = useRouter(),
  task = useTask();
const password = reactive({ old: "", next: "", repeat: "" }),
  totp = reactive({ password: "", code: "" }),
  qr = ref(""),
  secret = ref(""),
  setupOpen = ref(false);
const enabled = computed(() => Boolean(auth.admin.user.totp_enabled));
function clearSetup() {
  task.error.value = "";
  qr.value = "";
  secret.value = "";
  totp.code = "";
}
async function relogin() {
  auth.clearAdmin();
  await router.replace(adminPage("/login"));
}
async function changePassword() {
  await task.run(async () => {
    const n = new TextEncoder().encode(password.next).length;
    if (!password.old || n < 8 || n > 72)
      throw new Error("请输入当前密码，并将新密码设为8–72字节");
    if (password.next !== password.repeat)
      throw new Error("两次新密码输入不一致");
    await post("/auth/password", {
      old_password: password.old,
      new_password: password.next,
    });
    password.old = "";
    password.next = "";
    password.repeat = "";
    await relogin();
  }, "密码已修改，请重新登录");
}
async function setup() {
  await task.run(async () => {
    if (!totp.password) throw new Error("请先填写当前登录密码");
    const value = await post("/auth/totp/setup", { password: totp.password });
    secret.value = String(value.secret);
    qr.value = await QRCode.toDataURL(String(value.otpauth_uri), {
      width: 240,
      margin: 2,
      errorCorrectionLevel: "M",
    });
    totp.password = "";
    totp.code = "";
    setupOpen.value = true;
  });
}
async function enable() {
  await task.run(async () => {
    if (!/^\d{6}$/.test(totp.code)) throw new Error("请输入认证器的六位验证码");
    await post("/auth/totp/enable", { totp_code: totp.code });
    setupOpen.value = false;
    secret.value = "";
    qr.value = "";
    totp.code = "";
    await relogin();
  }, "两步验证已启用，请等待验证码刷新后重新登录");
}
async function disable() {
  await task.run(async () => {
    if (!totp.password || !/^\d{6}$/.test(totp.code))
      throw new Error("请填写当前密码和认证器的六位验证码");
    await post("/auth/totp/disable", {
      password: totp.password,
      totp_code: totp.code,
    });
    totp.password = "";
    totp.code = "";
    await relogin();
  }, "两步验证已停用，请重新登录");
}
</script>
<template>
  <page-heading
    title="个人安全"
    description="密码或两步验证变更后，现有登录会话将失效。请妥善保管认证器与恢复信息。"
  /><el-alert
    v-if="task.error.value && !setupOpen"
    :title="task.error.value"
    type="error"
    :closable="false"
  />
  <div class="security-section">
    <section-panel>
      <h2>修改登录密码</h2>
      <el-form label-position="top" @submit.prevent="changePassword">
        <el-form-item label="当前密码">
          <el-input
            v-model="password.old"
            type="password"
            show-password
            autocomplete="current-password"
          />
        </el-form-item><el-form-item label="新密码（8–72字节）">
          <el-input
            v-model="password.next"
            type="password"
            show-password
            autocomplete="new-password"
          />
        </el-form-item><el-form-item label="再次输入新密码">
          <el-input
            v-model="password.repeat"
            type="password"
            show-password
            autocomplete="new-password"
          />
        </el-form-item><el-button
          type="primary"
          native-type="submit"
          :loading="task.busy.value"
        >
          修改密码
        </el-button>
      </el-form>
    </section-panel>
    <section-panel>
      <div class="panel-heading">
        <h2>两步验证</h2>
        <el-tag :type="enabled ? 'success' : 'info'">
          {{ enabled ? "已启用" : "未启用" }}
        </el-tag>
      </div>
      <p class="muted">
        使用支持TOTP
        的认证器生成六位验证码。二维码与密钥仅在本次绑定中展示，不会发送给第三方服务。
      </p>
      <el-form
        label-position="top"
        @submit.prevent="enabled ? disable() : setup()"
      >
        <el-form-item label="当前登录密码">
          <el-input
            v-model="totp.password"
            type="password"
            show-password
            autocomplete="current-password"
          />
        </el-form-item><el-form-item v-if="enabled" label="当前认证器验证码">
          <el-input
            v-model="totp.code"
            maxlength="6"
            inputmode="numeric"
            autocomplete="one-time-code"
          />
        </el-form-item><el-button
          :type="enabled ? 'danger' : 'primary'"
          native-type="submit"
          :loading="task.busy.value"
        >
          {{ enabled ? "停用两步验证" : "开始绑定认证器" }}
        </el-button>
      </el-form>
    </section-panel>
  </div>
  <focus-overlay
    v-model="setupOpen"
    title="绑定认证器"
    width="480px"
    :close-on-click-modal="false"
    @closed="clearSetup"
  >
    <p>
      使用认证器扫描二维码，再输入生成的验证码完成验证。待绑定密钥十分钟内有效。
    </p>
    <img
      v-if="qr"
      :src="qr"
      class="qr-image"
      alt="用于绑定TOTP认证器的二维码"
    /><copy-field :value="secret" label="认证器密钥" sensitive /><el-form
      label-position="top"
      @submit.prevent="enable"
    >
      <el-alert
        v-if="task.error.value"
        :title="task.error.value"
        type="error"
        :closable="false"
      />
      <el-form-item label="六位认证器验证码">
        <el-input
          v-model="totp.code"
          maxlength="6"
          inputmode="numeric"
          autocomplete="one-time-code"
        />
      </el-form-item><el-button
        type="primary"
        native-type="submit"
        :loading="task.busy.value"
      >
        验证并启用
      </el-button>
    </el-form>
  </focus-overlay>
</template>
