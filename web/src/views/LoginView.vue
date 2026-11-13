<script setup lang="ts">
import { adminPath, adminPage } from "../lib/runtime";
import { computed, onBeforeUnmount, onMounted, reactive, ref } from "vue";
import type { FormInstance } from "element-plus";
import { useRoute, useRouter } from "vue-router";
import { useAuth } from "../stores/auth";
import { get, pget, ppost } from "../lib/http";
import RequestNotice from "../components/RequestNotice.vue";
import { useTask, useLoadTask } from "../composables/tasks";
const props = defineProps<{ mode: "admin" | "portal" }>();
const route = useRoute(),
  router = useRouter(),
  auth = useAuth(),
  form = ref<FormInstance>(),
  task = useTask(),
  loadTask = useLoadTask(),
  sendTask = useTask();
const values = reactive({
    username: "",
    password: "",
    totp_code: "",
    license_key: "",
    email: "",
    code: "",
  }),
  portalMode = ref("user"),
  method = ref("password"),
  canEmail = ref(false),
  optionsReady = ref(false),
  cooldown = ref(0),
  setupRequired = ref(false);
let timer: ReturnType<typeof setInterval> | undefined;
const admin = computed(() => props.mode === "admin");
async function options() {
  if (admin.value) {
    await loadTask.run(async () => {
      const state = await get("/status");
      setupRequired.value = !!state.setup_required;
      optionsReady.value = !setupRequired.value;
    });
    return;
  }
  await loadTask.run(async () => {
    const data = await pget("/login/options");
    canEmail.value =
      Array.isArray(data.methods) && data.methods.includes("email_code");
    method.value = canEmail.value ? "email_code" : "password";
    optionsReady.value = true;
  });
}
onMounted(() => {
  void options();
});
onBeforeUnmount(() => {
  if (timer) clearInterval(timer);
});
async function send() {
  await sendTask.run(async () => {
    if (
      (!values.license_key && portalMode.value === "license") ||
      !values.email
    )
      throw new Error("请先填写完整授权码和关联邮箱");
    await ppost(
      portalMode.value === "user" ? "/user/login/code" : "/login/code",
      {
        ...(portalMode.value === "license"
          ? { license_key: values.license_key }
          : {}),
        email: values.email,
      },
    );
    cooldown.value = 60;
    if (timer) clearInterval(timer);
    timer = setInterval(() => {
      cooldown.value = Math.max(0, cooldown.value - 1);
      if (!cooldown.value && timer) clearInterval(timer);
    }, 1000);
  }, "如邮箱可用于登录，将收到验证码，请检查邮箱");
}
async function login() {
  try {
    if (!(await form.value?.validate())) return;
  } catch {
    return;
  }
  await task.run(async () => {
    if (admin.value)
      await auth.login({
        username: values.username,
        password: values.password,
        ...(values.totp_code ? { totp_code: values.totp_code } : {}),
      });
    else if (portalMode.value === "user")
      await auth.portalUserLogin({
        email: values.email,
        ...(method.value === "email_code"
          ? { code: values.code }
          : { password: values.password }),
      });
    else
      await auth.portalLogin({
        license_key: values.license_key,
        ...(method.value === "email_code"
          ? { code: values.code }
          : { password: values.password }),
      });
    values.password = "";
    values.code = "";
    values.totp_code = "";
    const prefix = admin.value ? adminPage("/") : "/portal/";
    const next = String(route.query.next ?? "");
    await router.replace(
      next.startsWith(prefix) &&
        !next.startsWith("//") &&
        !next.includes("/login")
        ? next
        : admin.value
          ? adminPage("/overview")
          : portalMode.value === "user"
            ? "/portal/home"
            : "/portal/license",
    );
  });
}
</script>
<template>
  <main class="login-page">
    <el-alert
      v-if="setupRequired"
      title="系统尚未初始化，请从服务日志中获取一次性初始化链接，再设置管理员账号。"
      type="info"
      :closable="false"
    />
    <section class="login-context">
      <router-link class="brand" to="/">Auth Go</router-link>
    </section>
    <section class="login-panel">
      <div class="login-card">
        <h1>{{ admin ? "登录管理端" : "登录用户中心" }}</h1>
        <p class="muted">
          {{
            admin ? "使用管理员账号继续" : "用户由管理员创建；不开放自助注册。"
          }}
        </p>
        <request-notice
          :error="loadTask.error.value"
          :busy="loadTask.busy.value"
          @retry="options"
        />
        <el-alert
          v-if="task.error.value"
          :title="task.error.value"
          type="error"
          show-icon
          :closable="false"
        />

        <el-form
          ref="form"
          :model="values"
          label-position="top"
          @submit.prevent="login"
        >
          <request-notice :error="sendTask.error.value" />
          <el-form-item
            v-if="admin"
            label="用户名"
            prop="username"
            :rules="[{ required: true, message: '请输入用户名' }]"
          >
            <el-input
              v-model="values.username"
              autocomplete="username"
              autofocus
            />
          </el-form-item>
          <template v-else>
            <el-radio-group v-model="portalMode" class="login-methods">
              <el-radio-button value="user">
                用户登录
              </el-radio-button><el-radio-button value="license">
                授权码登录
              </el-radio-button>
            </el-radio-group>
            <el-form-item
              v-if="portalMode === 'user'"
              label="用户邮箱"
              prop="email"
              :rules="[
                { required: true, type: 'email', message: '请输入用户邮箱' },
              ]"
            >
              <el-input
                v-model="values.email"
                type="email"
                autocomplete="email"
              />
            </el-form-item>
            <el-form-item
              v-if="portalMode === 'license'"
              label="授权码"
              prop="license_key"
              :rules="[{ required: true, message: '请输入完整授权码' }]"
            >
              <el-input
                v-model="values.license_key"
                placeholder="AUTH-XXXXX-XXXXX-XXXXX-XXXXX"
                autocomplete="off"
              />
            </el-form-item><el-radio-group
              v-if="canEmail"
              v-model="method"
              class="login-methods"
            >
              <el-radio-button value="email_code">
                邮箱验证码
              </el-radio-button><el-radio-button value="password">
                {{ portalMode === "user" ? "用户中心密码" : "查询密码" }}
              </el-radio-button>
            </el-radio-group><el-alert
              v-else-if="optionsReady"
              :title="
                portalMode === 'user'
                  ? '当前仅支持用户中心密码登录，由管理员设置。'
                  : '当前仅支持查询密码登录，密码由软件提供方设置。'
              "
              type="info"
              :closable="false"
            />
          </template>
          <template v-if="!admin && method === 'email_code'">
            <el-form-item
              v-if="portalMode === 'license'"
              label="用户关联邮箱"
              prop="email"
              :rules="[
                { required: true, type: 'email', message: '请输入有效邮箱' },
              ]"
            >
              <el-input
                v-model="values.email"
                type="email"
                autocomplete="email"
              />
            </el-form-item><el-form-item
              label="邮箱验证码"
              prop="code"
              :rules="[
                {
                  required: true,
                  pattern: /^\d{6}$/,
                  message: '请输入六位数字验证码',
                },
              ]"
            >
              <div class="code-input">
                <el-input
                  v-model="values.code"
                  maxlength="6"
                  inputmode="numeric"
                  autocomplete="one-time-code"
                /><el-button
                  :loading="sendTask.busy.value"
                  :disabled="cooldown > 0"
                  @click="send"
                >
                  {{ cooldown ? `${cooldown} 秒后重发` : "发送验证码" }}
                </el-button>
              </div>
            </el-form-item>
          </template>
          <el-form-item
            v-else
            :label="
              admin
                ? '登录密码'
                : portalMode === 'user'
                  ? '用户中心密码'
                  : '授权查询密码'
            "
            prop="password"
            :rules="[{ required: true, message: '请输入密码' }]"
          >
            <el-input
              v-model="values.password"
              type="password"
              show-password
              autocomplete="current-password"
            />
          </el-form-item>
          <el-form-item
            v-if="admin"
            label="两步验证码（已开启时填写）"
            prop="totp_code"
            :rules="[{ pattern: /^\d{6}$/, message: '请输入六位数字验证码' }]"
          >
            <el-input
              v-model="values.totp_code"
              maxlength="6"
              inputmode="numeric"
              autocomplete="one-time-code"
            />
          </el-form-item>
          <el-button
            class="login-submit"
            type="primary"
            native-type="submit"
            :loading="task.busy.value"
            :disabled="!optionsReady"
          >
            {{ admin ? "登录控制台" : "进入用户中心" }}
          </el-button>
        </el-form><router-link
          v-if="admin || adminPath()"
          class="login-switch"
          :to="admin ? '/portal/login' : adminPage('/login')"
        >{{
          admin ? "我是软件用户，前往用户中心" : "管理员登录"
        }}</router-link>
      </div>
    </section>
  </main>
</template>
