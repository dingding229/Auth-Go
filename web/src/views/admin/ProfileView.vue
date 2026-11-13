<script setup lang="ts">
import { adminPage } from "../../lib/runtime";
import SectionPanel from "../../components/SectionPanel.vue";
import { reactive } from "vue";
import { useRouter } from "vue-router";
import { useAuth } from "../../stores/auth";
import { post } from "../../lib/http";
import { useTask } from "../../composables/tasks";
import PageHeading from "../../components/PageHeading.vue";

const auth = useAuth(),
  router = useRouter(),
  task = useTask();
const password = reactive({ old: "", next: "", repeat: "" });
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
</script>
<template>
  <page-heading
    title="个人安全"
    description="密码修改后，现有登录会话将失效，请重新登录。"
  />
  <el-alert
    v-if="task.error.value"
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
        </el-form-item>
        <el-form-item label="新密码（8–72字节）">
          <el-input
            v-model="password.next"
            type="password"
            show-password
            autocomplete="new-password"
          />
        </el-form-item>
        <el-form-item label="再次输入新密码">
          <el-input
            v-model="password.repeat"
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
          修改密码
        </el-button>
      </el-form>
    </section-panel>
  </div>
</template>
