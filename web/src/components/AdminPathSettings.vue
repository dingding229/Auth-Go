<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { get, patch } from "../lib/http";
import { clearAdmin } from "../lib/session";
import { useTask, confirmAction, useLoadTask } from "../composables/tasks";
import SectionPanel from "./SectionPanel.vue";
import RequestNotice from "./RequestNotice.vue";
const loadTask = useLoadTask(), task = useTask(), value = ref(""), current = ref(""), reserved = ref<string[]>([]), loaded = ref(false);
const busy = computed(() => loadTask.busy.value || task.busy.value);
const validation = computed(() => {
  if (!/^\/[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/.test(value.value))
    return "以 / 开头，随后为 1 至 48 个小写字母、数字或连字符，首尾须为字母或数字";
  if (reserved.value.includes(value.value.slice(1))) return "此地址与现有功能冲突，请选择其他后台地址";
  return "";
});
const submitted = ref(false);
async function load() {
  await loadTask.run(async () => {
    const result = await get<{ path: string; reserved: string[] }>("/system/admin-path");
    if (typeof result.path !== "string" || !Array.isArray(result.reserved) || result.reserved.some((item) => typeof item !== "string"))
      throw new Error("后台地址响应格式不正确");
    // Loading failures and save failures never discard an in-progress edit.
    if (!loaded.value) value.value = result.path;
    current.value = result.path;
    reserved.value = result.reserved;
    loaded.value = true;
  });
}
async function save() {
  submitted.value = true;
  task.error.value = "";
  if (validation.value || value.value === current.value) return;
  const requested = value.value;
  await task.run(async () => {
    await confirmAction("修改后台地址会立即撤销全部管理员会话（包括其他登录窗口）。保存后需要在新地址重新登录，是否继续？", "修改后台地址", { action: "更换后台地址并重新登录" });
    const result = await patch<{ path: string; login_url: string }>("/system/admin-path", { path: requested });
    clearAdmin();
    if (!/^\/[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/.test(result.path) ||
        result.path.length > 49 || result.login_url !== `${result.path}/login`)
      throw new Error("后台地址已更新，请使用新地址重新登录");
    window.location.assign(result.login_url);
  });
}
onMounted(load);
</script>
<template>
  <section-panel title="后台地址">
    <p class="muted">
      管理页面和管理接口一起更换地址。保存后全部管理员都需要重新登录，请妥善保存新地址。
    </p>
    <request-notice :error="loadTask.error.value" :busy="loadTask.busy.value" @retry="load" />
    <el-skeleton v-if="loadTask.busy.value && !loaded" :rows="2" animated />
    <el-form v-if="loaded" label-position="top" @submit.prevent="save">
      <el-form-item label="后台地址" :error="submitted ? validation : ''">
        <el-input
          v-model="value"
          :disabled="busy"
          maxlength="49"
          autocomplete="off"
          aria-describedby="admin-path-hint"
        />
        <p id="admin-path-hint" class="muted">
          以 / 开头，随后为 1 至 48 个小写字母、数字或连字符，首尾须为字母或数字。保留名称：{{ reserved.join("、") }}。
        </p>
      </el-form-item>
      <request-notice :error="task.error.value" />
      <el-button
        type="primary"
        native-type="submit"
        :loading="busy"
        :disabled="value === current"
      >
        保存后台地址并重新登录
      </el-button>
    </el-form>
  </section-panel>
</template>
