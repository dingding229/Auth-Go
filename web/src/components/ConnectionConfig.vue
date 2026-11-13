<script setup lang="ts">
import { adminPage } from "../lib/runtime";
import { onMounted, ref, watch } from "vue";
import { ElMessage } from "element-plus";
import { get, post, integrationOrigin } from "../lib/http";
import { useTask } from "../composables/tasks";
import DockerWizard from "./DockerWizard.vue";
import { issueLicenseLocation } from "../lib/navigation";
import CopyField from "./CopyField.vue";
const props = defineProps<{ id: string; autoReveal?: boolean }>();
const { busy, error, run } = useTask();
const url = ref(integrationOrigin()),
  config = ref("");
watch(url, () => {
  config.value = "";
});
watch(
  () => props.id,
  () => {
    config.value = "";
  },
);
async function reveal() {
  await run(async () => {
    const address = url.value,
      id = props.id;
    const result = await post(`/applications/${id}/connection`, {
      url: address,
    });
    if (url.value === address && props.id === id)
      config.value = String(result.config);
  });
}
async function copy() {
  await run(async () => {
    await navigator.clipboard.writeText(config.value);
    ElMessage.success("已复制接入配置");
  });
}
onMounted(async () => {
  await run(async () => {
    const s = await get("/system/settings");
    if (s.public_url) url.value = String(s.public_url);
  });
  if (props.autoReveal) await reveal();
});
</script>
<template>
  <el-alert
    title="配置可以公开，但必须编译进程序，不能从环境变量或文件读取。app_secret不是调用方身份凭据。不要写入日志；生产环境必须使用HTTPS。"
    type="warning"
    :closable="false"
  />
  <el-form
    class="connection-form"
    label-position="top"
    @submit.prevent="reveal"
  >
    <el-form-item label="程序可以访问的服务地址">
      <el-input v-model="url" placeholder="https://auth.example.com" />
    </el-form-item>
    <el-button type="primary" native-type="submit" :loading="busy">
      显示接入配置
    </el-button>
    <el-button v-if="config" @click="copy">
      一键复制配置
    </el-button>
  </el-form>
  <el-alert
    v-if="error"
    :title="error"
    type="error"
    :closable="false"
  />
  <copy-field
    v-if="config"
    :value="config"
    label="接入配置串"
    sensitive
  />
  <DockerWizard :id="id" :config="config" />
  <p>
    <router-link :to="adminPage('/docs?tab=protocol')">查看接入协议</router-link>
  </p>
  <router-link :to="issueLicenseLocation(id)"><el-button type="primary">立即发放授权</el-button></router-link>
</template>
