<script setup lang="ts">
import { adminPage } from "../lib/runtime";
import { computed, ref, watch } from "vue";
import { get, patch } from "../lib/http";
import { useTask, useLoadTask } from "../composables/tasks";
import { sdkExamples } from "../lib/sdk-examples";
import {
  dockerLanguages,
  phpModes,
  dockerTemplate,
  customerCompose,
  githubActions,
  guardCode,
  validDockerImage,
  protectedTemplate,
  sealedGuardCode,
  type EncryptionBuild,
  type DockerLanguage,
  type PHPMode,
} from "../lib/docker-wizard";
import RequestNotice from "./RequestNotice.vue";
import JsonBlock from "./JsonBlock.vue";
import DockerHubSync from "./DockerHubSync.vue";
import PayloadKeys from "./PayloadKeys.vue";
import { type Row } from "../lib/json";
const props = defineProps<{ id: string; config: string }>();
const encrypted = ref(false),
  cryptoTask = useTask(),
  tools = ref<Row>(),
  currentKey = ref<Row>(),
  appKey = ref("");
const encryption = computed<EncryptionBuild | undefined>(() =>
  encrypted.value &&
  tools.value?.tools_image &&
  tools.value?.tools_version &&
  currentKey.value &&
  appKey.value
    ? {
        toolsImage: String(tools.value.tools_image),
        toolsVersion: String(tools.value.tools_version),
        keyId: String(currentKey.value.key_id),
        publicKey: String(currentKey.value.public_key),
        appKey: appKey.value,
      }
    : undefined,
);
async function loadTools() {
  await cryptoTask.run(async () => {
    tools.value = await get("/system/settings");
  });
}
watch(encrypted, (value) => {
  if (value) void loadTools();
});
const task = useTask(),
  loadTask = useLoadTask(),
  image = ref(""),
  savedImage = ref(""),
  language = ref<DockerLanguage>("Go"),
  mode = ref<PHPMode>("cli"),
  step = ref("image");
let generation = 0;
async function load() {
  const serial = ++generation,
    id = props.id;
  await loadTask.run(async () => {
    const app = await get(`/applications/${id}`);
    if (serial === generation) {
      image.value = savedImage.value = String(app.docker_image || "");
      appKey.value = String(app.app_key || "");
    }
  });
}
watch(
  () => props.id,
  () => {
    step.value = "image";
    encrypted.value = false;
    tools.value = undefined;
    currentKey.value = undefined;
    image.value = "";
    savedImage.value = "";
    void load();
  },
  { immediate: true },
);
const template = computed(() =>
  encrypted.value && encryption.value
    ? protectedTemplate(language.value, mode.value, encryption.value)
    : dockerTemplate(language.value, mode.value),
);
const encryptionReady = computed(
  () => !encrypted.value || Boolean(encryption.value),
);
const ready = computed(() => validDockerImage(savedImage.value));
const actions = computed(() =>
  ready.value
    ? githubActions(
        language.value,
        mode.value,
        savedImage.value,
        encryption.value,
      )
    : "",
);
const compose = computed(() =>
  ready.value
    ? customerCompose(
        language.value,
        mode.value,
        savedImage.value,
        encryption.value,
      )
    : "",
);
const files = computed(() =>
  Object.entries(template.value.files).filter(
    ([name]) => !["Dockerfile", "docker-compose.yml"].includes(name),
  ),
);
async function save() {
  await task.run(async () => {
    const normalized = image.value.trim();
    if (normalized && !validDockerImage(normalized))
      throw new Error(
        "请填写Docker Hub镜像名，例如your-org/your-app，不含标签或凭据",
      );
    const id = props.id;
    await patch(`/applications/${id}`, { docker_image: normalized });
    if (id === props.id) {
      image.value = savedImage.value = normalized;
      step.value = normalized ? "code" : "image";
    }
  }, "镜像名已保存");
}
</script>
<template>
  <div class="docker-wizard">
    <h2>Docker接入向导</h2>
    <p>
      先保存镜像名，再按步骤复制。保留本仓库sdk与examples/docker的相对目录；配置只在构建时固化。
    </p>
    <request-notice
      :error="loadTask.error.value"
      :busy="loadTask.busy.value"
      @retry="load"
    />
    <request-notice :error="task.error.value" />
    <el-form
      v-if="step === 'code' || step === 'dockerfile'"
      label-position="top"
    >
      <el-form-item label="接入语言">
        <el-segmented
          v-model="language"
          :options="dockerLanguages"
          aria-label="Docker SDK语言"
        />
      </el-form-item>
      <el-form-item
        v-if="language === 'PHP'"
        label="PHP运行方式（请选择与业务一致的模式）"
      >
        <el-radio-group v-model="mode" aria-label="PHP运行方式">
          <el-radio
            v-for="option in phpModes"
            :key="option.value"
            :value="option.value"
          >
            {{ option.label }}
          </el-radio>
        </el-radio-group>
      </el-form-item>
      <p v-if="language === 'PHP' && mode !== 'cli'" class="muted">
        请求式不退出77，而由业务返回503和原因；空闲/停止依赖租约回收，不检测多副本共卷冲突。需要严格实例计数请用常驻CLI。
      </p>
    </el-form>
    <el-tabs v-model="step" aria-label="Docker接入步骤">
      <el-tab-pane label="1. 镜像名" name="image">
        <el-form label-position="top" @submit.prevent="save">
          <el-form-item label="Docker Hub镜像名">
            <el-input
              v-model="image"
              placeholder="your-org/your-app"
              :maxlength="255"
            />
          </el-form-item>
          <p class="muted">
            使用小写的命名空间/镜像名，不含标签。留空停止同步，已有版本保留。客户运行时只填授权码。
          </p>
          <el-button
            type="primary"
            native-type="submit"
            :loading="task.busy.value"
          >
            {{ image.trim() ? "保存镜像名并继续" : "保存镜像设置" }}
          </el-button>
        </el-form>
        <el-form label-position="top">
          <el-form-item label="代码加密">
            <el-switch
              v-model="encrypted"
              active-text="启用"
              inactive-text="不启用"
              aria-label="代码加密"
            />
          </el-form-item>
        </el-form>
        <template v-if="encrypted">
          <request-notice :error="cryptoTask.error.value" @retry="loadTools" />
          <p v-if="cryptoTask.busy.value" role="status">
            正在读取工具镜像设置…
          </p>
          <p
            v-else-if="tools && (!tools.tools_image || !tools.tools_version)"
            class="field-hint"
          >
            尚未配置工具镜像。请到系统设置填写工具镜像名与版本后重试。<el-button
              @click="loadTools"
            >
              重新读取设置
            </el-button>
          </p>
          <p class="field-hint">
            信任根在构建时固化。有效授权可从内存导出内容，不能承诺绝对防复制；数据文件仍公开。
          </p>
          <details class="technical-options" open>
            <summary>打包公钥与轮换</summary>
            <payload-keys
              :id="id"
              :app-key="appKey"
              @change="currentKey = $event"
            />
          </details>
          <p v-if="!encryptionReady" role="status">
            请先配置工具镜像并生成当前打包公钥，才能生成加密构建文件。
          </p>
        </template>
        <DockerHubSync :id="id" :image="savedImage" />
      </el-tab-pane>
      <el-tab-pane label="2. 接入代码" name="code">
        <p>
          从本仓库安装SDK，核心接入片段如下。完整程序的SIGTERM、业务循环、最终失败退出与关闭释放处理见下一步的参考文件。
        </p>
        <json-block
          :value="sdkExamples[language].install"
          title="获取SDK（不从公共包仓库安装）"
        />
        <json-block
          :value="
            encrypted
              ? sealedGuardCode(language, mode)
              : guardCode(language, mode)
          "
          title="嵌入业务入口的核心代码"
        />
      </el-tab-pane>
      <el-tab-pane label="3. Dockerfile" name="dockerfile">
        <p>
          将文件保存到{{
            template.directory
          }}/Dockerfile，构建上下文是仓库根。接入配置由构建参数写入程序，客户不能替换信任根。
        </p>
        <p v-if="language === 'Rust'" class="muted">
          Rust版本来自Cargo.toml的package.version，发版前应与标签去掉v后的版本一致。
        </p>
        <json-block
          v-if="encryptionReady"
          :value="template.files.Dockerfile"
          title="Dockerfile"
        />
        <details v-if="encryptionReady" class="technical-options">
          <summary>构建所需参考文件（与真实容器示例一致）</summary>
          <p>
            同时复制SDK目录。以下文件保存到{{
              template.directory
            }}内的相同路径；替换业务处理器时保留授权生命周期。
          </p>
          <json-block
            v-for="[name, content] in files"
            :key="name"
            :value="content"
            :title="name"
          />
        </details>
      </el-tab-pane>
      <el-tab-pane label="4. 自动发版" name="actions">
        <p>
          在Actions
          Variables中设置AUTHGO_CONFIG，值为上方显示的接入配置。Secrets仅需DOCKERHUB_USERNAME、DOCKERHUB_TOKEN。配置是公开的构建输入，不是运行时环境变量。
        </p>
        <p v-if="!config" class="muted">
          请先点击上方“显示接入配置”，取得需要保存到Actions变量的值。
        </p>
        <json-block
          v-if="ready && encryptionReady"
          :value="actions"
          title=".github/workflows/docker.yml"
        />
        <p v-else>
          请先在第1步保存Docker
          Hub镜像名；启用加密时还须配置工具镜像和打包公钥。
        </p>
      </el-tab-pane>
      <el-tab-pane label="5. 客户部署" name="compose">
        <p>
          把此文件交给客户；正式授权只需设置AUTHGO_LICENSE。软件开放试用时可留空，试用需要稳定联网、不提供断网宽限；同一网络共用一个试用。建议保留restart:
          unless-stopped。默认latest可改成已发布的固定标签，每个副本必须有自己的缓存卷。
        </p>
        <json-block
          v-if="ready"
          :value="compose"
          title="docker-compose.yml（客户运行）"
        />
        <p v-else>
          请先在第1步保存Docker
          Hub镜像名；启用加密时还须配置工具镜像和打包公钥。
        </p>
        <router-link :to="adminPage('/docs?tab=docker')">阅读Docker部署与故障说明</router-link>
      </el-tab-pane>
    </el-tabs>
    <div class="action-toolbar">
      <el-button
        v-if="step !== 'image'"
        @click="
          step = ['image', 'code', 'dockerfile', 'actions', 'compose'][
            ['image', 'code', 'dockerfile', 'actions', 'compose'].indexOf(
              step,
            ) - 1
          ]!
        "
      >
        上一步
      </el-button>
      <el-button
        v-if="step !== 'compose' && step !== 'image'"
        type="primary"
        @click="
          step = ['image', 'code', 'dockerfile', 'actions', 'compose'][
            ['image', 'code', 'dockerfile', 'actions', 'compose'].indexOf(
              step,
            ) + 1
          ]!
        "
      >
        下一步
      </el-button>
    </div>
  </div>
</template>
