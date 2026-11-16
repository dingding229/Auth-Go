<script setup lang="ts">
import { adminPage } from "../lib/runtime";
import { computed, ref, watch } from "vue";
import { patch } from "../lib/http";
import { useTask } from "../composables/tasks";
import { sdkExamples, announcementExamples } from "../lib/sdk-examples";
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
import AutoPublish from "./AutoPublish.vue";
import PayloadKeys from "./PayloadKeys.vue";
import { type Row } from "../lib/json";
const props = defineProps<{
  id: string;
  config: string;
  application: Row;
  packImageTag?: string;
}>();
const savedEncryption = ref<boolean>();
const encrypted = ref(false),
  currentKey = ref<Row>(),
  appKey = ref("");
const encryption = computed<EncryptionBuild | undefined>(() =>
  encrypted.value && currentKey.value && appKey.value
    ? {
        packImageTag: props.packImageTag,
        keyId: String(currentKey.value.key_id),
        publicKey: String(currentKey.value.public_key),
        appKey: appKey.value,
      }
    : undefined,
);
const task = useTask(),
  image = ref(""),
  savedImage = ref(""),
  language = ref<DockerLanguage>("Go"),
  mode = ref<PHPMode>("cli"),
  step = ref("image");
const selectionTouched = new Set<string>();
function restorePublishing(value: {
  language: string;
  mode: string;
  encrypted: boolean;
}) {
  if (!selectionTouched.has("language"))
    language.value = value.language as DockerLanguage;
  if (!selectionTouched.has("mode")) mode.value = value.mode as PHPMode;
  if (!selectionTouched.has("encrypted")) encrypted.value = value.encrypted;
}
const steps = ["image", "code", "dockerfile", "actions", "compose"];
function prev() {
  step.value = steps[Math.max(0, steps.indexOf(step.value) - 1)]!;
}
function next() {
  step.value =
    steps[Math.min(steps.length - 1, steps.indexOf(step.value) + 1)]!;
}
watch(
  () => props.id,
  () => {
    step.value = "image";
    selectionTouched.clear();
    encrypted.value = false;
    savedEncryption.value = undefined;
    currentKey.value = undefined;
    image.value = savedImage.value = String(
      props.application.docker_image || "",
    );
    appKey.value = String(props.application.app_key || "");
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
    <request-notice :error="task.error.value" />
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
              @change="selectionTouched.add('encrypted')"
            />
            <span
              v-if="
                savedEncryption !== undefined && encrypted !== savedEncryption
              "
              class="field-hint"
              title="仅指自动发布；手动导出立即使用当前开关"
            >
              自动发布：保存仓库配置后才生效
            </span>
          </el-form-item>
        </el-form>
        <template v-if="encrypted">
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
            请先生成当前打包公钥，随后可生成加密构建文件。
          </p>
        </template>
        <DockerHubSync :id="id" :image="savedImage" />
      </el-tab-pane>
      <el-tab-pane label="2. 接入代码" name="code">
        <section class="integration-section">
          <h3>1. 选择语言</h3>
          <p>选择业务语言与运行模式，下面的安装命令和代码会同步切换。</p>
          <el-form label-position="top">
            <el-form-item label="接入语言">
              <el-segmented
                v-model="language"
                :options="dockerLanguages"
                aria-label="Docker SDK语言"
                @change="selectionTouched.add('language')"
              />
            </el-form-item>
            <el-form-item
              v-if="language === 'PHP'"
              label="PHP运行方式（请选择与业务一致的模式）"
            >
              <el-radio-group
                v-model="mode"
                aria-label="PHP运行方式"
                @change="selectionTouched.add('mode')"
              >
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
        </section>
        <section class="integration-section">
          <h3>2. 安装 SDK</h3>
          <p>从本仓库获取 SDK，并保留生成文件要求的相对目录。</p>
          <json-block :value="sdkExamples[language].install" title="安装 SDK" />
        </section>
        <section class="integration-section">
          <h3>3. 接入代码</h3>
          <p>
            守卫负责持续校验，业务程序负责信号、退出与关闭释放；完整入口见下一步的参考文件。
          </p>
          <json-block
            :value="
              encrypted
                ? sealedGuardCode(language, mode)
                : guardCode(language, mode)
            "
            title="授权生命周期"
          />
          <h4>获取并显示公告</h4>
          <p>
            使用已创建的 SDK client
            读取签名公告；读取失败不改变授权状态，显示时使用纯文本。
          </p>
          <json-block
            :value="announcementExamples[language]"
            title="公告读取与显示"
          />
        </section>
        <section class="integration-section">
          <h3>4. 构建与发布</h3>
          <p>
            下一步复制 Dockerfile 和构建所需参考文件，再到“自动发布”配置 GitHub
            仓库并发版。接入配置只在构建时写入。
          </p>
        </section>
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
      <el-tab-pane label="4. 自动发布" name="actions">
        <AutoPublish
          :id="id"
          :language="language"
          :mode="mode"
          :encrypted="encrypted"
          :ready="ready && encryptionReady"
          @selection="restorePublishing"
          @saved-encryption="savedEncryption = $event"
        />
        <p>
          也可手动复制同一份工作流到
          .github/workflows/authgo-publish.yml，在仓库设置
          Secrets：DOCKERHUB_USERNAME、DOCKERHUB_TOKEN，以及
          Variable：AUTHGO_CONFIG。 配置只在构建时固化。GitHub
          的手动运行要求该工作流先存在于默认分支。
        </p>
        <p v-if="!config" class="muted">
          手动配置时请先在“接入配置”区域点击“显示接入配置”。
        </p>
        <json-block
          v-if="ready && encryptionReady"
          :value="actions"
          title=".github/workflows/authgo-publish.yml"
        />
        <p v-else>
          请先在第1步保存Docker Hub镜像名；启用加密时还须生成当前打包公钥。
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
          请先在第1步保存Docker Hub镜像名；启用加密时还须生成当前打包公钥。
        </p>
        <router-link :to="adminPage('/docs?tab=docker')">
          阅读Docker部署与故障说明
        </router-link>
      </el-tab-pane>
    </el-tabs>
    <div class="action-toolbar">
      <el-button v-if="step !== 'image'" @click="prev">
        上一步
      </el-button>
      <el-button
        v-if="step !== 'compose' && step !== 'image'"
        type="primary"
        @click="next"
      >
        下一步
      </el-button>
    </div>
  </div>
</template>
