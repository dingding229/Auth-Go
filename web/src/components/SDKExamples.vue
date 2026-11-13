<script setup lang="ts">
import { adminPage } from "../lib/runtime";
import { computed, ref } from "vue";
import {
  sdkLanguages,
  sdkExamples,
  announcementExamples,
  type SDKLanguage,
} from "../lib/sdk-examples";
import JsonBlock from "./JsonBlock.vue";
const language = ref<SDKLanguage>("Go");
const example = computed(() =>
  language.value === "其他语言" ? undefined : sdkExamples[language.value],
);
</script>
<template>
  <div class="sdk-examples">
    <section class="integration-section">
      <h3>1. 选择语言</h3>
      <p>选择业务程序使用的语言，示例会同步切换。</p>
      <el-form label-position="top">
        <el-form-item label="接入语言">
          <el-segmented
            v-model="language"
            :options="sdkLanguages"
            aria-label="SDK语言"
          />
        </el-form-item>
      </el-form>
    </section>
    <template v-if="example && language !== '其他语言'">
      <section class="integration-section">
        <h3>2. 安装 SDK</h3>
        <p>SDK 使用本仓库源码安装，不从公共包仓库下载。</p>
        <json-block :value="example.install" title="安装 SDK" />
      </section>
      <section class="integration-section">
        <h3>3. 接入代码</h3>
        <p>将接入配置编译进程序，客户只填写授权码。</p>
        <json-block :value="example.code" :title="`${language} 授权接入`" />
        <h4>获取并显示公告</h4>
        <p>
          以下 client 为使用编译配置创建的客户端；SDK
          验证服务端签名，失败时不要展示未经验证的内容。网页请用文本节点展示，不要插入
          HTML。
        </p>
        <json-block
          :value="announcementExamples[language]"
          :title="`${language} 公告读取`"
        />
      </section>
      <section class="integration-section">
        <h3>4. 构建与发布</h3>
        <p>
          构建时固化接入配置与版本。Docker 程序可在 Docker
          接入向导生成构建文件和发布工作流。
        </p>
        <router-link :to="adminPage('/docs?tab=docker')">
          查看构建与发布说明
        </router-link>
      </section>
    </template>
    <p v-else>
      其他语言请按统一协议实现客户端。
      <router-link :to="adminPage('/docs?tab=protocol')">
        阅读接入协议
      </router-link>
    </p>
  </div>
</template>
