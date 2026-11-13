<script setup lang="ts">
import { adminPage } from "../lib/runtime";
import { computed, ref } from "vue";
import {
  sdkLanguages,
  sdkExamples,
  type SDKLanguage,
} from "../lib/sdk-examples";
import JsonBlock from "./JsonBlock.vue";
const language = ref<SDKLanguage>("Go");
const example = computed(() =>
  language.value === "其他语言" ? undefined : sdkExamples[language.value],
);
</script>
<template>
  <el-form label-position="top">
    <el-form-item label="接入语言">
      <el-segmented
        v-model="language"
        :options="sdkLanguages"
        aria-label="SDK语言"
      />
    </el-form-item>
  </el-form>
  <template v-if="example">
    <p class="muted">
      SDK尚未发布到公共包仓库，请使用本仓库源码安装：
    </p>
    <json-block :value="example.install" title="从本仓库安装" /><json-block
      :value="example.code"
      :title="`最简 ${language} SDK接入示例`"
    />
  </template>
  <p v-else>
    其他语言可按统一协议实现客户端。<router-link :to="adminPage('/docs?tab=protocol')">阅读接入协议与实现清单</router-link>
  </p>
</template>
