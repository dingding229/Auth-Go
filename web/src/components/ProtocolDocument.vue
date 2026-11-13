<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import MarkdownIt from "markdown-it";
import { integrationProtocol, integrationDocker } from "../lib/http";
import RequestNotice from "./RequestNotice.vue";
import { useTask, useLoadTask } from "../composables/tasks";
const props = defineProps<{
  document?: "protocol" | "docker";
  content?: string;
}>();
const text = ref(""),
  task = useLoadTask(),
  copyTask = useTask();
const md = new MarkdownIt({ html: false, linkify: false });
md.validateLink = (url: string) =>
  /^https?:\/\//i.test(url) || /^#[^\s]*$/.test(url);
const sections = computed(() => {
  let fenced = false;
  return text.value.split("\n").flatMap((line, i) => {
    if (/^\s*```/.test(line)) {
      fenced = !fenced;
      return [];
    }
    const m = !fenced && /^(#{1,3})\s+(.+)$/.exec(line);
    return m
      ? [{ id: `protocol-section-${i}`, title: m[2]!, level: m[1]!.length }]
      : [];
  });
});
const html = computed(() => {
  let index = 0;
  return md
    .render(text.value)
    .replace(/<h([1-6])>/g, (_match, level) => {
      const id =
        Number(level) <= 3 ? ` id="${sections.value[index++]?.id || ""}"` : "";
      return `<h${Math.min(Number(level) + 1, 6)}${id}>`;
    })
    .replace(
      /<\/h([1-6])>/g,
      (_match, level) => `</h${Math.min(Number(level) + 1, 6)}>`,
    )
    .replace(
      /<pre><code([^>]*)>([\s\S]*?)<\/code><\/pre>/g,
      '<div class="protocol-codeblock"><button type="button" data-copy-code>复制代码</button><pre tabindex="0"><code$1>$2</code></pre></div>',
    );
});
async function load() {
  if (props.content !== undefined) {
    text.value = props.content;
    return;
  }
  await task.run(async () => {
    text.value = await (props.document === "docker"
      ? integrationDocker()
      : integrationProtocol());
  });
}
async function copyBlock(event: MouseEvent) {
  const button = (event.target as HTMLElement).closest("[data-copy-code]");
  if (!button) return;
  const code = button.closest(".protocol-codeblock")?.querySelector("code");
  if (!code) return;
  await copyTask.run(
    () => navigator.clipboard.writeText(code.textContent || ""),
    "代码已复制",
  );
}
onMounted(load);
watch(
  () => props.content,
  () => {
    void load();
  },
);
</script>
<template>
  <request-notice
    :error="task.error.value"
    :busy="task.busy.value"
    @retry="load"
  />
  <request-notice :error="copyTask.error.value" />
  <el-skeleton v-if="task.busy.value && !text" :rows="8" animated />
  <template v-if="text">
    <nav class="protocol-toc" aria-label="协议章节目录">
      <a
        v-for="section in sections"
        :key="section.id"
        :href="`#${section.id}`"
      >{{ section.title }}</a>
    </nav>
    <p class="muted">
      点击“复制代码”可复制代码块，也可用键盘选中后复制。文档以服务器返回的版本为准。
    </p>
    <!-- html:false and strict link validation above are the sole HTML renderer. -->
    <!-- eslint-disable-next-line vue/no-v-html -->
    <div class="protocol-markdown" @click="copyBlock" v-html="html" />
  </template>
</template>
