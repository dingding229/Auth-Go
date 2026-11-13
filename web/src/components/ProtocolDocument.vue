<script setup lang="ts">
import { copy } from "../lib/clipboard";
import {
  computed,
  inject,
  nextTick,
  onBeforeUnmount,
  onMounted,
  ref,
  watch,
} from "vue";
import { routerKey, type Router } from "vue-router";
import { integrationDocument } from "../lib/http";
import { renderDocument, type DocumentName } from "../lib/markdown";
import RequestNotice from "./RequestNotice.vue";
const props = defineProps<{ document?: DocumentName; content?: string }>();
const router = inject<Router | undefined>(routerKey, undefined),
  text = ref(""),
  busy = ref(false),
  error = ref("");
const article = ref<HTMLElement>(),
  active = ref(""),
  menu = ref<HTMLDetailsElement>();
const rendered = computed(() => renderDocument(text.value));
let generation = 0,
  frame = 0,
  mounted = false;
async function load() {
  const current = ++generation;
  text.value = "";
  error.value = "";
  busy.value = true;
  try {
    const value =
      props.content ??
      (await integrationDocument(props.document || "protocol"));
    if (current === generation) text.value = value;
  } catch (e) {
    if (current === generation)
      error.value = e instanceof Error ? e.message : "文档读取失败";
  } finally {
    if (current === generation) busy.value = false;
  }
}
function updateActive() {
  const headings =
    article.value?.querySelectorAll<HTMLElement>("h3[id], h4[id]");
  let id = rendered.value.sections[0]?.id || "";
  headings?.forEach((heading) => {
    if (heading.getBoundingClientRect().top <= 112) id = heading.id;
  });
  active.value = id;
}
function onScroll() {
  if (!frame)
    frame = requestAnimationFrame(() => {
      frame = 0;
      updateActive();
    });
}
async function followHash() {
  await nextTick();
  if (!mounted) return;
  let id = "";
  try {
    id = decodeURIComponent(window.location.hash.slice(1));
  } catch {
    return;
  }
  const target = [
    ...(article.value?.querySelectorAll<HTMLElement>("[id]") || []),
  ].find((node) => node.id === id);
  target?.scrollIntoView?.({ block: "start" });
  updateActive();
}
function closeMenu() {
  if (menu.value) menu.value.open = false;
}
async function handleClick(event: MouseEvent) {
  const target = event.target;
  if (!(target instanceof Element)) return;
  const button = target.closest("[data-copy-code]");
  if (button) {
    const code = button.closest(".protocol-codeblock")?.querySelector("code");
    if (code)
      await copy(code.textContent || "", "代码已复制");
    return;
  }
  const anchor = target.closest<HTMLAnchorElement>("a[data-copy-anchor]");
  if (anchor) {
    event.preventDefault();
    const url = new URL(window.location.href);
    url.hash = anchor.dataset.copyAnchor || "";
    await copy(url.href, "章节链接已复制");
    return;
  }
  const link = target.closest<HTMLAnchorElement>('a[href^="?tab="]');
  if (
    link &&
    router &&
    !event.ctrlKey &&
    !event.metaKey &&
    !event.shiftKey &&
    !event.altKey
  ) {
    event.preventDefault();
    const url = new URL(link.getAttribute("href") || "", window.location.href);
    let hash: string;
    try {
      hash = decodeURIComponent(url.hash);
    } catch {
      return;
    }
    await router.push({
      query: {
        ...router.currentRoute.value.query,
        tab: url.searchParams.get("tab"),
      },
      hash,
    });
  }
}
watch(
  () => [props.document, props.content],
  () => {
    void load();
  },
  { immediate: true },
);
watch(text, () => {
  if (mounted) void followHash();
});
watch(
  () => router?.currentRoute.value.hash,
  () => {
    void followHash();
  },
);
onMounted(() => {
  mounted = true;
  window.addEventListener("scroll", onScroll, true);
  window.addEventListener("resize", onScroll);
  window.addEventListener("hashchange", followHash);
  void followHash();
});
onBeforeUnmount(() => {
  mounted = false;
  generation++;
  cancelAnimationFrame(frame);
  window.removeEventListener("scroll", onScroll, true);
  window.removeEventListener("resize", onScroll);
  window.removeEventListener("hashchange", followHash);
});
</script>
<template>
  <request-notice :error="error" :busy="busy" @retry="load" />
  <el-skeleton v-if="busy && !text" :rows="8" animated />
  <div v-if="text" class="document-layout">
    <details
      v-if="rendered.sections.length"
      ref="menu"
      class="document-mobile-toc"
    >
      <summary>目录</summary>
      <nav class="protocol-toc" aria-label="本页目录">
        <a
          v-for="section in rendered.sections"
          :key="section.id"
          :href="`#${section.id}`"
          :class="{
            'is-active': active === section.id,
            'is-child': section.level === 3,
          }"
          :aria-current="active === section.id ? 'location' : undefined"
          @click="closeMenu"
        >
          {{ section.title }}
        </a>
      </nav>
    </details>
    <!-- 内容由禁用原始 HTML 的 Markdown 渲染器转义，并校验链接。 -->
    <!-- eslint-disable vue/no-v-html -->
    <article
      ref="article"
      class="protocol-markdown document-body"
      @click="handleClick"
      v-html="rendered.html"
    />
    <!-- eslint-enable vue/no-v-html -->
    <aside v-if="rendered.sections.length" class="document-desktop-toc">
      <h2>本页目录</h2>
      <nav class="protocol-toc" aria-label="本页目录">
        <a
          v-for="section in rendered.sections"
          :key="section.id"
          :href="`#${section.id}`"
          :class="{
            'is-active': active === section.id,
            'is-child': section.level === 3,
          }"
          :aria-current="active === section.id ? 'location' : undefined"
        >
          {{ section.title }}
        </a>
      </nav>
    </aside>
  </div>
</template>
