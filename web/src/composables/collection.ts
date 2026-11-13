import {
  onBeforeUnmount,
  ref,
  toValue,
  watch,
  type MaybeRefOrGetter,
} from "vue";
import { api, type Scope } from "../lib/http";
import type { Page, Row } from "../lib/json";
import axios from "axios";
export function useCollection(
  path: MaybeRefOrGetter<string>,
  fixed: MaybeRefOrGetter<Row> = {},
  scope: Scope = "admin",
  initialSize = 20,
) {
  const items = ref<Row[]>([]),
    total = ref(0),
    page = ref(1),
    size = ref(initialSize),
    query = ref<Row>({}),
    loading = ref(false),
    error = ref(""),
    hasLoaded = ref(false);
  let request: AbortController | undefined;
  async function load(reset = false) {
    if (reset) page.value = 1;
    request?.abort();
    const current = new AbortController();
    request = current;
    loading.value = true;
    error.value = "";
    try {
      const data = await api<Page>(scope, toValue(path), {
        params: {
          ...query.value,
          ...toValue(fixed),
          page: page.value,
          page_size: size.value,
        },
        signal: current.signal,
      });
      if (!current.signal.aborted) {
        items.value = data.items;
        total.value = Number(data.total);
        hasLoaded.value = true;
      }
    } catch (e) {
      if (!current.signal.aborted && request === current && !axios.isCancel(e)) {
        const message = e instanceof Error ? e.message : "读取失败";
        error.value = hasLoaded.value
          ? `刷新失败，显示上次成功读取的数据：${message}`
          : message;
      }
    } finally {
      if (request === current) loading.value = false;
    }
  }
  watch(
    () => [toValue(path), toValue(fixed)],
    () => {
      items.value = [];
      total.value = 0;
      hasLoaded.value = false;
      query.value = {};
      void load(true);
    },
    { immediate: true, deep: true },
  );
  onBeforeUnmount(() => request?.abort());
  return { items, total, page, size, query, loading, error, hasLoaded, load };
}
