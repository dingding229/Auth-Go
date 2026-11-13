import { computed, onBeforeUnmount, ref, watch, type Ref } from "vue";
import { get } from "../lib/http";
import { idText, type Row } from "../lib/json";

// Shared by the three admin detail pages: a loaded entity and a route ID must
// never be mixed. Reads can overlap; mutations/confirmations retain their scope.
export function useAdminDetail(
  base: string,
  id: Ref<string>,
  value: Ref<Row | undefined>,
  reset: () => void,
) {
  const loading = ref(false),
    error = ref("");
  let serial = 0;
  let request: AbortController | undefined;
  const ready = computed(
    () =>
      !loading.value && !!value.value && idText(value.value.id) === id.value,
  );
  function capture() {
    const selected = id.value,
      revision = serial;
    if (!ready.value) throw new Error("当前记录尚未就绪，请等待加载完成");
    const current = () =>
      revision === serial && selected === id.value && ready.value;
    const check = () => {
      if (!current()) throw new Error("页面已切换，请在当前记录上重新操作");
    };
    return {
      id: selected,
      check,
      current,
      commit(next: Row) {
        if (!current()) return;
        if (idText(next.id) !== selected)
          throw new Error("详情响应编号不一致，请重新加载");
        value.value = next;
      },
    };
  }
  async function load() {
    request?.abort();
    const controller = new AbortController(),
      n = ++serial,
      selected = id.value;
    request = controller;
    loading.value = true;
    error.value = "";
    try {
      const next = await get(
        `${base}/${encodeURIComponent(selected)}`,
        undefined,
        { signal: controller.signal },
      );
      if (controller.signal.aborted || n !== serial || selected !== id.value)
        return;
      if (idText(next.id) !== selected)
        throw new Error("详情响应编号不一致，请重新加载");
      value.value = next;
    } catch (e) {
      if (controller.signal.aborted || n !== serial) return;
      value.value = undefined;
      reset();
      error.value = e instanceof Error ? e.message : "无法加载当前记录";
    } finally {
      if (n === serial) loading.value = false;
    }
  }
  watch(
    id,
    () => {
      ++serial;
      request?.abort();
      value.value = undefined;
      error.value = "";
      reset();
      void load();
    },
    { immediate: true, flush: "sync" },
  );
  onBeforeUnmount(() => {
    ++serial;
    request?.abort();
    value.value = undefined;
    reset();
  });
  return { loading, error, ready, capture, load };
}
