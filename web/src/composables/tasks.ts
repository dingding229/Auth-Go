import { ref } from "vue";
import axios from "axios";
import { ElMessage, ElMessageBox } from "element-plus";
import { focusReturn } from "../lib/overlay-focus";
export function useTask(kind: "action" | "load" = "action") {
  let succeeded = false;
  const busy = ref(false),
    error = ref("");
  async function run<T>(
    fn: () => Promise<T>,
    message?: string,
  ): Promise<T | undefined> {
    if (busy.value) return;
    busy.value = true;
    error.value = "";
    try {
      const result = await fn();
      succeeded = true;
      if (message) ElMessage.success(message);
      return result;
    } catch (e) {
      if (axios.isCancel(e) || e === "cancel" || e === "close") return;
      const message = e instanceof Error ? e.message : "请检查表单填写是否完整";
      error.value = kind === "load" && succeeded
        ? `刷新失败，显示上次成功读取的数据：${message}` : message;
    } finally {
      busy.value = false;
    }
  }
  return { busy, error, run };
}
export function useLoadTask() {
  return useTask("load");
}
export async function confirmAction(
  message: string,
  title = "操作确认",
  options: { action: string; danger?: boolean; match?: string },
) {
  const focus = focusReturn();
  const common = {
    type: options.danger ? ("error" as const) : ("warning" as const),
    confirmButtonText: options.action,

    cancelButtonText: "取消",
    distinguishCancelAndClose: true,
    closeOnClickModal: false,
    customClass: "authgo-confirm",
    beforeClose: (_action: unknown, _instance: unknown, done: () => void) => {
      const box = document.querySelector(".authgo-confirm");
      if (box) {
        // Wait for leave/removal, otherwise the library's focus trap can undo
        // restoration to the original (possibly temporarily disabled) button.
        const observer = new MutationObserver(() => {
          if (!box.isConnected) { observer.disconnect(); focus.restore(); }
        });
        observer.observe(document.body, { childList: true, subtree: true });
      } else focus.restore();
      done();
    },
    confirmButtonClass: options.danger ? "el-button--danger" : "",
  };
  if (options.match) {
    await ElMessageBox.prompt(
      `${message}请输入“${options.match}”继续。`,
      title,
      {
        ...common,
        inputValidator: (v: string) =>
          v === options.match || "输入不匹配，请检查后重试",
        inputPlaceholder: `输入 ${options.match}`,
      },
    );
  } else await ElMessageBox.confirm(message, title, common);
}
