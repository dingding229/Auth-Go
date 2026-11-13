import { ElMessage } from "element-plus";

export async function copy(
  value: string,
  successText?: string,
): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(value);
    if (successText) ElMessage.success(successText);
    return true;
  } catch {
    ElMessage.warning("无法访问剪贴板，请选中文本手动复制");
    return false;
  }
}
