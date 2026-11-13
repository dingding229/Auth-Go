import { createApp } from "vue";
import { createPinia } from "pinia";
import ElementPlus, { ElMessage } from "element-plus";
import zhCn from "element-plus/es/locale/lang/zh-cn";
import "element-plus/dist/index.css";
import App from "./App.vue";
import router from "./router";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/layout.css";
import "./styles/element-overrides.css";
// Success notices expire; failures remain readable until explicitly dismissed.
const showError = ElMessage.error.bind(ElMessage),
  showSuccess = ElMessage.success.bind(ElMessage);
ElMessage.error = (options) =>
  showError(
    typeof options === "string"
      ? {
          message: options,
          duration: 0,
          showClose: true,
          customClass: "toast-right",
        }
      : {
          ...options,
          duration: 0,
          showClose: true,
          customClass: "toast-right",
        },
  );
ElMessage.success = (options) =>
  showSuccess(
    typeof options === "string"
      ? { message: options, duration: 3000, customClass: "toast-right" }
      : { ...options, duration: 3000, customClass: "toast-right" },
  );
createApp(App)
  .use(createPinia())
  .use(router)
  .use(ElementPlus, { locale: zhCn })
  .mount("#app");
