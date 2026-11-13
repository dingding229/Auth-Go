import "./admin-bootstrap";
import { it, expect, afterEach, vi } from "vitest";
import { createApp, h, type App } from "vue";
import { createPinia } from "pinia";
import { createRouter, createMemoryHistory } from "vue-router";
import ElementPlus, { ElMessageBox } from "element-plus";
import { AxiosHeaders } from "axios";
import PortalInstancesView from "../src/views/portal/PortalInstancesView.vue";
import { portalHttp } from "../src/lib/http";
import { licenseFields } from "../src/lib/schema";
let app: App | undefined, root: HTMLElement | undefined;
afterEach(() => {
  app?.unmount();
  root?.remove();
  vi.restoreAllMocks();
});
it("defaults KEY+FLOATING one instance", () => {
  expect(
    licenseFields.find((f) => f.key === "verify_methods")?.default,
  ).toEqual(["KEY", "FLOATING"]);
  expect(licenseFields.find((f) => f.key === "max_activations")?.default).toBe(
    1,
  );

});
it("user can release an own floating instance", async () => {
  const writes: string[] = [];
  vi.spyOn(ElMessageBox, "confirm").mockResolvedValue("confirm");
  portalHttp.defaults.adapter = async (config) => {
    if (config.method === "post") writes.push(config.url!);
    return {
      config,
      status: 200,
      statusText: "OK",
      headers: new AxiosHeaders(),
      data: {
        code: "OK",
        data:
          config.url === "/user/instances"
            ? {
                items: [
                  {
                    id: 7,
                    kind: "floating",
                    status: "active",
                    hostname: "实例甲",
                  },
                ],
                total: 1,
              }
            : {},
      },
    };
  };
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: "/", component: { template: "<div/>" } }],
  });
  await router.push("/");
  root = document.createElement("div");
  document.body.append(root);
  app = createApp({ render: () => h(PortalInstancesView, { embedded: true }) });
  app.use(createPinia()).use(ElementPlus).use(router);
  app.mount(root);
  let button: HTMLButtonElement | undefined;
  await vi.waitFor(() => {
    button = [...root!.querySelectorAll<HTMLButtonElement>("button")].find(
      (b) => b.textContent?.trim() === "释放实例",
    );
    expect(button).toBeTruthy();
  });
  expect(button!.disabled).toBe(false);
  expect(root.textContent).toContain("程序仍在运行时会重新占用席位");
  button!.click();
  await vi.waitFor(() =>
    expect(writes).toEqual(["/user/instances/7/release-seat"]),
  );
});
