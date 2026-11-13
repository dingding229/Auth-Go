import "./admin-bootstrap";
import { afterEach, expect, it } from "vitest";
import { createApp, nextTick, type App } from "vue";
import ElementPlus from "element-plus";
import { AxiosHeaders } from "axios";
import { maintenanceText, renewalMaintenance } from "../src/lib/maintenance";
import { label } from "../src/lib/labels";
import { licenseFields } from "../src/lib/schema";
import { licenseRequest } from "../src/lib/validity";
import PortalUpdate from "../src/components/PortalUpdate.vue";
import { portalHttp } from "../src/lib/http";
import { setPortal } from "../src/lib/session";
let app: App | undefined, root: HTMLElement;
const original = portalHttp.defaults.adapter;
afterEach(() => { app?.unmount(); root?.remove(); portalHttp.defaults.adapter = original; });
it("维护期发放和批量使用相同字段，0表示不限", () => {
  const field = licenseFields.find(f => f.key === "maintenance_days")!;
  expect(field.advanced).toBe(true);
  expect(field.default).toBe(0);
  for (const count of [1, 3]) {
    expect(licenseRequest({count, app_id:1, maintenance_days:30}).data.maintenance_days).toBe(30);
  }
});
it("续期不默认延长维护期，必须显式填写", () => {
  expect(renewalMaintenance(false, 30)).toEqual({});
  expect(renewalMaintenance(true, 30)).toEqual({maintenance_days:30});
  expect(renewalMaintenance(true, 0)).toEqual({maintenance_days:0});
  for (const days of [-1, 1.5, 36501]) expect(() => renewalMaintenance(true,days)).toThrow();
});
it("维护期没有时显示不限，到期后明确提示但不说授权失效", () => {
  expect(maintenanceText(null)).toBe("不限");
  expect(maintenanceText("2020-01-02T00:00:00Z", Date.UTC(2020,0,3))).toContain("维护期已到期");
  expect(maintenanceText("2030-01-02T00:00:00Z", Date.UTC(2020,0,3))).not.toContain("已到期");
});
it("用户中心只给可用版本的拉取命令，并说明更新版本需要续期", async () => {
  setPortal("portal", "license");
  portalHttp.defaults.adapter = async config => ({ data:{code:"OK",data:{available:true,version:"2.0.0",assets:[],docker_image:"example/app",docker_pull:"docker pull example/app:2.0.0",renewal_required:true,latest_entitled_version:"2.0.0"}},status:200,statusText:"OK",headers:new AxiosHeaders(),config });
  root=document.createElement("div");document.body.append(root);
  app=createApp(PortalUpdate,{license:{id:1,status:"active",maintenance_until:"2020-01-02T00:00:00Z"}});app.use(ElementPlus);app.mount(root);
  for(let i=0;i<5;i++){await nextTick();await new Promise(resolve=>setTimeout(resolve,0));}
  expect(root.textContent).toContain("更新版本需要续期");
  expect(root.textContent).toContain("可用最高版本：2.0.0");
  expect(root.textContent).toContain("docker pull example/app:2.0.0");
  expect(root.textContent).not.toContain("example/app:2.1.0");
});

it("维护期拒绝显示面向用户的原因而不是内部错误码", () => {
 expect(label("MAINTENANCE_EXPIRED")).toBe("当前授权的更新维护期已结束，此版本需要续期");
});
