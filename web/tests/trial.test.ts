import "./admin-bootstrap";
import {afterEach,expect,it} from "vitest";
import {createApp,nextTick,type App} from "vue";
import ElementPlus from "element-plus";
import {AxiosHeaders} from "axios";
import TrialSettings from "../src/components/TrialSettings.vue";
import TrialMetrics from "../src/components/TrialMetrics.vue";
import {http} from "../src/lib/http";
import {setAdmin} from "../src/lib/session";
let app:App|undefined,root:HTMLElement;const original=http.defaults.adapter;
afterEach(()=>{app?.unmount();root?.remove();http.defaults.adapter=original;});
async function mount(component:Parameters<typeof createApp>[0],props={}){setAdmin("admin","refresh");root=document.createElement("div");document.body.append(root);app=createApp(component,props).use(ElementPlus);app.mount(root);for(let i=0;i<6;i++){await nextTick();await new Promise(r=>setTimeout(r,0));}}
it("试用设置走接口保存并说明无宽限与网络共享",async()=>{
 let sent:unknown;http.defaults.adapter=async config=>{if(config.method==="patch")sent=config.data;return{data:{code:"OK",data:{trial_enabled:true,trial_days:14}},status:200,statusText:"OK",headers:new AxiosHeaders(),config};};
 await mount(TrialSettings,{id:"7"});expect(root.textContent).toContain("不提供断网宽限");expect(root.textContent).toContain("同一网络共用一个试用");
 root.querySelector("form")!.dispatchEvent(new Event("submit",{bubbles:true,cancelable:true}));await nextTick();await new Promise(r=>setTimeout(r,0));expect(String(sent)).toContain("trial_enabled");
});
it("概览显示累计试用和转正数量",async()=>{
 http.defaults.adapter=async config=>({data:{code:"OK",data:{trial_count:8,converted_count:3}},status:200,statusText:"OK",headers:new AxiosHeaders(),config});
 await mount(TrialMetrics);expect(root.textContent).toContain("累计试用：8");expect(root.textContent).toContain("已转正：3");
});
