import "./admin-bootstrap";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createApp, h, nextTick, ref, type App } from "vue";
import ElementPlus from "element-plus";
import StatusBadge from "../src/components/StatusBadge.vue";
import CopyField from "../src/components/CopyField.vue";
import DataTable from "../src/components/DataTable.vue";
import SectionPanel from "../src/components/SectionPanel.vue";
import ListPager from "../src/components/ListPager.vue";
import KeyValueList from "../src/components/KeyValueList.vue";
import { statusKinds } from "../src/lib/status";
import { label } from "../src/lib/labels";
import { dateText } from "../src/lib/json";
import { deviceRows, deviceUsage } from "../src/lib/presentation";
import { readFileSync } from "node:fs";
let app: App | undefined, root: HTMLElement;
beforeEach(() => {
  root = document.createElement("div");
  document.body.append(root);
});
afterEach(() => {
  app?.unmount();
  app = undefined;
  root.remove();
  vi.restoreAllMocks();
});
function mount(component: Parameters<typeof createApp>[0]) {
  app = createApp(component);
  app.use(ElementPlus);
  app.mount(root);
}
it("全部状态具有统一中文和语义；未知状态保留原文并显示neutral", async () => {
  mount({
    render: () =>
      h(
        "div",
        [...Object.keys(statusKinds), "custom_state"].map((value) =>
          h(StatusBadge, { value }),
        ),
      ),
  });
  await nextTick();
  const badges = [...root.querySelectorAll(".status-badge")];
  expect(badges).toHaveLength(Object.keys(statusKinds).length + 1);
  Object.entries(statusKinds).forEach(([state, kind], i) => {
    expect(badges[i]!.classList.contains(`status-${kind}`)).toBe(true);
    expect(badges[i]!.textContent).toBe(label(state));
  });
  expect(badges.at(-1)?.textContent).toBe("custom_state");
  expect(badges.at(-1)?.classList.contains("status-neutral")).toBe(true);
  expect(label("withdrawn")).toBe("已撤回");
});
it("CopyField敏感值默认隐藏；显示、展开、复制及已复制反馈可通过键盘按钮操作", async () => {
  const write = vi.fn().mockResolvedValue(undefined);
  const clipboard = Object.getOwnPropertyDescriptor(navigator, "clipboard");
  Object.defineProperty(navigator, "clipboard", {
    value: { writeText: write },
    configurable: true,
  });
  try {
    const secret = "authgo2." + "private".repeat(12);
    mount({
      render: () =>
        h(CopyField, { value: secret, sensitive: true, label: "接入配置" }),
    });
    await nextTick();
    expect(root.textContent).not.toContain(secret);
    const button = (name: string) =>
      root.querySelector<HTMLButtonElement>(`button[aria-label="${name}"]`)!;
    expect(button("复制接入配置").disabled).toBe(true);
    button("显示接入配置").click();
    await nextTick();
    expect(root.textContent).toContain(secret);
    button("展开接入配置").click();
    await nextTick();
    expect(root.querySelector(".is-expanded")).not.toBeNull();
    button("复制接入配置").click();
    await vi.waitFor(() => expect(root.textContent).toContain("已复制"));
    expect(write).toHaveBeenCalledExactlyOnceWith(secret);
    button("隐藏接入配置").click();
    await nextTick();
    expect(root.textContent).not.toContain(secret);
  } finally {
    if (clipboard) Object.defineProperty(navigator, "clipboard", clipboard);
    else Reflect.deleteProperty(navigator, "clipboard");
  }
});
it("DataTable空状态不使用插画，筛选无结果提供可执行的清除入口", async () => {
  const clear = vi.fn();
  mount({
    render: () =>
      h(DataTable, { items: [], columns: [], filtered: true, onClear: clear }),
  });
  await nextTick();
  expect(root.textContent).toContain("没有符合条件的记录");
  root.querySelector<HTMLButtonElement>("button")!.click();
  expect(clear).toHaveBeenCalledOnce();
  expect(root.querySelector("img,svg")).toBeNull();
});
it("DataTable首次加载用骨架；刷新保留已有行；手机卡片含同样记录", async () => {
  const items = ref<Record<string, unknown>[]>([]);
  mount({
    render: () =>
      h(DataTable, {
        items: items.value,
        columns: [{ key: "name", title: "名称" }],
        loading: true,
      }),
  });
  await nextTick();
  expect(root.querySelector(".el-skeleton")).not.toBeNull();
  items.value = [{ id: 1, name: "账本记录" }];
  await nextTick();
  await nextTick();
  expect(root.querySelector(".el-skeleton")).toBeNull();
  await vi.waitFor(() =>
    expect(root.querySelector(".table-scroll")?.textContent).toContain(
      "账本记录",
    ),
  );
  expect(root.querySelector(".table-cards")?.textContent).toContain("账本记录");
});
it("嵌套的SectionPanel退化为线条区块，不产生卡片套卡片；空资料显示破折号", async () => {
  mount({
    render: () =>
      h(SectionPanel, {}, () => [
        h(SectionPanel, {}, () =>
          h(KeyValueList, { items: [{ label: "邮箱", value: null }] }),
        ),
      ]),
  });
  await nextTick();
  expect(root.querySelectorAll(".section-panel")).toHaveLength(1);
  expect(root.querySelectorAll(".section-group")).toHaveLength(1);
  expect(root.textContent).toContain("—");
});
it("视觉约束集中在tokens且没有暗色模式、页面深度覆盖或业务十六进制颜色", () => {
  const sources = import.meta.glob("../src/**/*.vue", {
    query: "?raw",
    import: "default",
    eager: true,
  }) as Record<string, string>;
  for (const source of Object.values(sources)) {
    expect(source).not.toMatch(/:deep\(/);
    expect(source).not.toMatch(/#[0-9a-fA-F]{6}\b/);
  }
  const tokens = readFileSync("src/styles/tokens.css", "utf8");
  expect(tokens).toContain("--canvas: #f6f7f5");
  expect(tokens).toContain("--brand: #0f6b5c");
  expect(readFileSync("src/styles/layout.css", "utf8")).toContain("216px");
});
it("时间统一完整日期，日志可加秒，不显示相对时间", () => {
  const date = new Date(2026, 10, 5, 9, 4, 3);
  expect(dateText(date.toISOString())).toBe("2026-11-05 09:04");
  expect(dateText(date.toISOString(), true)).toBe("2026-11-05 09:04:03");
  expect(dateText(null)).toBe("—");
});

it("用户详情仅按展示合并实例，key激活保留在授权详情，不改原始对象", () => {
  const source = [
    { id: 1, kind: "key", instance_id: "k", license_key: "L1" },
    { id: 2, kind: "floating", instance_id: "fp", license_key: "L1" },
    { id: 3, kind: "floating", instance_id: "fp", license_key: "L2" },
  ];
  const result = deviceRows(source);
  expect(result).toHaveLength(1);
  expect(result[0]?.license_key).toBe("L1、L2");
  expect(source[1]?.license_key).toBe("L1");
});

it("设备用量来自服务端汇总，KEY只显示不限而不是伪造设备额度", () => {
  expect(
    deviceUsage({
      active_activations: 1,
      max_activations: 3,
      verify_methods: ["KEY", "FLOATING"],
    }),
  ).toBe("1/3");
  expect(
    deviceUsage({
      active_activations: 3,
      max_activations: 2,
      verify_methods: ["KEY"],
    }),
  ).toBe("3/不限");
  expect(
    deviceUsage({
      active_activations: 0,
      max_activations: 5,
      verify_methods: ["KEY", "FLOATING"],
    }),
  ).toBe("0/5");
});

it("全站分页器总数为0时不渲染，非空时仍保留翻页入口", async () => {
  const total = ref(0);
  mount({
    render: () => h(ListPager, { total: total.value, page: 1, size: 20 }),
  });
  await nextTick();
  expect(root.querySelector(".list-pager")).toBeNull();
  total.value = 20;
  await nextTick();
  expect(root.querySelector(".list-pager")).not.toBeNull();
  total.value = 0;
  await nextTick();
  expect(root.querySelector(".el-pagination")).toBeNull();
});
