import { opts } from "./labels";
import type { Column } from "../components/DataTable.vue";
export type Values = Record<string, string | number | boolean | string[]>;
export interface Field {
  key: string;
  label: string;
  type?:
    | "text"
    | "password"
    | "textarea"
    | "number"
    | "select"
    | "methods"
    | "switch"
    | "json"
    | "lines"
    | "date"
    | "resource"
    | "multi"
    | "validity"
    | "user";
  advanced?: boolean;
  required?: boolean | ((v: Values) => boolean);
  hideControl?: boolean;
  options?: { value: string; label: string }[];
  resource?: string;
  default?: string | number | boolean | string[];
  hint?: string;
  min?: number;
  max?: number;
  immutable?: boolean;
  nullable?: boolean;
  visible?: (v: Values) => boolean;
}
export interface Spec {
  key: string;
  title: string;
  singular: string;
  path: string;
  fields: Field[];
  columns: Column[];
  search?: boolean;
  noEdit?: boolean;
  filters?: Field[];
  description?: string;
}
export const field = (
  key: string,
  label: string,
  rest: Omit<Field, "key" | "label"> = {},
): Field => ({ key, label, ...rest });
const name = field("name", "名称", { required: true, max: 128 });
const note = field("note", "备注", { type: "textarea", max: 4096 });
const app = field("app_id", "所属软件", {
  type: "resource",
  resource: "/applications",
  required: true,
  immutable: true,
});
const date = (key: string, label: string, nullable = false) =>
  field(key, label, { type: "date", nullable });
const number = (
  key: string,
  label: string,
  value: number,
  min = 0,
  max = 1000000,
) => field(key, label, { type: "number", default: value, min, max });
const select = (key: string, label: string, values: string[], value: string) =>
  field(key, label, { type: "select", options: opts(values), default: value });
export const policyFields: Field[] = [
  select(
    "type",
    "授权类型",
    ["trial", "standard", "subscription", "perpetual", "floating"],
    "standard",
  ),
  select(
    "validity_rule",
    "有效期规则",
    ["perpetual", "fixed_days", "after_activation"],
    "perpetual",
  ),
  {
    ...number("duration_days", "有效天数", 30, 1, 36500),
    visible: (v) =>
      v.validity_rule === "fixed_days" ||
      v.validity_rule === "after_activation",
  },
  field("verify_methods", "验证方式", {
    type: "methods",
    default: ["KEY", "FLOATING"],
    hint: "默认按同时在线的运行实例计数；显式仅授权码时不限制实例数。",
  }),
  select("match_mode", "验证条件组合", ["all", "any"], "all"),
  number("max_activations", "同时运行实例数", 1, 1),
  field("features", "功能项（JSON对象）", {
    type: "json",
    default: "{}",
    hint: '例如 {"导出":true,"配额":100}，保留大整数精度。',
  }),
];
export const licenseFields: Field[] = [
  field("user_id", "发给谁", {
    type: "user",
    resource: "/users",
    required: (v) => Number(v.count || 1) === 1,
    hint: "单个必须选择用户；批量时可留空，生成待分配授权。",
  }),
  app,

  field("prefix", "授权码前缀", { default: "AUTH", max: 16 }),
  ...policyFields.map((f) =>
    f.key === "validity_rule"
      ? {
          ...f,
          options: opts([
            "perpetual",
            "fixed_days",
            "after_activation",
            "fixed_expiry",
          ]),
        }
      : f,
  ),
  {
    ...date("expires_at", "到期时间"),
    required: true,
    visible: (v) => v.validity_rule === "fixed_expiry",
  },
  { ...date("starts_at", "允许开始时间（可选）") },

  field("maintenance_days", "更新维护天数", {
    type: "number",
    default: 0,
    min: 0,
    max: 36500,
    advanced: true,
    hint: "从发放时计算，0表示不限。维护期结束后仍可使用维护期内发布的版本。",
  }),

  field("portal_password", "授权查询密码（可选）", {
    type: "password",
    max: 72,
    hint: "设置后用户可用授权码与查询密码登录用户中心。",
  }),
  note,
  field("metadata", "扩展数据（JSON对象）", { type: "json", default: "{}" }),
];
// Progressive disclosure changes presentation only; API defaults stay explicit.
for (const f of licenseFields) {
  f.advanced = ![
    "user_id",
    "app_id",
    "verify_methods",
    "validity_rule",
    "max_activations",
  ].includes(f.key);
  if (f.key === "validity_rule") {
    f.type = "validity";
    f.label = "有效期";
  }
  if (["duration_days", "expires_at"].includes(f.key)) f.visible = () => false;
  if (f.key === "max_activations")
    f.visible = (v) =>
      (v.verify_methods as string[]).some((m) => ["FLOATING"].includes(m));
}
const base: Column[] = [
  { key: "id", title: "编号", width: 80 },
  { key: "created_at", title: "创建时间", date: true, width: 180 },
];
const status: Column = {
  key: "status",
  title: "状态",
  state: true,
  width: 110,
};
export const specs: Record<string, Spec> = {
  users: {
    key: "users",
    title: "用户",
    description: "管理用户资料、授权与实例。",
    singular: "用户",
    path: "/users",
    fields: [
      field("name", "姓名", { required: true, max: 128 }),
      field("email", "邮箱（可选）", { max: 254 }),
      field("note", "备注", { type: "textarea", advanced: true, max: 4096 }),
      {
        ...select("status", "状态", ["active", "disabled"], "active"),
        advanced: true,
      },
      field("portal_password", "用户中心密码", {
        type: "password",
        advanced: true,
        max: 72,
        hint: "8至72字节；编辑留空不更改。也可在用户详情中设置。",
      }),
    ],
    columns: [
      { key: "name", title: "姓名", width: 110 },
      { key: "email", title: "邮箱", width: 180 },
      { key: "license_count", title: "授权数", width: 80 },
      { key: "status", title: "状态", state: true, width: 88 },
    ],
  },
  applications: {
    key: "applications",
    title: "软件",
    singular: "软件",
    path: "/applications",
    description: "管理软件、使用规则和程序接入。",
    fields: [
      name,
      field("description", "软件说明", { type: "textarea" }),
      field("docker_image", "Docker Hub镜像名", {
        max: 255,
        hint: "例如your-org/your-app，不含标签；可在接入向导中填写。留空停止同步，已有版本保留。",
      }),
      select("status", "运行状态", ["active", "disabled"], "active"),
      number("next_check_in", "多久联网检查一次（秒）", 3600, 1, 86400),
      field("grace_hours", "断网继续运行（小时）", {
        type: "number",
        default: 72,
        min: 0,
        max: 8760,
        hint: "0表示不提供断网宽限。仅已有有效缓存可用；时长越长，吊销生效越晚，断网期间无法清点实例席位。",
      }),

      number("heartbeat_interval", "心跳间隔（秒）", 60, 5, 3600),
    ].map((f) => ({ ...f, advanced: f.key !== "name" })),
    columns: [{ key: "name", title: "软件名称", width: 180 }, status, base[1]!],
    filters: [],
  },
};
export const announcementSpec: Spec = {
  key: "announcements",
  title: "公告",
  singular: "公告",
  path: "/announcements",
  fields: [
    field("title", "标题", { required: true, max: 128 }),
    field("content", "正文", {
      type: "textarea",
      max: 32768,
      hint: "已发布公告任何人可读，不要写内部信息。按纯文本展示，不执行HTML。",
    }),
    date("published_at", "发布时间（空为草稿）", true),
    date("expires_at", "失效时间（可清空）", true),
  ],
  columns: [
    { key: "title", title: "标题", width: 250 },
    { key: "published_at", title: "发布时间", date: true },
    { key: "expires_at", title: "失效时间", date: true },
  ],
};
export const versionSpec: Spec = {
  key: "versions",
  title: "版本",
  singular: "版本",
  path: "/versions",
  fields: [
    field("encrypted", "代码加密（展示元数据）", {
      type: "switch",
      default: false,
      hint: "由管理员在版本创建/编辑时登记；Docker Hub同步保留。不是授权信任源。",
    }),
    field("built_at", "构建时间", {
      type: "date",
      nullable: true,
      hint: "启用代码加密时必填，取自打包产物payload.json的built_at；授权始终使用已认证信封而非此字段。",
    }),
    field("version", "版本号", {
      required: true,
      hint: "例如1.2.0，使用语义化版本。",
    }),
    field("changelog", "更新说明", {
      type: "textarea",
      hint: "已发布版本内容任何人可读，不要写内部信息。",
    }),
    field("mandatory", "强制更新", { type: "switch", default: false }),
    date("published_at", "发布时间（空为草稿）", true),
  ],
  columns: [
    { key: "version", title: "版本号" },
    { key: "mandatory", title: "强制更新" },
    { key: "published_at", title: "发布时间", date: true },
  ],
};
export const activationColumns: Column[] = [
  { key: "id", title: "编号", width: 80 },
  { key: "license_key", title: "授权码", mono: true, width: 210 },
  { key: "hostname", title: "实例名称" },
  { key: "instance_id", title: "实例 ID", mono: true, width: 230 },
  { key: "os", title: "系统" },
  status,
  { key: "last_ip", title: "最近IP", width: 160 },
  { key: "last_seen_at", title: "最近在线", date: true, width: 180 },
];
export const logColumns: Column[] = [
  { key: "created_at", title: "时间", date: true, width: 185 },
  { key: "license_id", title: "授权编号" },
  { key: "action", title: "操作", enum: true },
  { key: "code", title: "结果", enum: true, width: 200 },
  { key: "ip", title: "来源IP", width: 170 },
  { key: "device", title: "实例指纹", mono: true, width: 220 },
  { key: "client_version", title: "客户端版本" },
  { key: "duration_ms", title: "耗时（毫秒）" },
];
