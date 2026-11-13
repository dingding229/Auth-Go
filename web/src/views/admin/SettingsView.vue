<script setup lang="ts">
import RequestNotice from "../../components/RequestNotice.vue";
import DataTable from "../../components/DataTable.vue";
import SectionPanel from "../../components/SectionPanel.vue";
import { computed, onMounted, ref } from "vue";
import { ElMessage } from "element-plus";
import { get, patch, post, download } from "../../lib/http";
import { record, rows, stringify, type Row } from "../../lib/json";
import { field, type Field } from "../../lib/schema";
import { watch } from "vue";
import { useUIStore } from "../../stores/ui";
import { useTask, confirmAction, useLoadTask } from "../../composables/tasks";
import AdminPathSettings from "../../components/AdminPathSettings.vue";
import SupportContactSettings from "../../components/SupportContactSettings.vue";
import IpDatabaseSettings from "../../components/IpDatabaseSettings.vue";
import GatewaySettings from "../../components/GatewaySettings.vue";
import UpdateSettings from "../../components/UpdateSettings.vue";
import PageHeading from "../../components/PageHeading.vue";
import SchemaEditor from "../../components/SchemaEditor.vue";
const task = useTask(),
  loadTask = useLoadTask(),
  settings = ref<Row>(),
  backups = ref<Row[]>([]),
  to = ref("");
const ui = useUIStore();
watch(
  () => settings.value?.site_name,
  (name) => {
    if (name) ui.siteName = String(name);
  },
);
const topFields: Field[] = [
  field("tools_image", "authgo-pack工具镜像名", {
    max: 255,
    hint: "代码加密构建使用，例如 registry.example.com/team/authgo-tools；不含标签。不填账号默认值，留空时向导提示先配置。",
  }),
  field("tools_version", "工具镜像版本", {
    max: 128,
    hint: "已构建并发布的工具镜像标签，与镜像名同时填写；本系统不会自动推送镜像。",
  }),
  field("public_url", "对外服务地址", {
    hint: "用于接入配置和初始化链接，例如https://auth.example.com；留空时复制配置采用当前页面地址。",
  }),
  field("site_name", "站点名称", { required: true, max: 128 }),
  field("trusted_proxies", "受信代理（每行一项）", {
    type: "lines",
    hint: "部署环境的可信代理与此处列表合并生效，此处清空不能取消环境配置；仅填写实际可信的代理IP/CIDR。",
  }),
  field("client_ip_rate", "客户端每IP速率（次/秒）", {
    type: "number",
    min: 1,
    max: 100000,
  }),
  field("client_ip_burst", "客户端每IP突发容量", {
    type: "number",
    min: 1,
    max: 100000,
  }),
  field("client_license_rate", "每授权速率（次/秒）", {
    type: "number",
    min: 1,
    max: 100000,
  }),
  field("client_license_burst", "每授权突发容量", {
    type: "number",
    min: 1,
    max: 100000,
  }),
  field("log_retention_days", "验证日志保留天数", {
    hint: "仅影响验证日志；审计日志固定保留 365 天，由每日清理任务删除更早记录，不自动归档。",
    type: "number",
    min: 1,
    max: 3650,
  }),
  field("notification_retention_days", "通知历史保留天数", {
    type: "number",
    min: 1,
    max: 3650,
    hint: "仅清理成功或重试耗尽的记录；仍在途的任务不会被删除。",
  }),

  field("admin_notification_emails", "管理员通知邮箱（每行一项）", {
    type: "lines",
    hint: "到期提醒会同时独立投递至这些邮箱，最多50个。",
  }),
];
const smtpFields: Field[] = [
  field("enabled", "启用邮件服务", { type: "switch" }),
  field("host", "SMTP主机"),
  field("port", "端口", { type: "number", min: 1, max: 65535 }),
  field("mode", "连接方式", {
    type: "select",
    options: [
      { value: "starttls", label: "必需STARTTLS" },
      { value: "tls", label: "隐式TLS" },
      { value: "plain", label: "明文（仅回环测试）" },
    ],
  }),
  field("username", "SMTP用户名"),
  field("password", "SMTP密码", {
    type: "password",
    max: 1024,
    hint: "留空保持原值，不会回显现有密码。",
  }),
  field("from", "发件邮箱"),
];
const smtp = computed(() => record(settings.value?.smtp));
function changes(body: Row, before: Row): Row {
  return Object.fromEntries(
    Object.entries(body).filter(
      ([key, v]) => stringify(v) !== stringify(before[key]),
    ),
  );
}
async function load() {
  await loadTask.run(async () => {
    settings.value = await get("/system/settings");
    {
      const list = await get("/system/backups");
      backups.value = rows(list.items);
    }
  });
}
onMounted(() => {
  void load();
});
async function saveTop(body: Row) {
  await task.run(async () => {
    const changed = changes(body, settings.value ?? {});
    if (!Object.keys(changed).length) {
      ElMessage.info("没有需要保存的修改");
      return;
    }
    settings.value = await patch("/system/settings", changed);
    ElMessage.success("系统设置已保存");
  });
}
async function saveSMTP(body: Row) {
  await task.run(async () => {
    const changed = changes(body, smtp.value);
    if (!Object.keys(changed).length) {
      ElMessage.info("没有需要保存的修改");
      return;
    }
    settings.value = await patch("/system/settings", { smtp: changed });
    ElMessage.success("邮件设置已保存");
  });
}
async function clearSMTP() {
  await task.run(async () => {
    await confirmAction(
      "确认清除保存的SMTP密码？邮件发送可能因此失败。",
      "清除 SMTP 密码",
      { action: "清除 SMTP 密码", danger: true },
    );
    settings.value = await patch("/system/settings", {
      smtp: { password: "" },
    });
  }, "SMTP密码已清除");
}
async function test() {
  await task.run(async () => {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(to.value))
      throw new Error("请输入有效的测试收件邮箱");
    await post("/system/smtp/test", { to: to.value });
  }, "测试邮件已发送");
}
async function backup() {
  await task.run(async () => {
    await confirmAction(
      "备份包含授权码、个人数据和加密密钥，仅保留最新7份。确认立即备份？",
      "创建数据库备份",
      { action: "创建数据库备份" },
    );
    await post("/system/backups", {});
    backups.value = rows((await get("/system/backups")).items);
  }, "备份已完成");
}
</script>
<template>
  <page-heading
    title="系统设置"
    description="已保存的业务设置优先于环境默认值；可信代理与部署环境列表合并生效。审计日志保留 365 天。"
  >
    <el-button :loading="task.busy.value" @click="load">
      刷新设置
    </el-button>
  </page-heading>
  <el-skeleton
    v-if="loadTask.busy.value && !settings"
    :rows="5"
    animated
    aria-label="正在加载资料"
  /><request-notice
    :error="loadTask.error.value"
    :busy="loadTask.busy.value"
    @retry="load()"
  />
  <request-notice :error="task.error.value" /><template v-if="settings">
    <el-tabs>
      <el-tab-pane label="基础与安全">
        <section-panel>
          <gateway-settings />
          <schema-editor
            :fields="topFields"
            :initial="settings"
            :busy="task.busy.value"
            @save="saveTop"
            @cancel="load"
          />
        </section-panel>
        <AdminPathSettings />
        <SupportContactSettings />
      </el-tab-pane>
      <el-tab-pane label="邮件服务">
        <section-panel>
          <el-alert
            title="默认要求TLS，明文连接仅允许本机测试。修改后请手动发送测试邮件。"
            type="info"
            :closable="false"
          />
          <p class="muted">
            已保存密码：{{ smtp.has_password ? "是" : "否" }}
          </p>
          <schema-editor
            :fields="smtpFields"
            :initial="smtp"
            :busy="task.busy.value"
            @save="saveSMTP"
            @cancel="load"
          /><el-button
            v-if="smtp.has_password"
            type="danger"
            plain
            @click="clearSMTP"
          >
            清除SMTP密码
          </el-button>
        </section-panel>
        <section-panel>
          <h2>测试发送</h2>
          <el-form label-position="top" @submit.prevent="test">
            <el-form-item label="测试收件邮箱">
              <el-input
                v-model="to"
                type="email"
                autocomplete="email"
                placeholder="输入你可以接收邮件的地址"
              />
            </el-form-item><el-button
              type="primary"
              native-type="submit"
              :loading="task.busy.value"
            >
              发送测试邮件
            </el-button>
          </el-form>
        </section-panel>
      </el-tab-pane>
      <el-tab-pane label="IP 库" lazy>
        <IpDatabaseSettings />
      </el-tab-pane>
      <el-tab-pane label="版本同步">
        <update-settings />
      </el-tab-pane>

      <el-tab-pane label="数据库备份">
        <section-panel>
          <div class="panel-heading">
            <h2>SQLite备份</h2>
            <el-button
              type="primary"
              :loading="task.busy.value"
              @click="backup"
            >
              立即备份
            </el-button>
          </div>
          <p class="muted">
            每日自动备份，最多保留7份。请下载完整ZIP，包含authgo.db和
            master.key；主密钥与数据库在同一数据卷，必须一起备份。ZIP
            含敏感密钥，请安全保存。恢复需停机；环境变量主密钥优先，必须与备份一致。旧快照没有完整包时须另行备份原密钥。此处不提供在线恢复。
          </p>
          <data-table
            :error="loadTask.error.value"
            :loading="loadTask.busy.value"
            :items="backups"
            empty="还没有数据库备份"
            empty-action="立即备份"
            :columns="[
              { key: 'name', title: '文件名称', width: 240 },
              { key: 'size', title: '大小', width: 80 },
              { key: 'created_at', title: '生成时间', date: true, width: 150 },
            ]"
            @empty-action="backup"
          >
            <template #cell-size="{ row }">
              {{ (Number(row.size) / 1024 / 1024).toFixed(2) }}MB
            </template>
            <template #actions="{ row }">
              <el-button
                link
                type="primary"
                @click="
                  task.run(() =>
                    download(
                      'admin',
                      `/system/backups/${encodeURIComponent(String(row.name))}`,
                      String(row.name) + '.zip',
                      {},
                    ),
                  )
                "
              >
                下载完整包
              </el-button>
            </template>
          </data-table>
        </section-panel>
      </el-tab-pane>
    </el-tabs>
  </template>
</template>
