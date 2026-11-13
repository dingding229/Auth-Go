<script setup lang="ts">
import FocusOverlay from "../../components/FocusOverlay.vue";
import { adminPage } from "../../lib/runtime";
import RequestNotice from "../../components/RequestNotice.vue";
import KeyValueItem from "../../components/KeyValueItem.vue";
import KeyValueList from "../../components/KeyValueList.vue";
import SectionPanel from "../../components/SectionPanel.vue";
import { deviceRows } from "../../lib/presentation";
import StatusBadge from "../../components/StatusBadge.vue";
import ActionMenu from "../../components/ActionMenu";
import { computed, ref } from "vue";
import { useRoute } from "vue-router";
import { patch, pget } from "../../lib/http";
import { idText, type Row } from "../../lib/json";
import { issueLicenseLocation } from "../../lib/navigation";
import { specs } from "../../lib/schema";
import { useTask, confirmAction } from "../../composables/tasks";
import { useAdminDetail } from "../../composables/admin-detail";
import { useCollection } from "../../composables/collection";
import PageHeading from "../../components/PageHeading.vue";
import SchemaEditor from "../../components/SchemaEditor.vue";
import DataTable from "../../components/DataTable.vue";
import ListPager from "../../components/ListPager.vue";
const route = useRoute(),
  id = computed(() => String(route.params.id)),
  user = ref<Row>(),
  editing = ref(false),
  task = useTask();
const displayDevices = computed(() => deviceRows(devices.items.value));
const licenses = useCollection("/licenses", () => ({ user_id: id.value })),
  devices = useCollection("/activations", () => ({ user_id: id.value })),
  logs = useCollection("/verify-logs", () => ({ user_id: id.value }));
async function reloadLists() {
  await Promise.all([licenses.load(), devices.load(), logs.load()]);
}
const detail = useAdminDetail("/users", id, user, () => {
  editing.value = false;
  for (const list of [licenses, devices, logs]) {
    list.items.value = [];
    list.total.value = 0;
  }
  task.error.value = "";
});
const load = detail.load;
async function save(body: Row) {
  await task.run(async () => {
    const selected = detail.capture();
    selected.commit(await patch(`/users/${selected.id}`, body));
    if (!selected.current()) return;
    editing.value = false;
  }, "用户信息已更新");
}
async function toggle() {
  await task.run(async () => {
    const selected = detail.capture();
    const status = user.value?.status === "active" ? "disabled" : "active";
    await confirmAction(
      status === "disabled"
        ? "停用后该用户全部授权立即验证失败，用户中心会话失效。确认停用？"
        : "确认启用该用户？",
      status === "disabled" ? "停用用户" : "启用用户",
      {
        action: status === "disabled" ? "停用用户" : "启用用户",
        danger: status === "disabled",
      },
    );
    selected.check();
    selected.commit(await patch(`/users/${selected.id}`, { status }));
  });
}
async function clearPassword() {
  await task.run(async () => {
    const selected = detail.capture();
    // Read the public login capability at the time of this destructive action.
    // If it cannot be read, do not guess that email-code login is available.
    const options = await pget("/login/options");
    selected.check();
    const hasEmail = Boolean(String(user.value?.email || "").trim());
    const canEmail = options.smtp_configured === true && hasEmail;
    await confirmAction(
      "清除后旧用户中心会话立即失效。" +
        (!hasEmail
          ? "该用户未关联邮箱，无法接收邮箱验证码，清除后用户将无法登录；必须由管理员在“编辑资料与密码”中补充邮箱并重新设置用户中心密码。"
          : canEmail
            ? "邮箱验证码已启用；账号处于启用状态时可使用关联邮箱接收验证码登录，也可由管理员重新设置密码。"
            : "邮箱验证码未启用，清除后用户将无法登录，必须由管理员在“编辑资料与密码”中重新设置用户中心密码才能恢复邮箱账号登录。") +
        (user.value?.status === "disabled"
          ? "该用户已停用，恢复登录还需要先启用用户。"
          : ""),
      "清除用户中心密码",
      { action: "清除用户中心密码", danger: true },
    );
    selected.check();
    selected.commit(
      await patch(`/users/${selected.id}`, { portal_password: "" }),
    );
  });
}
</script>
<template>
  <page-heading
    managed-actions
    :title="String(user?.name || '用户详情')"
    :description="String(user?.email || '尚未填写邮箱')"
  >
    <template #status>
      <status-badge v-if="user" :value="user.status" />
    </template><action-menu>
      <el-button
        :disabled="!detail.ready.value || task.busy.value"
        @click="
          task.error.value = '';
          editing = true;
        "
      >
        编辑资料与密码
      </el-button><el-button
        v-if="user?.has_portal_password"
        :disabled="!detail.ready.value || task.busy.value"
        @click="clearPassword"
      >
        清除用户中心密码
      </el-button><el-button
        :type="user?.status === 'active' ? 'danger' : 'primary'"
        :disabled="!detail.ready.value || task.busy.value"
        @click="toggle"
      >
        {{ user?.status === "active" ? "停用用户" : "启用用户" }}
      </el-button>
    </action-menu>
  </page-heading>
  <el-skeleton
    v-if="detail.loading.value && !user"
    :rows="5"
    animated
    aria-label="正在加载资料"
  />
  <request-notice :error="detail.error.value" @retry="load()" />
  <request-notice v-if="!editing" :error="task.error.value" />
  <request-notice
    :error="licenses.error.value || devices.error.value || logs.error.value"
    @retry="reloadLists"
  />
  <section-panel v-if="user">
    <key-value-list :column="1" border>
      <key-value-item label="用户中心密码">
        {{ user.has_portal_password ? "已设置" : "未设置" }}
      </key-value-item><key-value-item label="备注">
        {{ user.note || "—" }}
      </key-value-item>
    </key-value-list>
  </section-panel>
  <el-tabs>
    <el-tab-pane label="授权">
      <section-panel>
        <div class="panel-heading">
          <h2>名下授权</h2>
          <router-link :to="issueLicenseLocation(undefined, id)"><el-button
            type="primary"
            :disabled="!detail.ready.value || task.busy.value"
          >发放授权</el-button></router-link>
        </div>
        <data-table
          :error="licenses.error.value"
          :row-href="(row) => adminPage(`/licenses/${idText(row.id)}`)"
          :items="licenses.items.value"
          :actions-width="90"
          :actions-fixed="false"
          :loading="licenses.loading.value"
          :columns="[
            { key: 'key', title: '授权码', width: 260 },
            { key: 'status', title: '状态', state: true, width: 88 },
            { key: 'expires_at', title: '到期时间', date: true, width: 150 },
          ]"
        /><list-pager
          v-model:page="licenses.page.value"
          v-model:size="licenses.size.value"
          :total="licenses.total.value"
          @change="licenses.load()"
        />
      </section-panel>
    </el-tab-pane><el-tab-pane label="实例">
      <section-panel>
        <h2>用户运行实例</h2>
        <data-table
          :error="devices.error.value"
          :items="displayDevices"
          :loading="devices.loading.value"
          :columns="[
            { key: 'hostname', title: '实例名称', width: 90 },
            { key: 'license_key', title: '授权码', mono: true, width: 190 },
            { key: 'instance_id', title: '实例 ID', mono: true, width: 144 },
            { key: 'os', title: '系统', width: 82 },
            { key: 'status', title: '状态', state: true, width: 88 },
            { key: 'last_seen_at', title: '最近在线', date: true, width: 128 },
          ]"
        /><list-pager
          v-model:page="devices.page.value"
          v-model:size="devices.size.value"
          :total="devices.total.value"
          @change="devices.load()"
        />
      </section-panel>
    </el-tab-pane><el-tab-pane label="验证记录">
      <section-panel>
        <h2>最近验证记录</h2>
        <data-table
          :error="logs.error.value"
          :items="logs.items.value"
          :loading="logs.loading.value"
          :columns="[
            {
              key: 'created_at',
              title: '时间',
              date: true,
              seconds: true,
              width: 160,
            },
            { key: 'license_key', title: '授权码', mono: true, width: 210 },
            { key: 'action', title: '操作', enum: true, width: 80 },
            { key: 'code', title: '结果', enum: true, width: 120 },
            { key: 'ip', title: '来源IP', width: 114 },
          ]"
        /><list-pager
          v-model:page="logs.page.value"
          v-model:size="logs.size.value"
          :total="logs.total.value"
          @change="logs.load()"
        />
      </section-panel>
    </el-tab-pane>
  </el-tabs>
  <focus-overlay
    v-model="editing"
    drawer
    title="编辑用户资料与用户中心密码"
    size="560px"
    destroy-on-close
  >
    <request-notice :error="task.error.value" />
    <schema-editor
      :fields="specs.users!.fields"
      :initial="user"
      editing
      :busy="task.busy.value"
      @save="save"
      @cancel="editing = false"
    />
  </focus-overlay>
</template>
