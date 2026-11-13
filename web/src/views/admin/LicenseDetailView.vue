<script setup lang="ts">
import NumberInput from "../../components/NumberInput.vue";
import FocusOverlay from "../../components/FocusOverlay.vue";
import { adminPage } from "../../lib/runtime";
import TrialDetails from "../../components/TrialDetails.vue";
import LicenseSharing from "../../components/LicenseSharing.vue";
import RequestNotice from "../../components/RequestNotice.vue";
import KeyValueItem from "../../components/KeyValueItem.vue";
import KeyValueList from "../../components/KeyValueList.vue";
import SectionPanel from "../../components/SectionPanel.vue";
import { computed, watch, reactive, ref, onBeforeUnmount } from "vue";
import { useRoute } from "vue-router";
import { get, post, patch } from "../../lib/http";
import {
  dateText,
  idText,
  text,
  rows,
  type Row,
  type Page,
} from "../../lib/json";
import {
  activationQuota,
  effectiveDays,
  instanceOnline,
} from "../../lib/presentation";
import { maintenanceText, renewalMaintenance } from "../../lib/maintenance";
import { label } from "../../lib/labels";
import { useTask, confirmAction } from "../../composables/tasks";
import { useAdminDetail } from "../../composables/admin-detail";
import { useCollection } from "../../composables/collection";
import { logColumns } from "../../lib/schema";
import SchemaEditor from "../../components/SchemaEditor.vue";
import { field } from "../../lib/schema";
import ActionMenu from "../../components/ActionMenu";
import PageHeading from "../../components/PageHeading.vue";
import CopyField from "../../components/CopyField.vue";
import StatusBadge from "../../components/StatusBadge.vue";
import JsonBlock from "../../components/JsonBlock.vue";
import DataTable from "../../components/DataTable.vue";
import ListPager from "../../components/ListPager.vue";
const route = useRoute(),
  task = useTask(),
  value = ref<Row>(),
  id = computed(() => String(route.params.id));
const logs = useCollection("/verify-logs", () => ({ license_id: id.value }));
let bindingRequest: AbortController | undefined;
const activations = {
  items: ref<Row[]>([]),
  loading: ref(false),
  error: ref(""),
  hasLoaded: ref(false),
  load: loadBindings,
};
async function loadBindings() {
  bindingRequest?.abort();
  const current = new AbortController();
  bindingRequest = current;
  activations.loading.value = true;
  activations.error.value = "";
  const collected: Row[] = [];
  try {
    for (let page = 1; ; page++) {
      const data = await get<Page>(
        `/licenses/${id.value}/activations`,
        { page, page_size: 100 },
        { signal: current.signal },
      );
      const chunk = rows(data.items);
      collected.push(...chunk);
      if (!chunk.length || collected.length >= Number(data.total)) break;
    }
    if (!current.signal.aborted) {
      activations.items.value = collected;
      activations.hasLoaded.value = true;
    }
  } catch (error) {
    if (!current.signal.aborted && bindingRequest === current) {
      const message = error instanceof Error ? error.message : "读取失败";
      activations.error.value = activations.hasLoaded.value
        ? `刷新失败，显示上次成功读取的数据：${message}` : message;
    }
  } finally {
    if (bindingRequest === current) activations.loading.value = false;
  }
}
onBeforeUnmount(() => bindingRequest?.abort());
watch(
  id,
  () => {
    activations.items.value = [];
    activations.hasLoaded.value = false;
    void loadBindings();
  },
  { immediate: true },
);
const devicePage = ref(1),
  deviceSize = ref(20),
  keyPage = ref(1),
  keySize = ref(20);
const boundDevices = computed(() =>
  activations.items.value
    .filter((row) => row.kind === "floating")
    .map((row) => ({
      ...row,
      online_status: instanceOnline(row) ? "online" : "offline_instance",
    })),
);
const keyActivations = computed(() =>
  activations.items.value
    .filter((row) => row.kind === "key")
    .map((row) => ({ ...row, online_status: row.status })),
);
watch([() => boundDevices.value.length, deviceSize], () => {
  devicePage.value = Math.max(
    1,
    Math.min(
      devicePage.value,
      Math.ceil(boundDevices.value.length / deviceSize.value),
    ),
  );
});
watch([() => keyActivations.value.length, keySize], () => {
  keyPage.value = Math.max(
    1,
    Math.min(
      keyPage.value,
      Math.ceil(keyActivations.value.length / keySize.value),
    ),
  );
});
const detailActivationColumns = [
  { key: "instance_id", title: "实例 ID", mono: true, width: 168 },
  { key: "hostname", title: "实例名称", width: 112 },
  { key: "created_at", title: "首次心跳", date: true, width: 144 },
  { key: "os", title: "系统", width: 80 },
  { key: "online_status", title: "状态", state: true, width: 88 },
  { key: "last_ip", title: "最近IP", mono: true, width: 120 },
  { key: "last_seen_at", title: "最近心跳", date: true, width: 144 },
];
const maintenanceOpen = ref(false),
  maintenanceDays = ref(0);
async function saveMaintenance() {
  await task.run(async () => {
    const selected = detail.capture();
    await post(
      `/licenses/${selected.id}/maintenance`,
      renewalMaintenance(true, maintenanceDays.value),
    );
    selected.commit(await get(`/licenses/${selected.id}`));
    if (!selected.current()) return;
    maintenanceOpen.value = false;
  }, "更新维护期已保存");
}
const renewal = reactive({
    mode: "days",
    days: 30,
    expires_at: "",
    changeMaintenance: false,
    maintenanceDays: 0,
  }),
  renewOpen = ref(false),
  password = ref(""),
  passwordOpen = ref(false),
  assignmentOpen = ref(false);
const detail = useAdminDetail("/licenses", id, value, () => {
  renewOpen.value = false;
  maintenanceOpen.value = false;
  passwordOpen.value = false;
  assignmentOpen.value = false;
  password.value = "";
  activations.items.value = [];
  logs.items.value = [];
  logs.total.value = 0;
  devicePage.value = 1;
  keyPage.value = 1;
  task.error.value = "";
});
const load = detail.load;
watch([renewOpen, maintenanceOpen, passwordOpen, assignmentOpen], () => {
  task.error.value = "";
});

async function state(action: string) {
  await task.run(async () => {
    const selected = detail.capture();
    await confirmAction(
      action === "revoke"
        ? "吊销后授权无法恢复，所有在线激活将失效。"
        : `确认${action === "suspend" ? "暂停" : "恢复"}这条授权？`,
      action === "revoke" ? "吊销授权" : "授权状态",
      {
        action:
          action === "revoke"
            ? "吊销授权"
            : action === "suspend"
              ? "暂停授权"
              : "恢复授权",
        danger: action === "revoke",
        match:
          action === "revoke"
            ? String(value.value?.key || "").slice(-5)
            : undefined,
      },
    );
    selected.check();
    selected.commit(await post(`/licenses/${selected.id}/${action}`, {}));
    if (!selected.current()) return;
    await activations.load();
  }, "授权状态已更新");
}
async function renew() {
  await task.run(async () => {
    const selected = detail.capture();
    if (renewal.mode === "date" && !renewal.expires_at)
      throw new Error("请选择新的到期时间");
    const result = await post(`/licenses/${selected.id}/renew`, {
      ...(renewal.mode === "days"
        ? { days: renewal.days }
        : { expires_at: new Date(renewal.expires_at).toISOString() }),
      ...renewalMaintenance(renewal.changeMaintenance, renewal.maintenanceDays),
    });
    selected.commit(result);
    if (!selected.current()) return;
    renewOpen.value = false;
  }, "授权已续期");
}
async function setPassword(clear = false) {
  await task.run(
    async () => {
      const selected = detail.capture();
      if (clear)
        await confirmAction(
          "清除后将不能使用查询密码登录门户。确认继续？",
          "清除查询密码",
          { action: "清除查询密码", danger: true },
        );
      else if (
        new TextEncoder().encode(password.value).length < 8 ||
        new TextEncoder().encode(password.value).length > 72
      )
        throw new Error("查询密码须为8至72字节");
      selected.check();
      await post(`/licenses/${selected.id}/portal-password`, {
        password: clear ? "" : password.value,
      });
      if (!selected.current()) return;
      password.value = "";
      passwordOpen.value = false;
      selected.commit(await get(`/licenses/${selected.id}`));
    },
    clear ? "查询密码已清除" : "查询密码已设置",
  );
}
async function manage(row: Row, action: string) {
  await task.run(async () => {
    const selected = detail.capture();
    await confirmAction(
      action === "release-seat"
        ? "删除此运行实例记录并写入审计，不改变会话凭据；程序下次心跳可能重新竞争席位。"
        : action === "unbind"
          ? "确认停用当前激活？相关会话将失效。"
          : "确认标记下线？相关会话将失效。",
      action === "release-seat" ? "释放席位" : "管理激活",
      {
        action:
          action === "release-seat"
            ? "释放席位"
            : action === "unbind"
              ? "停用激活"
              : "标记下线",
      },
    );
    selected.check();
    await post(`/activations/${idText(row.id)}/${action}`, {});
    if (!selected.current()) return;
    await activations.load();
    selected.commit(await get(`/licenses/${selected.id}`));
  }, "实例或激活状态已更新");
}
async function saveAssignment(body: Row) {
  await task.run(async () => {
    const selected = detail.capture();
    const result = await patch(`/licenses/${selected.id}`, {
      user_id: body.user_id || null,
    });
    selected.commit(result);
    if (!selected.current()) return;
    assignmentOpen.value = false;
  }, "授权归属已更新");
}
</script>
<template>
  <page-heading managed-actions :title="String(value?.key || '授权详情')" copy>
    <template #status>
      <status-badge v-if="value" :value="value.status" />
    </template>
    <template v-if="value" #description>
      {{
        value.validity_rule === "perpetual"
          ? "永久有效"
          : `到期时间：${dateText(value.expires_at)}`
      }}
      · 授权编号 {{ idText(value.id) }} · {{ label(value.type) }}
    </template>
    <el-button
      :disabled="!detail.ready.value || task.busy.value || !value"
      @click="assignmentOpen = true"
    >
      {{ value?.user_id ? "更改用户" : "分配用户" }}
    </el-button>
    <action-menu :limit="0" static>
      <el-button :loading="task.busy.value" @click="load">
        刷新
      </el-button><template v-if="value && value.status !== 'revoked'">
        <el-button
          :disabled="!detail.ready.value || task.busy.value"
          @click="maintenanceOpen = true"
        >
          修改维护期
        </el-button>
        <el-button
          v-if="value.validity_rule !== 'perpetual'"
          type="primary"
          :disabled="!detail.ready.value || task.busy.value"
          @click="renewOpen = true"
        >
          续期
        </el-button><el-button
          v-if="value.status === 'suspended'"
          :disabled="!detail.ready.value || task.busy.value"
          @click="state('resume')"
        >
          恢复
        </el-button><el-button
          v-else
          :disabled="!detail.ready.value || task.busy.value"
          @click="state('suspend')"
        >
          暂停
        </el-button><el-button
          :disabled="!detail.ready.value || task.busy.value"
          @click="passwordOpen = true"
        >
          授权查询密码
        </el-button><el-button
          type="danger"
          plain
          :disabled="!detail.ready.value || task.busy.value"
          @click="state('revoke')"
        >
          吊销授权
        </el-button>
      </template>
    </action-menu>
  </page-heading>
  <trial-details
    v-if="value?.source === 'self_trial'"
    :id="id"
    :is-trial="value.type === 'trial'"
    :converted-at="value.converted_at"
    @changed="load"
  />
  <el-skeleton
    v-if="detail.loading.value && !value"
    :rows="5"
    animated
    aria-label="正在加载资料"
  /><request-notice :error="detail.error.value" @retry="load()" />
  <request-notice
    v-if="!renewOpen && !maintenanceOpen && !passwordOpen && !assignmentOpen"
    :error="task.error.value"
  />
  <template v-if="value">
    <el-tabs>
      <el-tab-pane label="概览">
        <section-panel>
          <key-value-list :column="2" border>
            <key-value-item label="用户">
              <router-link
                v-if="value.user_id"
                :to="adminPage(`/users/${idText(value.user_id)}`)"
              >{{ value.user_name || "查看用户" }}</router-link><span v-else>未分配</span>
            </key-value-item><key-value-item label="软件">
              <router-link
                :to="adminPage(`/applications/${idText(value.app_id)}`)"
              >{{ value.app_name || "—" }}</router-link>
            </key-value-item><key-value-item label="验证方式">
              {{
                (value.verify_methods as string[]).map(label).join("、")
              }}
            </key-value-item><key-value-item label="组合规则">
              {{ label(value.match_mode) }}
            </key-value-item><key-value-item label="有效期规则">
              {{ label(value.validity_rule) }}
            </key-value-item><key-value-item label="有效天数">
              {{ effectiveDays(value) }}
            </key-value-item><key-value-item label="开始时间">
              {{ dateText(value.starts_at) }}
            </key-value-item><key-value-item label="更新维护期">
              {{ maintenanceText(value.maintenance_until) }}
            </key-value-item><key-value-item label="到期时间">
              {{ dateText(value.expires_at) }}
            </key-value-item><key-value-item
              :label="
                (value.verify_methods as string[]).includes('FLOATING')
                  ? '同时运行实例数'
                  : '最大激活数'
              "
            >
              {{ activationQuota(value, true) }}
            </key-value-item><key-value-item label="查询密码">
              {{
                value.has_portal_password ? "已设置" : "未设置"
              }}
            </key-value-item><key-value-item label="备注" :span="2">
              {{ text(value.note) }}
            </key-value-item>
          </key-value-list><json-block :value="value.features" title="授权功能项" /><json-block
            :value="value.metadata"
            title="扩展数据"
          />
        </section-panel>
        <license-sharing :key="id" :license-id="id" />
      </el-tab-pane>
      <el-tab-pane label="实例">
        <section-panel>
          <request-notice
            :error="activations.error.value"
            @retry="activations.load()"
          /><data-table
            v-if="boundDevices.length || !keyActivations.length"
            :items="
              boundDevices.slice(
                (devicePage - 1) * deviceSize,
                devicePage * deviceSize,
              )
            "
            empty="还没有运行实例"
            :columns="detailActivationColumns"
            :actions-width="208"
            :loading="activations.loading.value"
          >
            <template #cell-instance_id="{ row }">
              <copy-field
                :value="row.instance_id"
                label="实例 ID"
                compact
                :expandable="false"
              />
            </template>
            <template #actions="{ row }">
              <el-button
                v-if="row.kind === 'floating' && row.status === 'active'"
                link
                :disabled="!detail.ready.value || task.busy.value"
                @click.stop="manage(row, 'release-seat')"
              >
                释放席位
              </el-button>
              <template v-else-if="row.status === 'active'">
                <el-button
                  link
                  type="warning"
                  :disabled="!detail.ready.value || task.busy.value"
                  @click.stop="manage(row, 'offline')"
                >
                  标记下线
                </el-button><el-button
                  link
                  type="danger"
                  :disabled="!detail.ready.value || task.busy.value"
                  @click.stop="manage(row, 'unbind')"
                >
                  停用激活
                </el-button>
              </template><span v-else class="muted">无可用操作</span>
            </template>
          </data-table>
          <list-pager
            v-if="boundDevices.length"
            v-model:page="devicePage"
            v-model:size="deviceSize"
            :total="boundDevices.length"
          />
          <details
            :class="
              boundDevices.length ? 'technical-options' : 'activation-section'
            "
            :open="
              activations.items.value.length > 0 &&
                activations.items.value.every((row) => row.kind === 'key')
            "
          >
            <summary>激活</summary>
            <data-table
              :items="
                keyActivations.slice((keyPage - 1) * keySize, keyPage * keySize)
              "
              empty="还没有授权码激活"
              :columns="detailActivationColumns"
              :actions-width="208"
              :loading="activations.loading.value"
            >
              <template #cell-instance_id="{ row }">
                <copy-field
                  :value="row.instance_id"
                  label="实例 ID"
                  compact
                  :expandable="false"
                />
              </template>
              <template #actions="{ row }">
                <el-button
                  v-if="row.kind === 'floating' && row.status === 'active'"
                  link
                  :disabled="!detail.ready.value || task.busy.value"
                  @click.stop="manage(row, 'release-seat')"
                >
                  释放席位
                </el-button>
                <template v-else-if="row.status === 'active'">
                  <el-button
                    link
                    type="warning"
                    :disabled="!detail.ready.value || task.busy.value"
                    @click.stop="manage(row, 'offline')"
                  >
                    标记下线
                  </el-button><el-button
                    link
                    type="danger"
                    :disabled="!detail.ready.value || task.busy.value"
                    @click.stop="manage(row, 'unbind')"
                  >
                    停用激活
                  </el-button>
                </template><span v-else class="muted">无可用操作</span>
              </template>
            </data-table>
            <list-pager
              v-if="keyActivations.length"
              v-model:page="keyPage"
              v-model:size="keySize"
              :total="keyActivations.length"
            />
          </details>
        </section-panel>
      </el-tab-pane>
      <el-tab-pane label="用户中心">
        <section-panel title="授权查询与用户中心">
          <p>
            用户可使用授权码与查询密码登录；分配给用户后，也可通过用户账号查询。
          </p>
          <el-button
            :disabled="!detail.ready.value || task.busy.value"
            @click="passwordOpen = true"
          >
            设置授权查询密码
          </el-button><router-link
            to="/portal/login"
            target="_blank"
          ><el-button :disabled="!detail.ready.value || task.busy.value">打开用户中心</el-button></router-link>
        </section-panel>
      </el-tab-pane><el-tab-pane label="验证记录">
        <section-panel>
          <request-notice
            :error="logs.error.value"
            @retry="logs.load()"
          /><data-table
            :error="logs.error.value"
            :items="logs.items.value"
            :columns="logColumns"
            :loading="logs.loading.value"
          /><list-pager
            v-model:page="logs.page.value"
            v-model:size="logs.size.value"
            :total="logs.total.value"
            @change="logs.load()"
          />
        </section-panel>
      </el-tab-pane>
    </el-tabs>
  </template>
  <focus-overlay
    v-model="assignmentOpen"
    drawer
    :title="value?.user_id ? '更改用户' : '分配用户'"
    size="560px"
    destroy-on-close
  >
    <request-notice :error="task.error.value" />
    <schema-editor
      v-if="value"
      :fields="[
        field('user_id', '发给谁', {
          type: 'user',
          nullable: true,
          hint: '留空表示未分配库存授权；改分配后原用户将失去此授权的用户中心访问权。',
        }),
      ]"
      :initial="{ user_id: value.user_id }"
      :busy="task.busy.value"
      @save="saveAssignment"
      @cancel="assignmentOpen = false"
    />
  </focus-overlay>
  <focus-overlay
    v-model="renewOpen"
    title="续期授权"
    width="480px"
    :close-on-click-modal="false"
    @closed="renewal.changeMaintenance = false"
  >
    <el-form label-position="top" @submit.prevent="renew">
      <request-notice :error="task.error.value" />
      <el-form-item label="续期方式">
        <el-radio-group v-model="renewal.mode">
          <el-radio-button value="days">
            延长天数
          </el-radio-button><el-radio-button value="date">
            新到期时间
          </el-radio-button>
        </el-radio-group>
      </el-form-item><el-form-item v-if="renewal.mode === 'days'" label="延长天数">
        <number-input
          v-model="renewal.days"
          :min="1"
          :max="36500"
          :precision="0"
        />
      </el-form-item><el-form-item v-else label="新的到期时间">
        <el-date-picker
          v-model="renewal.expires_at"
          type="datetime"
          value-format="YYYY-MM-DDTHH:mm:ssZ"
        />
      </el-form-item>
      <el-form-item label="更新维护期">
        <el-checkbox v-model="renewal.changeMaintenance">
          同时修改更新维护期
        </el-checkbox>
        <p class="field-hint">
          默认不变，不随授权续期自动延长。
        </p>
      </el-form-item>
      <el-form-item
        v-if="renewal.changeMaintenance"
        label="维护天数（从现在计算）"
      >
        <number-input
          v-model="renewal.maintenanceDays"
          :min="0"
          :max="36500"
          :precision="0"
        />
        <p class="field-hint">
          0表示不限。
        </p>
      </el-form-item>
      <el-button
        type="primary"
        native-type="submit"
        :loading="task.busy.value"
        :disabled="!detail.ready.value || task.busy.value"
      >
        确认续期
      </el-button>
    </el-form>
  </focus-overlay>
  <focus-overlay
    v-model="maintenanceOpen"
    title="修改更新维护期"
    width="480px"
    :close-on-click-modal="false"
  >
    <el-form label-position="top" @submit.prevent="saveMaintenance">
      <request-notice :error="task.error.value" />
      <p>当前维护期：{{ maintenanceText(value?.maintenance_until) }}</p>
      <el-form-item label="维护天数（从现在计算）">
        <number-input
          v-model="maintenanceDays"
          :min="0"
          :max="36500"
          :precision="0"
        />
        <p class="field-hint">
          0表示不限。不会改变授权到期时间。
        </p>
      </el-form-item>
      <el-button
        native-type="submit"
        type="primary"
        :loading="task.busy.value"
        :disabled="!detail.ready.value || task.busy.value"
      >
        保存维护期
      </el-button>
    </el-form>
  </focus-overlay>
  <focus-overlay
    v-model="passwordOpen"
    title="授权查询密码"
    width="480px"
    @closed="password = ''"
  >
    <el-form label-position="top" @submit.prevent="setPassword()">
      <request-notice :error="task.error.value" />
      <el-form-item label="新查询密码（8–72字节）">
        <el-input
          v-model="password"
          type="password"
          show-password
          autocomplete="new-password"
        />
      </el-form-item><el-button
        type="primary"
        native-type="submit"
        :loading="task.busy.value"
        :disabled="!detail.ready.value || task.busy.value"
      >
        保存新密码
      </el-button><el-button
        v-if="value?.has_portal_password"
        type="danger"
        plain
        :disabled="!detail.ready.value || task.busy.value"
        @click="setPassword(true)"
      >
        清除查询密码
      </el-button>
    </el-form>
  </focus-overlay>
</template>
