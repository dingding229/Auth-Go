<script setup lang="ts">
import { RouterLink } from "vue-router";
import { computed, useSlots } from "vue";
import { dateText, text, idText, type Row } from "../lib/json";
import { label } from "../lib/labels";
import IpInfo from "./IpInfo.vue";
import StatusBadge from "./StatusBadge.vue";
import ActionMenu from "./ActionMenu";
export interface Column {
  key: string;
  title: string;
  width?: number;
  date?: boolean;
  seconds?: boolean;
  state?: boolean;
  enum?: boolean;
  mono?: boolean;
}
const props = withDefaults(
  defineProps<{
    items: Row[];
    columns: Column[];
    loading?: boolean;
    error?: string;
    empty?: string;
    filtered?: boolean;
    emptyAction?: string;
    actionsWidth?: number;
    actionsFixed?: boolean;
    rowHref?: (row: Row) => string;
    clickable?: boolean;
  }>(),
  {
    actionsWidth: 112,
    actionsFixed: false,
    empty: "",
    error: "",
    emptyAction: "",
    rowHref: undefined,
  },
);
const emit = defineEmits<{ select: [row: Row]; clear: []; emptyAction: [] }>();
const slots = useSlots();
const emptyText = computed(() =>
  props.filtered ? "没有符合条件的记录" : props.empty || "还没有可显示的记录",
);
const rowKey = (r: Row) =>
  idText(
    r.id ?? r.row ?? r.day ?? r.uid ?? r.key ?? r.name ?? r.domain ?? r.code,
  );
function isMono(col: Column) {
  return (
    col.mono || /(^|_)(key|token|fingerprint|ip|version|config)$/.test(col.key)
  );
}
function display(row: Row, col: Column) {
  return col.date
    ? dateText(row[col.key], col.seconds)
    : col.enum
      ? label(row[col.key])
      : text(row[col.key]);
}
function expiry(row: Row, col: Column) {
  if (col.key !== "expires_at" || !row[col.key]) return "";
  const left = new Date(String(row[col.key])).getTime() - Date.now();
  return left < 0 ? "is-expired" : left < 7 * 86400000 ? "is-soon" : "";
}
function pick(row: Row, _column: unknown, event: MouseEvent) {
  // Inline controls own their interaction, including native clicks emitted by
  // switches and controls supplied through cell slots.
  if (
    (event.target as Element | null)?.closest(
      "button,a,input,select,textarea,[role=button],[role=switch],[role=checkbox],.row-actions,.el-switch",
    )
  )
    return;
  if (props.clickable) emit("select", row);
}
</script>
<template>
  <div class="data-table" :aria-busy="loading">
    <el-skeleton
      v-if="loading && !items.length"
      :rows="4"
      animated
      aria-label="正在加载记录"
    />
    <div v-else-if="!items.length && !error" class="table-empty" role="status">
      <p>{{ emptyText }}</p>
      <el-button
        v-if="filtered"
        text
        type="primary"
        @click="emit('clear')"
      >
        清除筛选
      </el-button><el-button
        v-else-if="emptyAction"
        type="primary"
        @click="emit('emptyAction')"
      >
        {{ emptyAction }}
      </el-button><slot name="empty" />
    </div>
    <template v-else-if="items.length">
      <div class="table-scroll">
        <el-table :data="items" :row-key="rowKey" @row-click="pick">
          <el-table-column
            v-for="(col, index) in columns"
            :key="col.key"
            :prop="col.key"
            :label="col.title"
            :min-width="col.width || 100"
            show-overflow-tooltip
          >
            <template #default="{ row }">
              <slot :name="`cell-${col.key}`" :row="row">
                <IpInfo
                  v-if="['ip', 'first_ip', 'last_ip'].includes(col.key)"
                  :ip="row[col.key]"
                  :info="col.key === 'first_ip' ? undefined : row.ip_info"
                  compact
                />
                <RouterLink
                  v-else-if="index === 0 && rowHref"
                  :to="rowHref(row)"
                  :class="{ 'code-value': isMono(col) }"
                >{{ display(row, col) }}</RouterLink><button
                  v-else-if="index === 0 && clickable"
                  class="table-link"
                  :class="{ 'code-value': isMono(col) }"
                  @click.stop="emit('select', row)"
                >
                  {{ display(row, col) }}
                </button><status-badge
                  v-else-if="col.state"
                  :value="row[col.key]"
                /><span
                  v-else
                  :class="[
                    { 'code-value': isMono(col) },
                    col.date ? 'table-date' : '',
                    expiry(row, col),
                  ]"
                >{{ display(row, col) }}</span>
              </slot>
            </template>
          </el-table-column>
          <el-table-column
            v-if="slots.actions"
            label="操作"
            :width="actionsWidth"
            :fixed="actionsFixed ? 'right' : false"
            align="right"
          >
            <template #default="{ row }">
              <action-menu>
                <slot name="actions" :row="row" />
              </action-menu>
            </template>
          </el-table-column>
        </el-table>
      </div>
      <div class="table-cards">
        <article v-for="row in items" :key="rowKey(row)" class="table-card">
          <header class="table-card-title">
            <span
              class="table-card-primary"
              :title="display(row, columns[0]!)"
            ><slot :name="`cell-${columns[0]!.key}`" :row="row">
              <IpInfo
                v-if="['ip', 'first_ip', 'last_ip'].includes(columns[0]!.key)"
                :ip="row[columns[0]!.key]"
                :info="
                  columns[0]!.key === 'first_ip' ? undefined : row.ip_info
                "
              />
              <RouterLink
                v-else-if="rowHref"
                :to="rowHref(row)"
                :class="{ 'code-value': isMono(columns[0]!) }"
              >{{ display(row, columns[0]!) }}</RouterLink>
              <button
                v-else-if="clickable"
                class="table-link"
                @click="emit('select', row)"
              >
                {{ display(row, columns[0]!) }}
              </button>
              <span v-else :class="{ 'code-value': isMono(columns[0]!) }">{{
                display(row, columns[0]!)
              }}</span>
            </slot></span>
            <template
              v-for="col in columns.filter((c) => c.state)"
              :key="col.key"
            >
              <slot :name="`cell-${col.key}`" :row="row">
                <status-badge :value="row[col.key]" />
              </slot>
            </template>
            <action-menu v-if="slots.actions" mobile>
              <slot name="actions" :row="row" />
            </action-menu>
          </header>
          <dl class="table-card-fields">
            <div
              v-for="col in columns.slice(1).filter((c) => !c.state)"
              :key="col.key"
            >
              <dt>{{ col.title }}</dt>
              <dd :title="display(row, col)">
                <slot :name="`cell-${col.key}`" :row="row">
                  <IpInfo
                    v-if="['ip', 'first_ip', 'last_ip'].includes(col.key)"
                    :ip="row[col.key]"
                    :info="col.key === 'first_ip' ? undefined : row.ip_info"
                  />
                  <span
                    v-else
                    :class="[{ 'code-value': isMono(col) }, expiry(row, col)]"
                  >{{ display(row, col) }}</span>
                </slot>
              </dd>
            </div>
          </dl>
        </article>
      </div>
    </template>
  </div>
</template>
