<script setup lang="ts">
import { adminPage } from "../lib/runtime";
import RequestNotice from "./RequestNotice.vue";
import SectionPanel from "./SectionPanel.vue";
import { computed, ref } from "vue";
import { get, patch, post, remove } from "../lib/http";
import { useTask, confirmAction } from "../composables/tasks";
import { useCollection } from "../composables/collection";
import { idText, type Row } from "../lib/json";
import type { Spec } from "../lib/schema";
import DataTable from "./DataTable.vue";
import FormOverlay from "./FormOverlay.vue";
import SchemaEditor from "./SchemaEditor.vue";
import FilterBar from "./FilterBar.vue";
import ListPager from "./ListPager.vue";
const props = defineProps<{
  spec: Spec;
  listPath?: string;
  createPath?: string;
  embedded?: boolean;
  editFromRow?: boolean;
}>();
const emit = defineEmits<{ created: [row: Row] }>();
const path = computed(() => props.listPath || props.spec.path);
const list = useCollection(path),
  task = useTask(),
  editor = ref(false),
  editing = ref(false),
  initial = ref<Row>({});
const sortFields = computed(() => [
  { value: "created_at", label: "创建时间" },
  { value: "id", label: "编号" },
  ...(props.spec.key === "applications"
    ? [{ value: "name", label: "名称" }]
    : []),
]);
function sort(key: string, value: unknown) {
  list.query.value = { ...list.query.value, [key]: value };
  void list.load(true);
}
async function edit(row?: Row) {
  await task.run(async () => {
    initial.value = row
      ? props.editFromRow
        ? { ...row }
        : await get(`${props.spec.path}/${idText(row.id)}`)
      : {};

    editing.value = !!row;
    editor.value = true;
  });
}
async function save(body: Row) {
  await task.run(async () => {
    if (editing.value)
      await patch(`${props.spec.path}/${idText(initial.value.id)}`, body);
    else emit("created", await post(props.createPath || path.value, body));
    editor.value = false;
    await list.load();
  }, "保存成功");
}
async function destroy(row: Row) {
  await task.run(async () => {
    await confirmAction(`删除${props.spec.singular}后无法恢复。`, "删除操作", {
      action: `删除${props.spec.singular}`,
      danger: true,
      match: String(row.name || row.version || row.title || row.id),
    });
    await remove(`${props.spec.path}/${idText(row.id)}`);
    await list.load();
  }, "已删除");
}
defineExpose({ reload: list.load, create: () => edit() });
</script>
<template>
  <section-panel>
    <div
      v-if="embedded || !['users', 'applications'].includes(spec.key)"
      class="panel-heading"
    >
      <div>
        <h2 v-if="embedded">
          {{ spec.title }}
        </h2>
      </div>
      <el-button v-if="embedded" type="primary" @click="edit()">
        新建{{ spec.singular }}
      </el-button>
      <label v-if="!['applications', 'users', 'feature_templates'].includes(spec.key)">排序字段<el-select
        :model-value="String(list.query.value.sort_by || 'created_at')"
        @update:model-value="sort('sort_by', $event)"
      ><el-option
        v-for="item in sortFields"
        :key="item.value"
        :value="item.value"
        :label="item.label"
      /></el-select></label><label v-if="!['applications', 'users', 'feature_templates'].includes(spec.key)">方向<el-select
        :model-value="String(list.query.value.sort_order || 'desc')"
        @update:model-value="sort('sort_order', $event)"
      ><el-option value="desc" label="降序" /><el-option
        value="asc"
        label="升序"
      /></el-select></label>
    </div>
    <filter-bar
      v-model="list.query.value"
      :fields="spec.filters"
      :search="spec.search !== false"
      :busy="list.loading.value"
      @search="list.load(true)"
    />
    <request-notice v-if="!editor" :error="task.error.value" />
    <request-notice :error="list.error.value" @retry="list.load()" />
    <data-table
      :error="list.error.value"
      :row-href="
        ['users', 'applications'].includes(spec.key)
          ? (row) => adminPage(`/${spec.key}/${idText(row.id)}`)
          : undefined
      "
      :empty="`还没有${spec.singular}`"
      :empty-action="`创建${spec.singular}`"
      :filtered="
        Object.values(list.query.value).some((v) => v !== '' && v != null)
      "
      :items="list.items.value"
      :columns="spec.columns"
      :actions-width="144"
      :actions-fixed="spec.key !== 'users'"
      :loading="list.loading.value"
      @empty-action="edit()"
      @clear="
        list.query.value = {};
        list.load(true);
      "
    >
      <template #actions="{ row }">
        <el-button
          v-if="!spec.noEdit"
          link
          type="primary"
          @click="edit(row)"
        >
          编辑
        </el-button>
        <el-button link type="danger" @click="destroy(row)">
          删除
        </el-button>
      </template>
    </data-table>
    <list-pager
      v-model:page="list.page.value"
      v-model:size="list.size.value"
      :total="list.total.value"
      @change="list.load()"
    />
  </section-panel>
  <form-overlay
    v-model="editor"
    :short="spec.fields.length <= 4"
    :title="`${editing ? '编辑' : '新建'}${spec.singular}`"
    size="560px"
    destroy-on-close
    :close-on-click-modal="false"
  >
    <request-notice :error="task.error.value" />
    <schema-editor
      :submit-label="editing ? `保存${spec.singular}` : `创建${spec.singular}`"
      :fields="spec.fields"
      :initial="initial"
      :editing="editing"
      :busy="task.busy.value"
      @save="save"
      @cancel="editor = false"
    />
  </form-overlay>
</template>
