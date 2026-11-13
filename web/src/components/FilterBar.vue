<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { Field } from "../lib/schema";
import type { Row } from "../lib/json";
import ResourceSelect from "./ResourceSelect.vue";
const props = withDefaults(
  defineProps<{
    modelValue: Row;
    fields?: Field[];
    search?: boolean;
    busy?: boolean;
    searchPlaceholder?: string;
  }>(),
  { search: true, fields: () => [], searchPlaceholder: "输入关键字" },
);
const emit = defineEmits<{ "update:modelValue": [value: Row]; search: [] }>();
const active = computed(() =>
  Object.values(props.modelValue).some((v) => v !== "" && v != null),
);
const advancedOpen = ref(false);
const advancedFields = computed(() =>
  (props.fields || []).filter((f) => f.advanced),
);
const activeAdvanced = computed(() =>
  advancedFields.value.filter((f) => {
    const value = props.modelValue[f.key];
    return value !== "" && value !== undefined && value !== null;
  }),
);
watch(
  () => [props.modelValue, props.fields],
  () => {
    if (activeAdvanced.value.length) advancedOpen.value = true;
  },
  { deep: true, immediate: true },
);
const set = (key: string, value: unknown) =>
  emit("update:modelValue", { ...props.modelValue, [key]: value });
function reset() {
  advancedOpen.value = false;
  emit("update:modelValue", {});
  emit("search");
}
</script>
<template>
  <form class="filter-bar" role="search" @submit.prevent="emit('search')">
    <label
      v-if="search !== false"
      class="query-field query-search"
    ><span>关键字</span><el-input
      :model-value="String(modelValue.q || '')"
      :placeholder="searchPlaceholder || '输入关键字'"
      clearable
      maxlength="128"
      @update:model-value="set('q', $event)"
    /></label>
    <template v-for="advanced in [false, true]" :key="String(advanced)">
      <div
        v-if="!advanced || advancedOpen"
        :class="advanced ? 'advanced-filters' : 'basic-filters'"
        :aria-label="advanced ? '更多筛选条件' : undefined"
      >
        <label
          v-for="f in (fields || []).filter((f) => !!f.advanced === advanced)"
          :key="f.key"
          :data-filter="f.key"
          class="query-field"
        ><span>{{ f.label }}</span>
          <resource-select
            v-if="f.type === 'resource'"
            :model-value="String(modelValue[f.key] || '')"
            :endpoint="f.resource!"
            @update:model-value="set(f.key, $event)"
          />
          <el-select
            v-else-if="f.type === 'select'"
            :model-value="String(modelValue[f.key] ?? '')"
            clearable
            placeholder="全部"
            @update:model-value="set(f.key, $event)"
          ><el-option
            v-for="o in f.options?.filter((o) => o.value)"
            :key="o.value"
            :value="o.value"
            :label="o.label"
          /></el-select>
          <el-date-picker
            v-else-if="f.type === 'date'"
            :model-value="String(modelValue[f.key] || '')"
            type="datetime"
            value-format="YYYY-MM-DDTHH:mm:ssZ"
            placeholder="选择时间"
            @update:model-value="set(f.key, $event)"
          />
          <el-input
            v-else
            :model-value="String(modelValue[f.key] || '')"
            clearable
            @update:model-value="set(f.key, $event)"
          />
        </label>
      </div>
    </template>
    <div class="query-buttons">
      <el-button native-type="submit" type="primary" :loading="busy">
        查询
      </el-button><el-button v-if="active" @click="reset">
        清除筛选
      </el-button>
      <el-button
        v-if="advancedFields.length"
        :aria-expanded="advancedOpen"
        @click="advancedOpen = !advancedOpen"
      >
        {{ advancedOpen ? "收起更多筛选" : "更多筛选"
        }}{{ activeAdvanced.length ? `（${activeAdvanced.length}）` : "" }}
      </el-button>
      <slot name="actions" />
    </div>
  </form>
</template>
