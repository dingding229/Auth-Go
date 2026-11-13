<script setup lang="ts">
withDefaults(
  defineProps<{
    total: number;
    page: number;
    size: number;
    sizes?: number[];
  }>(),
  { sizes: () => [20, 50, 100] },
);
const emit = defineEmits<{
  "update:page": [value: number];
  "update:size": [value: number];
  change: [];
}>();
function changePage(v: number) {
  emit("update:page", v);
  emit("change");
}
function changeSize(v: number) {
  emit("update:size", v);
  emit("update:page", 1);
  emit("change");
}
</script>
<template>
  <div v-if="Number(total) > 0" class="list-pager">
    <el-pagination
      :total="total"
      :current-page="page"
      :page-size="size"
      :page-sizes="sizes"
      layout="total, sizes, prev, pager, next"
      @current-change="changePage"
      @size-change="changeSize"
    />
  </div>
</template>
