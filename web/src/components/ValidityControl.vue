<script setup lang="ts">
import NumberInput from "./NumberInput.vue";
defineProps<{ rule: string; days: number; expiry: string }>();
const emit = defineEmits<{
  "update:rule": [string];
  "update:days": [number];
  "update:expiry": [string];
}>();
</script>
<template>
  <div class="validity-control" style="width: 100%; min-width: 0">
    <el-select
      style="width: 100%; min-width: 0"
      :model-value="rule"
      aria-label="有效期"
      @update:model-value="emit('update:rule', String($event))"
    >
      <el-option value="perpetual" label="永久有效" /><el-option
        value="fixed_days"
        label="从发放日起N天"
      /><el-option value="fixed_expiry" label="指定到期日期" /><el-option
        value="after_activation"
        label="首次使用后N天"
      />
    </el-select>
    <number-input
      v-if="['fixed_days', 'after_activation'].includes(rule)"
      :model-value="days"
      :min="1"
      :max="36500"
      :precision="0"
      aria-label="有效天数"
      @update:model-value="emit('update:days', Number($event))"
    />
    <el-date-picker
      v-if="rule === 'fixed_expiry'"
      :model-value="expiry"
      type="datetime"
      value-format="YYYY-MM-DDTHH:mm:ssZ"
      placeholder="选择到期时间"
      @update:model-value="emit('update:expiry', String($event || ''))"
    />
  </div>
</template>
