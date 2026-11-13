<script setup lang="ts">
import { ref } from "vue";
import ResourceSelect from "./ResourceSelect.vue";
import { post } from "../lib/http";
import { idText } from "../lib/json";
import { useTask } from "../composables/tasks";
defineProps<{ modelValue: string }>();
const emit = defineEmits<{ "update:modelValue": [string] }>();
const task = useTask();
const creating = ref(false),
  name = ref(""),
  serial = ref(0);
async function create() {
  await task.run(async () => {
    if (!name.value.trim()) throw new Error("请填写姓名");
    const user = await post("/users", { name: name.value.trim() });
    serial.value++;
    emit("update:modelValue", idText(user.id));
    name.value = "";
    creating.value = false;
  });
}
</script>
<template>
  <div class="user-select">
    <resource-select
      :key="serial"
      :model-value="modelValue"
      endpoint="/users"
      placeholder="搜索用户姓名或邮箱"
      @update:model-value="emit('update:modelValue', $event)"
    />
    <el-button
      v-if="!creating"
      link
      type="primary"
      @click="creating = true"
    >
      就地新建用户
    </el-button>
    <div v-if="creating" class="inline-user">
      <el-input
        v-model="name"
        placeholder="新用户姓名"
        aria-label="新用户姓名"
        maxlength="128"
        @keydown.enter.prevent="create"
      />
      <el-button type="primary" :loading="task.busy.value" @click="create">
        创建并选择
      </el-button><el-button @click="creating = false">
        取消
      </el-button>
    </div>
    <el-alert
      v-if="task.error.value"
      :title="task.error.value"
      type="error"
      :closable="false"
    />
  </div>
</template>
