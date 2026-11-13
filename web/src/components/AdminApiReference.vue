<script setup lang="ts">
import { computed } from "vue";
import { apiGroups } from "../lib/openapi";
import { type Row } from "../lib/json";
const props = defineProps<{ spec: Row }>();
const groups = computed(() => apiGroups(props.spec));
</script>
<template>
  <div class="admin-api-reference document-body">
    <p>
      按标签和路径查阅接口。点击接口查看参数与响应；接口使用当前管理员身份和后台路径。
    </p>
    <section v-for="group in groups" :key="group.tag" class="api-group">
      <h2>{{ group.tag }}</h2>
      <details
        v-for="operation in group.operations"
        :key="operation.id"
        class="api-operation"
      >
        <summary>
          <span class="api-method" :data-method="operation.method">
            {{ operation.method }}
          </span>
          <code>{{ operation.path }}</code>
          <span>{{ operation.summary }}</span>
        </summary>
        <div class="api-operation-body">
          <p v-if="operation.description">
            {{ operation.description }}
          </p>
          <h3>请求参数</h3>
          <div
            v-if="operation.fields.length"
            class="document-table"
            tabindex="0"
            role="region"
            aria-label="请求参数表格"
          >
            <table>
              <thead>
                <tr>
                  <th>字段</th>
                  <th>位置</th>
                  <th>必填</th>
                  <th>类型</th>
                  <th>说明</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="field in operation.fields"
                  :key="`${field.location}:${field.name}`"
                >
                  <td>
                    <code>{{ field.name }}</code>
                  </td>
                  <td>{{ field.location }}</td>
                  <td>{{ field.required ? "是" : "否" }}</td>
                  <td>{{ field.type }}</td>
                  <td>{{ field.description }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p v-else>
            无需额外参数。
          </p>
          <h3>响应</h3>
          <div
            class="document-table"
            tabindex="0"
            role="region"
            aria-label="响应状态表格"
          >
            <table>
              <thead>
                <tr>
                  <th>状态码</th>
                  <th>说明</th>
                  <th>类型</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="response in operation.responses"
                  :key="response.status"
                >
                  <td>{{ response.status }}</td>
                  <td>{{ response.description }}</td>
                  <td>{{ response.type }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </details>
    </section>
  </div>
</template>
