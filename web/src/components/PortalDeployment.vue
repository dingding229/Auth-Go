<script setup lang="ts">
import { computed } from "vue";
import { record } from "../lib/json";
import CopyField from "./CopyField.vue";
import ProtocolDocument from "./ProtocolDocument.vue";
const props = defineProps<{ value: unknown }>();
const deployment = computed(() => record(props.value));
</script>
<template>
  <section class="portal-deployment">
    <el-alert
      v-if="deployment.available !== true"
      :title="
        String(
          deployment.reason || '当前没有可用的部署配置，请联系软件提供方。',
        )
      "
      type="info"
      :closable="false"
    />
    <template v-else>
      <h2>docker-compose.yml</h2>
      <p class="warning-text">
        配置内含你的授权码，请妥善保管，不要转发到公开渠道。
      </p>
      <copy-field
        :value="deployment.compose"
        label="docker-compose.yml"
        sensitive
      />
      <p class="field-hint">
        {{
          deployment.ports_hint ||
            "如程序需要对外提供服务，请按软件文档添加 ports"
        }}
      </p>
      <h2>部署步骤</h2>
      <ol class="portal-deploy-steps">
        <li
          v-for="step in Array.isArray(deployment.steps)
            ? deployment.steps
            : []"
          :key="String(step)"
        >
          <copy-field :value="step" label="部署命令" />
        </li>
      </ol>
      <h2>常见问题与运行说明</h2>
      <protocol-document :content="String(deployment.guide || '')" />
    </template>
  </section>
</template>
