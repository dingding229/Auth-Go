<script setup lang="ts">
import { dateText, type Row } from "../lib/json";
import { instanceUsage } from "../lib/presentation";
withDefaults(defineProps<{ license: Row; quota?: boolean }>(), { quota: true });
</script>
<template>
  <div class="portal-license-facts">
    <p>
      到期时间：{{
        license.expires_at ? dateText(license.expires_at) : "永久或尚未起算"
      }}<span v-if="license.remaining_days != null">
        · 剩余 {{ license.remaining_days }} 天</span>
    </p>
    <p v-if="quota">
      在线实例：{{ instanceUsage(license) }}
      <span class="muted">（在线/上限）</span>
    </p>
    <p v-if="license.type === 'trial'" class="portal-trial">
      试用授权<span v-if="license.trial_remaining_days != null">
        · 剩余 {{ license.trial_remaining_days }} 天</span>
      · 联系提供方转正
    </p>
    <p>
      更新维护期：{{
        license.maintenance_until ? dateText(license.maintenance_until) : "不限"
      }}
    </p>
    <p v-if="license.latest_entitled_version">
      可用版本到
      <span class="code-value">{{ license.latest_entitled_version }}</span>
    </p>
    <p v-if="license.renewal_required" class="warning-text">
      需要续期，请联系软件提供方。
    </p>
  </div>
</template>
