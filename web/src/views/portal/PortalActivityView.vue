<script setup lang="ts">
import { useRoute } from "vue-router";
import { computed } from "vue";
import { useAuth } from "../../stores/auth";
import PageHeading from "../../components/PageHeading.vue";
import SectionPanel from "../../components/SectionPanel.vue";
import PortalRecords from "../../components/PortalRecords.vue";
import PortalView from "./PortalView.vue";
const auth = useAuth(),
  route = useRoute();
const kind = computed(() =>
  route.path.endsWith("/updates") ? "updates" : "announcements",
);
</script>
<template>
  <template v-if="auth.portal.scope === 'user'">
    <page-heading
      :title="kind === 'updates' ? '软件更新' : '公告'"
    /><section-panel>
      <portal-records :key="kind" :kind="kind" />
    </section-panel>
  </template>
  <portal-view v-else />
</template>
