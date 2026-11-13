<script setup lang="ts">
import { computed } from "vue";
import { record, text } from "../lib/json";
const props = withDefaults(
  defineProps<{ ip?: unknown; info?: unknown; compact?: boolean }>(),
  { compact: false, ip: undefined, info: undefined },
);
const details = computed(() => {
  const info = record(props.info);
  const scope =
    info.scope === "private"
      ? "内网"
      : info.scope === "loopback"
        ? "本机"
        : info.scope === "unknown"
          ? "未知"
          : "";
  if (scope) return { location: scope, asn: "", org: "", full: scope };
  let country = typeof info.country === "string" ? info.country : "";
  const code =
    typeof info.country_code === "string"
      ? info.country_code.toUpperCase()
      : "";
  // Unknown region codes must fall back to the name supplied by the server.
  if (/^[A-Z]{2}$/.test(code) && !["ZZ", "XX"].includes(code)) {
    try {
      country =
        new Intl.DisplayNames("zh-CN", { type: "region", fallback: "none" }).of(
          code,
        ) || country;
    } catch {
      /* Keep the supplied country name. */
    }
  }
  const location = [
    ...new Set(
      [country, info.city].filter(
        (v): v is string => typeof v === "string" && v !== "",
      ),
    ),
  ].join(" ");
  const fullLocation = [
    ...new Set(
      [country, info.region, info.city].filter(
        (v): v is string => typeof v === "string" && v !== "",
      ),
    ),
  ].join(" ");
  const number = Number(info.asn);
  const asn = Number.isSafeInteger(number) && number > 0 ? `AS${number}` : "";
  const org = asn && typeof info.as_org === "string" ? info.as_org : "";
  const network = [asn, org].filter(Boolean).join(" ");
  return {
    location,
    asn,
    org,
    full: [fullLocation, network].filter(Boolean).join(" · "),
  };
});
const hasDetails = computed(
  () => !!(details.value.location || details.value.asn),
);
</script>
<template>
  <el-tooltip
    :disabled="!details.full"
    :content="details.full"
    :trigger="['hover', 'focus']"
    placement="top"
    :show-after="250"
  >
    <span
      class="ip-info"
      :class="{ 'ip-info-compact': compact }"
      :tabindex="compact && details.full ? 0 : undefined"
    >
      <span
        class="ip-info-address code-value"
        :title="details.full || undefined"
      >{{ text(ip) }}</span>
      <span v-if="hasDetails" class="ip-info-details" :title="details.full">
        <span v-if="details.location" class="ip-info-location">{{
          details.location
        }}</span><span v-if="details.location && details.asn" class="ip-info-separator">
          · </span><span v-if="details.asn" class="ip-info-asn">{{ details.asn }}</span><span v-if="details.org" class="ip-info-org">{{
          ` ${details.org}`
        }}</span>
      </span>
    </span>
  </el-tooltip>
</template>
