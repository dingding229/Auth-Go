import { computed, toValue, type MaybeRefOrGetter } from "vue";
import { useRoute, useRouter } from "vue-router";
export function useQueryTab(
  allowed: MaybeRefOrGetter<readonly string[]>,
  fallback: string,
  aliases: Record<string, string> = {},
) {
  const route = useRoute(),
    router = useRouter();
  return computed({
    get: () => {
      const raw = String(route.query.tab || fallback),
        name = aliases[raw] || raw;
      return toValue(allowed).includes(name) ? name : fallback;
    },
    set: (name: string) => {
      if (name === String(route.query.tab || fallback)) return;
      void router.replace({ query: { ...route.query, tab: name }, hash: "" });
    },
  });
}
