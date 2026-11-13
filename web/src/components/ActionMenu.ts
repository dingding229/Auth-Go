import {
  defineComponent,
  h,
  Fragment,
  Comment,
  ref,
  onMounted,
  onBeforeUnmount,
  type VNode,
  type VNodeChild,
} from "vue";
import { ArrowDown } from "@element-plus/icons-vue";
import {
  ElIcon,
  ElDropdown,
  ElDropdownMenu,
  ElDropdownItem,
  ElButton,
} from "element-plus";
function flatten(nodes: VNode[]): VNode[] {
  return nodes.flatMap((n) =>
    n.type === Fragment
      ? flatten(n.children as VNode[])
      : n.type === Comment
        ? []
        : [n],
  );
}
function content(node: VNode): VNodeChild {
  const children = node.children as { default?: () => VNodeChild } | VNodeChild;
  return children &&
    typeof children === "object" &&
    "default" in children &&
    typeof children.default === "function"
    ? children.default()
    : (children as VNodeChild);
}
function invoke(node: VNode, event: MouseEvent) {
  const handler = node.props?.onClick;
  if (Array.isArray(handler)) handler.forEach((fn) => fn(event));
  else if (typeof handler === "function") handler(event);
}
export default defineComponent({
  name: "ActionMenu",
  props: {
    mobile: Boolean,
    limit: { type: Number, default: 2 },
    static: Boolean,
    keepPrimary: Boolean,
  },
  setup(props, { slots }) {
    const compact = ref(false);
    let media: MediaQueryList | undefined;
    const change = () => (compact.value = !!media?.matches);
    onMounted(() => {
      media = window.matchMedia("(max-width:767px)");
      change();
      media.addEventListener("change", change);
    });
    onBeforeUnmount(() => media?.removeEventListener("change", change));
    return () => {
      const items = flatten(slots.default?.() || []).filter(
        (node) =>
          !compact.value ||
          !String(node.props?.class || "").includes("detail-back"),
      );
      const single = items.length === 1;
      const limit = single
        ? 1
        : props.mobile || (compact.value && !props.static)
          ? 0
          : props.limit;
      const primary =
        !single && compact.value && !props.static && props.keepPrimary;
      const direct = primary
        ? items.filter((n) => n.props?.type === "primary")
        : items.slice(0, limit);
      const rest = primary
        ? items.filter((n) => n.props?.type !== "primary")
        : items.slice(limit);
      return h(
        "div",
        {
          class: "row-actions",
          onClick: (event: MouseEvent) => event.stopPropagation(),
        },
        [
          ...direct,
          ...(rest.length
            ? [
                h(
                  ElDropdown,
                  {
                    trigger: "click",
                    popperClass: "action-menu-popper",
                    popperOptions: {
                      modifiers: [
                        { name: "preventOverflow", options: { padding: 8 } },
                        { name: "flip", options: { padding: 8 } },
                        {
                          name: "authgoViewportPadding",
                          enabled: true,
                          phase: "main",
                          requires: ["popperOffsets", "preventOverflow"],
                          fn: ({
                            state,
                          }: {
                            state: {
                              modifiersData: {
                                popperOffsets?: { x: number; y: number };
                              };
                              rects: { popper: { width: number } };
                            };
                          }) => {
                            const offsets = state.modifiersData.popperOffsets;
                            if (offsets) {
                              const left = window.scrollX + 8,
                                right =
                                  window.scrollX +
                                  document.documentElement.clientWidth -
                                  8 -
                                  state.rects.popper.width;
                              offsets.x = Math.max(
                                left,
                                Math.min(offsets.x, right),
                              );
                            }
                          },
                        },
                      ],
                    },
                  },
                  {
                    default: () =>
                      h(ElButton, { "aria-label": "更多操作" }, () => [
                        "更多",
                        h(ElIcon, {}, () => h(ArrowDown)),
                      ]),
                    dropdown: () =>
                      h(ElDropdownMenu, {}, () =>
                        rest.map((node, index) => {
                          const action =
                            node.type === ElButton
                              ? node
                              : Array.isArray(node.children)
                                ? flatten(node.children as VNode[]).find(
                                    (child) => child.type === ElButton,
                                  )
                                : undefined;
                          const button = !!action;
                          const danger = action?.props?.type === "danger";
                          return h(
                            ElDropdownItem,
                            {
                              key: index,
                              disabled: action?.props?.disabled === true,
                              title: node.props?.title,
                              divided: danger && index > 0,
                              class: { "is-danger": danger },
                              onClick: (event: MouseEvent) => {
                                event.stopPropagation();
                                if (action) invoke(action, event);
                                else if (event.target === event.currentTarget)
                                  (event.currentTarget as HTMLElement)
                                    .querySelector<HTMLElement>(
                                      "button:not([disabled]),a",
                                    )
                                    ?.click();
                              },
                            },
                            () => (button ? content(action!) : node),
                          );
                        }),
                      ),
                  },
                ),
              ]
            : []),
        ],
      );
    };
  },
});
