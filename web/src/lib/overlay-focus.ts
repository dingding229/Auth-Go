// Element Plus captures focus when its trap mounts. Async actions/loading buttons
// can already have blurred by then, so retain the initiating control beforehand.
let activated: HTMLElement | undefined;
let lastOrigin: HTMLElement | undefined;
const parents = new WeakMap<HTMLElement, HTMLElement>();
const selector = 'button,a[href],input,select,textarea,[tabindex]:not([tabindex="-1"]),[role="switch"],[role="menuitem"]';
function trigger(target: EventTarget | null) {
  if (!(target instanceof Element)) return undefined;
  let control = target.closest<HTMLElement>(selector) ?? undefined;
  const menu = control?.closest('[role="menu"]');
  if (menu?.id) {
    // A dropdown item disappears on selection; its persistent trigger owns focus.
    control = [...document.querySelectorAll<HTMLElement>('[aria-controls]')]
      .find((item) => item.getAttribute("aria-controls") === menu.id) ?? control;
  }
  const dialog = control?.closest<HTMLElement>('[role="dialog"]');
  const parent = dialog && parents.get(dialog);
  // Capture the chain at activation, before an async submit destroys its form.
  if (control && parent && parent !== control) parents.set(control, parent);
  return control;
}
if (typeof document !== "undefined") {
  document.addEventListener("pointerdown", (event) => { activated = trigger(event.target); }, true);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") activated = trigger(event.target);
  }, true);
}
function visible(target?: HTMLElement): boolean {
  if (!target?.isConnected || target.closest('[aria-hidden="true"],[inert]')) return false;
  for (let node: HTMLElement | null = target; node; node = node.parentElement) {
    const style = getComputedStyle(node);
    if (style.display === "none" || style.visibility === "hidden") return false;
  }
  return true;
}
export function focusReturn() {
  const active = trigger(document.activeElement);
  let origin = active ?? activated ?? lastOrigin;
  if (origin) lastOrigin = origin;
  return {
    bind(owner?: string) {
      // Retained, hidden siblings can occur later in DOM order. Bind the actual
      // owning overlay even when its focus trap has not moved focus yet.
      const node = owner
        ? [...document.querySelectorAll<HTMLElement>("[data-focus-owner]")].find((element) => element.getAttribute("data-focus-owner") === owner)
        : document.activeElement;
      const dialog = node?.closest<HTMLElement>('[role="dialog"]') ?? node?.querySelector<HTMLElement>('[role="dialog"]');
      if (dialog && origin) parents.set(dialog, origin);
    },
    restore(event?: Event) {
      event?.preventDefault();
      queueMicrotask(() => {
        // Nested overlays may close with their parent. Return to its opener,
        // never to a now-hidden input inside the retired drawer.
        const seen = new Set<HTMLElement>();
        while (origin && !visible(origin) && !seen.has(origin)) {
          seen.add(origin);
          const dialog = origin.closest<HTMLElement>('[role="dialog"]');
          origin = parents.get(origin) ?? (dialog ? parents.get(dialog) : undefined);
        }
        if (!origin || !visible(origin)) return;
        const target = origin;
        let pending: MutationObserver | undefined;
        const restore = () => {
          if (!target.isConnected || !visible(target)) { pending?.disconnect(); return; }
          if (target.matches(":disabled,[aria-disabled=true]")) return;
          pending?.disconnect();
          // Switches/checkboxes focus a zero-sized native input. Put the ring on
          // its visible control, using an attribute Vue's class patch won't erase.
          const ring = target.closest<HTMLElement>(".el-switch,.el-checkbox,.el-radio") ?? target;
          ring.setAttribute("data-overlay-focus-return", "");
          target.addEventListener("blur", () => ring.removeAttribute("data-overlay-focus-return"), { once: true });
          target.focus({ preventScroll: true });
        };
        if (target.matches(":disabled,[aria-disabled=true]")) {
          // Confirming can start an async mutation. Native disabled controls
          // cannot receive focus until that task finishes; do not drop the
          // original control just because the leave transition finishes first.
          pending = new MutationObserver(restore);
          pending.observe(document.body, { attributes: true, childList: true, subtree: true, attributeFilter: ["disabled", "aria-disabled", "class", "style"] });
        }
        restore();
      });
    },
  };
}
