export function injectAdminRuntime(path: string | null = "/admin") {
  document.getElementById("authgo-runtime")?.remove();
  if (path === null) return;
  const node = document.createElement("script");
  node.id = "authgo-runtime";
  node.type = "application/json";
  node.textContent = JSON.stringify({ admin_path: path });
  document.head.append(node);
}
injectAdminRuntime();
