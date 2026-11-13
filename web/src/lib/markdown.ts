import MarkdownIt, { type MarkdownToken } from "markdown-it";

export const documentTabs = [
  "quickstart",
  "docker",
  "customer",
  "sdk",
  "offline",
  "protocol",
  "admin-api",
] as const;
export type DocumentName =
  "quickstart" | "docker" | "customer" | "offline" | "protocol";
export interface DocumentSection {
  id: string;
  title: string;
  level: number;
}

// Only fixed documentation tabs may use a relative URL. Repository paths and
// other query parameters remain disallowed, as do protocol-relative URLs.
export function safeDocumentLink(url: string): boolean {
  if (/^https?:\/\//i.test(url) || /^#[^\s]*$/.test(url)) return true;
  const match = /^\?tab=([a-z-]+)(#[^\s]*)?$/.exec(url);
  return !!match && documentTabs.some((tab) => tab === match[1]);
}
export function headingSlug(title: string): string {
  return (
    title
      .normalize("NFC")
      .toLowerCase()
      .trim()
      .replace(/[^\p{L}\p{N}\p{M}_\s-]/gu, "")
      .replace(/\s+/g, "-") || "section"
  );
}
export function renderDocument(source: string): {
  html: string;
  sections: DocumentSection[];
} {
  const md = new MarkdownIt({ html: false, linkify: false });
  md.validateLink = safeDocumentLink;
  const escape = (value: string) => md.utils.escapeHtml(value);
  const tokens = md.parse(source, {}),
    sections: DocumentSection[] = [],
    used = new Set<string>(),
    headingIds = new Map<MarkdownToken, string>();
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i]!;
    if (token.type === "heading_open") {
      const inline = tokens[i + 1];
      const title =
        inline?.children
          ?.filter((t) => t.type === "text" || t.type === "code_inline")
          .map((t) => t.content)
          .join("") ||
        inline?.content ||
        "章节";
      const base = headingSlug(title);
      let id = base,
        suffix = 1;
      while (used.has(id)) id = `${base}-${suffix++}`;
      used.add(id);
      headingIds.set(token, id);
      token.attrSet("id", id);
      const level = Number(token.tag.slice(1));
      if (level === 2 || level === 3) sections.push({ id, title, level });
      // The page heading is h1; document headings start at h2.
      token.tag = `h${Math.min(level + 1, 6)}`;
      const close = tokens[i + 2];
      if (close?.type === "heading_close") close.tag = token.tag;
    }
    if (token.type === "blockquote_open") {
      const label = tokens[i + 2]?.children?.find(
        (t) => t.type === "text" && t.content.trim(),
      )?.content.trim();
      token.attrSet(
        "class",
        label === "注意"
          ? "document-callout document-callout--warning"
          : "document-callout document-callout--tip",
      );
    }
  }
  // Attribute values and all code are escaped; raw Markdown HTML stays disabled.
  md.renderer.rules.heading_open = (items, index) => {
    const token = items[index]!,
      id = headingIds.get(token) || "section";
    return `<${token.tag} id="${escape(id)}"><a class="document-anchor" href="#${escape(id)}" data-copy-anchor="${escape(id)}" aria-label="复制章节链接" title="复制章节链接"></a>`;
  };
  md.renderer.rules.fence = (items, index) => {
    const token = items[index]!,
      language = token.info.trim().split(/\s+/)[0] || "文本";
    return `<div class="protocol-codeblock"><div class="document-codebar"><span>${escape(language)}</span><button type="button" data-copy-code>复制代码</button></div><pre tabindex="0"><code>${escape(token.content)}</code></pre></div>`;
  };
  md.renderer.rules.code_block = md.renderer.rules.fence;
  md.renderer.rules.table_open = () =>
    '<div class="document-table" tabindex="0" role="region" aria-label="可横向滚动的表格"><table>';
  md.renderer.rules.table_close = () => "</table></div>";
  return { html: md.renderer.render(tokens, md.options, {}), sections };
}
