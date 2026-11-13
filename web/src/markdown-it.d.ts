declare module "markdown-it" {
  export interface MarkdownToken {
    type: string;
    tag: string;
    content: string;
    info: string;
    children: MarkdownToken[] | null;
    attrSet(name: string, value: string): void;
  }
  export default class MarkdownIt {
    constructor(options: {
      html: boolean;
      linkify?: boolean;
      typographer?: boolean;
    });
    validateLink: (url: string) => boolean;
    parse(source: string, env: object): MarkdownToken[];
    utils: { escapeHtml(value: string): string };
    renderer: {
      rules: Record<
        string,
        ((tokens: MarkdownToken[], index: number) => string) | undefined
      >;
      render(tokens: MarkdownToken[], options: object, env: object): string;
    };
    options: object;
    render(source: string): string;
  }
}
