declare module "markdown-it" {
  export default class MarkdownIt {
    constructor(options: {
      html: boolean;
      linkify?: boolean;
      typographer?: boolean;
    });
    validateLink: (url: string) => boolean;
    render(source: string): string;
  }
}
