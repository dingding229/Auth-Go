import { type Row } from "./json";
export interface ApiField {
  name: string;
  location: string;
  required: boolean;
  type: string;
  description: string;
}
export interface ApiOperation {
  id: string;
  method: string;
  path: string;
  summary: string;
  description: string;
  fields: ApiField[];
  responses: { status: string; description: string; type: string }[];
}
const object = (value: unknown): Row =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Row)
    : {};
const responseDescriptions: Record<string, string> = {
  OK: "成功",
  "Bad Request": "请求参数错误",
  Unauthorized: "未登录或会话已失效",
  Forbidden: "无权访问",
  "Not Found": "资源不存在",
  Conflict: "操作冲突",
  "Too Many Requests": "请求过于频繁",
  "Internal Server Error": "服务器内部错误",
  "Service Unavailable": "服务暂不可用",
  "No Content": "成功，无响应正文",
};
export function apiGroups(
  spec: Row,
): { tag: string; operations: ApiOperation[] }[] {
  function resolve(value: unknown): Row {
    let node = object(value);
    const seen = new Set<string>();
    while (
      typeof node.$ref === "string" &&
      node.$ref.startsWith("#/") &&
      !seen.has(node.$ref)
    ) {
      seen.add(node.$ref);
      let target: unknown = spec;
      for (const key of node.$ref.slice(2).split("/"))
        target = object(target)[key.replace(/~1/g, "/").replace(/~0/g, "~")];
      node = object(target);
    }
    return node;
  }
  function schemaType(value: unknown, depth = 0): string {
    const schema = resolve(value);
    if (depth > 3) return "object";
    if (schema.type === "array")
      return `${schemaType(schema.items, depth + 1)}[]`;
    if (Array.isArray(schema.enum)) return schema.enum.map(String).join(" / ");
    return (
      String(schema.type || (schema.properties ? "object" : "—")) +
      (schema.format ? ` (${String(schema.format)})` : "")
    );
  }
  const groups = new Map<string, ApiOperation[]>();
  for (const [path, raw] of Object.entries(object(spec.paths)).sort(
    ([a], [b]) => a.localeCompare(b),
  )) {
    const pathItem = resolve(raw);
    for (const method of [
      "get",
      "post",
      "put",
      "patch",
      "delete",
      "head",
      "options",
    ]) {
      if (!pathItem[method]) continue;
      const operation = resolve(pathItem[method]),
        fields: ApiField[] = [];
      const parameters = [
        ...(Array.isArray(pathItem.parameters) ? pathItem.parameters : []),
        ...(Array.isArray(operation.parameters) ? operation.parameters : []),
      ];
      function addBody(
        rawSchema: unknown,
        bodyRequired: boolean,
        mediaType: string,
      ) {
        const schema = resolve(rawSchema),
          required = Array.isArray(schema.required) ? schema.required : [];
        const entries = Object.entries(object(schema.properties));
        if (!entries.length)
          fields.push({
            name: "body",
            location: mediaType,
            required: bodyRequired,
            type: schemaType(schema),
            description: String(schema.description || "请求正文"),
          });
        for (const [name, rawProperty] of entries) {
          const property = resolve(rawProperty);
          fields.push({
            name,
            location: mediaType,
            required: bodyRequired && required.includes(name),
            type: schemaType(property),
            description: String(property.description || "—"),
          });
        }
      }
      for (const rawParameter of parameters) {
        const parameter = resolve(rawParameter);
        fields.push({
          name: String(parameter.name || "—"),
          location: String(parameter.in || "—"),
          required: parameter.required === true,
          type: schemaType(parameter.schema || parameter),
          description: String(parameter.description || "—"),
        });
      }
      const requestBody = resolve(operation.requestBody);
      for (const [mediaType, content] of Object.entries(
        object(requestBody.content),
      ))
        addBody(
          object(content).schema,
          requestBody.required === true,
          `body (${mediaType})`,
        );
      const responses = Object.entries(object(operation.responses)).map(
        ([status, rawResponse]) => {
          const response = resolve(rawResponse);
          return {
            status,
            description:
              responseDescriptions[String(response.description)] ||
              String(response.description || "—"),
            type: schemaType(
              response.schema ||
                object(object(response.content)["application/json"]).schema,
            ),
          };
        },
      );
      const entry = {
        id: `${method}:${path}`,
        method: method.toUpperCase(),
        path,
        summary: String(operation.summary || "未提供摘要"),
        description: String(operation.description || ""),
        fields,
        responses,
      };
      const tags =
        Array.isArray(operation.tags) && operation.tags.length
          ? operation.tags.map(String)
          : ["其他接口"];
      for (const tag of new Set(tags)) {
        if (!groups.has(tag)) groups.set(tag, []);
        groups.get(tag)?.push(entry);
      }
    }
  }
  return [...groups].map(([tag, operations]) => ({ tag, operations }));
}
