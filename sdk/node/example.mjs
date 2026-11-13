import { Client } from "./index.js";
const AUTH_CONFIG = "authgo2.请在构建时替换为后台接入配置";
const client = new Client(AUTH_CONFIG);
const result = await client.check(process.env.AUTHGO_LICENSE);
console.log(result.status);
