using AuthGo;

// Public launcher: only this compiled-in constant selects the licensing server.
const string Config = "authgo2.请在构建时替换为后台接入配置";
return await Bootstrap.RunAsync(new GuardOptions { Config = Config }, args);
