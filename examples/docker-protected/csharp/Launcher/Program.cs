using AuthGo;
// Build.sh creates Build.cs in this project, not a runtime trust configuration file.
return await Bootstrap.RunAsync(new GuardOptions { Config = Build.Config, Version = Build.Version }, args);
