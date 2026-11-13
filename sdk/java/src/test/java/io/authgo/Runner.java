package io.authgo;

import java.io.*;
import java.nio.file.*;
import java.util.*;

public final class Runner {

  public static void main(String[] args) throws Exception {
    Client c = null;
    Client.Result result = null;
    Map<String, Object> update = null;
    long[] clock = { java.time.Instant.now().getEpochSecond() };
    BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
    String line;
    while ((line = in.readLine()) != null) {
      Map<String, Object> out = Client.map("code", "OK");
      try {
        var p = Client.obj(Client.parse(Client.bytes(line)));
        String op = Client.str(p, "op");
        switch (op) {
          case "init" -> {
            Client.Options opt = new Client.Options();
            clock[0] = Client.num(p, "time");
            opt.clock = () -> clock[0];
            opt.fingerprint = Client.yes(p,"automatic") ? null : p.containsKey("fingerprint") ? Client.str(p,"fingerprint") : "a".repeat(64);
            opt.version = Client.yes(p,"unversioned") ? "" : p.containsKey("version") ? Client.str(p,"version") : "1.0.0";
            opt.cacheDir = p.containsKey("cache_dir") ? Path.of(Client.str(p,"cache_dir")) : Files.createTempDirectory("authgo-sdk-java-");
            c = new Client(Client.str(p, "config"), opt);
            out.put("status", "ready");
          }
          case "clock" -> clock[0] += Client.num(p, "seconds");
          case "check", "activate", "verify", "heartbeat" -> {
            if (c == null) throw new Exception();
            result = switch (op) {
              case "check" -> c.check(Client.str(p, "key"));
              case "activate" -> c.activate(Client.str(p, "key"));
              case "verify" -> c.verify();
              default -> c.heartbeat();
            };
            out.put("status", result.status);
          }
          case "guard_check" -> {result=c.guardCheck(Client.str(p,"key"));out.put("status",result.status);}
          case "trial_info" -> out.put("is_trial",result.isTrial);
          case "release_seat" -> c.releaseSeat();
          case "entitlement" -> {out.put("maintenance_until",result.maintenanceUntil.isEmpty()?null:result.maintenanceUntil);out.put("latest_entitled_version",result.latestEntitledVersion);}
          case "validate" -> c.validate(result.ticket());
          case "identity" -> {var field=Client.class.getDeclaredField("fp");field.setAccessible(true);out.put("fingerprint",field.get(c));}
          case "cache_warning" -> out.put("cache_warning",!result.cacheWarning.isEmpty());
          case "deactivate" -> c.deactivate();
          case "announcements" -> out.put("count", c.announcements().size());
          case "check_update" -> {
            update = c.checkUpdate(
              p.containsKey("version") ? Client.str(p, "version") : "1.0.0"
            );
            out.put("available", update.get("available"));
            out.put("version", update.get("version"));
            out.put("docker_image", update.get("docker_image")); out.put("docker_pull", update.get("docker_pull"));
          }
          default -> throw new Exception();
        }
      } catch (Client.AuthGoException e) {
        out = Client.map("code", e.code);
        if(!e.latestVersion.isEmpty())out.put("latest_version",e.latestVersion);
        if(e.code.equals("MAINTENANCE_EXPIRED"))out.put("latest_entitled_version",e.latestEntitledVersion);
      } catch (Exception e) {
        out = Client.map(
          "code",
          "RUNNER_ERROR",
          "detail",
          e.getClass().getSimpleName()
        );
      }
      System.out.println(Client.canonical(out));
      System.out.flush();
    }
  }
}
