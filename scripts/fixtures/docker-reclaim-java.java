package io.authgo;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

// Test-only: warm the real SDK/JVM before timing server lease reclamation.
final class ReclaimProbe {
  private static void requireFull(Client client, String license) {
    try {
      client.check(license);
      client.releaseSeat();
      throw new IllegalStateException("capacity was not full before kill");
    } catch (Client.AuthGoException error) {
      if (!error.authenticated || !error.code.equals("FLOATING_LIMIT_REACHED")) throw error;
    }
  }

  static void run(String config) throws Exception {
    var options = new Client.Options();
    options.version = "1.0.0";
    var client = new Client(config, options);
    String license = System.getenv("AUTHGO_LICENSE");
    requireFull(client, license);
    System.out.println("reclaim probe ready; authenticated FLOATING_LIMIT_REACHED");
    var trigger = Path.of("/var/lib/authgo/reclaim.trigger");
    while (!Files.exists(trigger)) Thread.sleep(10);
    long started = System.nanoTime();
    long deadline = started + 10_700_000_000L;
    while (System.nanoTime() < deadline) {
      try {
        var result = client.check(license);
        if (!result.status.equals("online")) throw new IllegalStateException("reclaim used cache");
        client.validate(result.ticket());
        System.out.println("RECLAIM_GRANTED wall_millis=" + Instant.now().toEpochMilli());
        client.releaseSeat();
        return;
      } catch (Client.AuthGoException error) {
        if (!error.authenticated || !error.code.equals("FLOATING_LIMIT_REACHED")) throw error;
      }
      Thread.sleep(250);
    }
    throw new IllegalStateException("lease reclamation exceeded 10.7 seconds");
  }
}
