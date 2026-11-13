import io.authgo.Client;
import io.authgo.Guards;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;

/** Only this business JAR is encrypted; it reuses Bootstrap's single Guard. */
public final class Main {
  public static void main(String[] args) throws Exception {
    var guard = Guards.current();
    String listen = "0.0.0.0:8080";
    for (int i = 0; i + 1 < args.length; i++) if (args[i].equals("-listen")) listen = args[i + 1];
    String[] address = listen.split(":");
    var server = HttpServer.create(new InetSocketAddress(address[0].isEmpty() ? "0.0.0.0" : address[0], Integer.parseInt(address[1])), 0);
    server.setExecutor(Executors.newCachedThreadPool(task -> {
      var thread = new Thread(task, "business-http"); thread.setDaemon(true); return thread;
    }));
    server.createContext("/", exchange -> {
      int status = 200;
      byte[] body;
      try {
        guard.require();
        body = Client.canonical(Map.of("marker", "AUTHGO_payload_PROTECTED_CORE", "language", "java",
            "unique", "AUTHGO_payload_JAVA_CORE", "features", guard.result().data.get("features"))).getBytes(StandardCharsets.UTF_8);
      } catch (Client.AuthGoException error) {
        status = 503; body = error.code.getBytes(StandardCharsets.UTF_8);
      }
      exchange.getResponseHeaders().set("Content-Type", "application/json");
      exchange.sendResponseHeaders(status, body.length);
      try (var out = exchange.getResponseBody()) { out.write(body); }
    });
    var stopping = new CountDownLatch(1);
    sun.misc.Signal.handle(new sun.misc.Signal("TERM"), signal -> { server.stop(0); stopping.countDown(); });
    sun.misc.Signal.handle(new sun.misc.Signal("INT"), signal -> { server.stop(0); stopping.countDown(); });
    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      server.stop(0);
      stopping.countDown();
      // Wait for the same idempotent close as Bootstrap's hook before setting exit status.
      try { guard.close(); } catch (RuntimeException error) { System.err.println("释放席位未完成"); }
      System.out.flush(); System.err.flush();
      Runtime.getRuntime().halt(guard.error() == null ? 0 : io.authgo.Guard.EXIT_LICENSE);
    }, "business-shutdown"));
    server.start();
    System.out.println("HTTP已启动");
    stopping.await();
  }
}
