package watermarkprobe;
import java.lang.instrument.*;
import java.nio.file.*;
import java.security.ProtectionDomain;
public final class Agent {
  public static void premain(String directory, Instrumentation instrumentation) {
    Thread worker = new Thread(() -> {
      Path out = Path.of(directory);
      try {
        while (!Files.exists(out.resolve("agent-trigger"))) Thread.sleep(50);
        Class<?> target = null;
        for (Class<?> value : instrumentation.getAllLoadedClasses())
          if (value.getName().equals("watermark.Business")) target = value;
        if (target == null) throw new IllegalStateException("loaded target missing");
        ClassFileTransformer transformer = new ClassFileTransformer() {
          public byte[] transform(ClassLoader loader, String name, Class<?> redefined,
                                  ProtectionDomain domain, byte[] bytes) {
            if (name.equals("watermark/Business") && redefined != null) {
              try { Files.write(out.resolve("agent-runtime.class"), bytes); }
              catch (Exception error) { throw new RuntimeException(error); }
            }
            return null;
          }
        };
        instrumentation.addTransformer(transformer, true);
        instrumentation.retransformClasses(target);
        instrumentation.removeTransformer(transformer);
        Files.writeString(out.resolve("agent-done"), "RUNTIME_RETRANSFORM_DONE\n");
      } catch (Throwable error) {
        error.printStackTrace();
        try { Files.writeString(out.resolve("agent-error"), error.getClass().getName()); }
        catch (Exception ignored) { }
      }
    }, "watermark-runtime-export");
    worker.setDaemon(true);
    worker.start();
  }
}
