package io.authgo;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;

/** Main-Class for a public SDK/build-config launcher plus an encrypted ordinary JAR. */
public final class Bootstrap {
  private Bootstrap() {}

  /**
   * io.authgo.BuildConfig.options() is compiled into the public launcher, never read from
   * payload.config.
   */
  public static void main(String[] args) {
    try {
      run(buildOptions(), "app", args);
    } catch (Throwable failure) {
      System.err.println(message(failure));
      System.exit(Guard.EXIT_LICENSE);
    }
  }

  static GuardOptions buildOptions() throws ReflectiveOperationException {
    Class<?> build = Class.forName("io.authgo.BuildConfig", true, Bootstrap.class.getClassLoader());
    var method = build.getMethod("options");
    if (!Modifier.isStatic(method.getModifiers()) || method.getReturnType() != GuardOptions.class)
      throw new Client.AuthGoException("SDK_INVALID_CONFIG");
    Object value = method.invoke(null);
    if (!(value instanceof GuardOptions options)
        || options.config == null
        || options.config.isEmpty()) throw new Client.AuthGoException("SDK_INVALID_CONFIG");
    return options;
  }

  static Path directory() {
    String path = System.getenv("AUTHGO_PAYLOAD_DIR");
    return Path.of(path == null || path.isEmpty() ? "/opt/authgo" : path);
  }

  /** Read public metadata only. It never changes the Client's compiled trust root. */
  public static SealedClassLoader load(Guard guard, String name) throws IOException {
    return load(guard, name, directory());
  }

  static SealedClassLoader load(Guard guard, String name, Path directory) throws IOException {
    guard.require();
    if (name == null || !name.matches("[a-z0-9_-]{1,128}")) throw Payload.invalid();
    return load(guard, name, directory, metadata(directory));
  }

  private static Payload metadata(Path directory) throws IOException {
    try (var source =
        Files.newInputStream(
            directory.resolve("payload.json"),
            StandardOpenOption.READ,
            LinkOption.NOFOLLOW_LINKS)) {
      return Payload.parsePayload(source.readNBytes(65537));
    }
  }

  private static SealedClassLoader load(Guard guard, String name, Path directory, Payload payload)
      throws IOException {
    guard.require();
    var files = PayloadFiles.files(payload);
    int index = -1;
    for (int i = 0; i < files.size(); i++)
      if (files.get(i).name().equals(name)) {
        index = i;
        break;
      }
    if (index < 0 || !files.get(index).kind().equals("java")) throw Payload.invalid();
    var file = files.get(index);
    guard.require();
    byte[] material = guard.unlockPayloadMaterial(payload), key = Arrays.copyOf(material,32), jar = null;
    try (var out = new SealedClassLoader.WipingBuffer()) {
      var watermark=PayloadWatermark.read(directory,payload,material);
      Path ciphertext = directory.resolve(file.path());
      long total = Files.size(ciphertext);
      try (InputStream source =
          Files.newInputStream(ciphertext, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
        PayloadFiles.decryptPayloadFile(out, source, total, payload, key, index);
      }
      jar = out.toByteArray();
      guard.require();
      return SealedClassLoader.openV2(guard,jar,file.mainClass(),watermark,index,material);
    } finally {
      Arrays.fill(material, (byte) 0); Arrays.fill(key, (byte) 0);
      if (jar != null) Arrays.fill(jar, (byte) 0);
    }
  }

  /** Alternative compiled entry point, e.g. Bootstrap.run(options,"app",args). */
  public static void run(GuardOptions options, String name, String[] args) throws Exception {
    if (options == null) throw new Client.AuthGoException("SDK_INVALID_CONFIG");
    Path directory = directory();
    Payload payload = metadata(directory);
    var fixed = new GuardOptions();
    fixed.config = options.config;
    fixed.license = options.license;
    fixed.sdkOptions = options.sdkOptions;
    fixed.onChange = options.onChange;
    // The version becomes trustworthy when unlock authenticates this same
    // envelope. Keep reporting it during online checks, not a caller override.
    fixed.version = payload.version();
    Guard guard = Guard.start(fixed);
    SealedClassLoader loader = null;
    Thread hook = null;
    boolean launched = false;
    try {
      Guards.bind(guard);
      loader = load(guard, name, directory, payload);
      final SealedClassLoader loaded = loader;
      hook =
          new Thread(
              () -> {
                loaded.close();
                try {
                  guard.close();
                } catch (RuntimeException ignored) {
                } finally {
                  Guards.clear(guard);
                }
              },
              "authgo-protected-shutdown");
      Runtime.getRuntime().addShutdownHook(hook);
      guard
          .done()
          .thenRun(
              () -> {
                // Do not block the Guard worker in System.exit's shutdown-hook join.
                Thread exit =
                    new Thread(
                        () -> {
                          System.err.println(message(guard.error()));
                          System.exit(Guard.EXIT_LICENSE);
                        },
                        "authgo-protected-exit");
                exit.setDaemon(true);
                exit.start();
              });
      invoke(loader, args);
      launched = true;
      // A Java main may start non-daemon HTTP workers and return. Keep its
      // guard/loader alive until shutdown; do not release its seat here.
    } finally {
      if (!launched) {
        if (hook != null)
          try {
            Runtime.getRuntime().removeShutdownHook(hook);
          } catch (IllegalStateException ignored) {
          }
        if (loader != null) loader.close();
        try {
          guard.close();
        } catch (RuntimeException ignored) {
        } finally {
          Guards.clear(guard);
        }
      }
    }
  }

  static void invoke(SealedClassLoader loader, String[] args) throws Exception {
    Thread thread = Thread.currentThread();
    ClassLoader parent = thread.getContextClassLoader();
    try {
      thread.setContextClassLoader(loader);
      Class<?> main = Class.forName(loader.mainClass(), true, loader);
      var method = main.getMethod("main", String[].class);
      if (!Modifier.isStatic(method.getModifiers()) || method.getReturnType() != void.class)
        throw Payload.invalid();
      loader.checkAccess();
      try {
        method.invoke(null, (Object) args.clone());
      } catch (InvocationTargetException failure) {
        Throwable cause = failure.getCause();
        if (cause instanceof Exception exception) throw exception;
        if (cause instanceof Error error) throw error;
        throw new IllegalStateException(cause);
      }
    } finally {
      thread.setContextClassLoader(parent);
    }
  }

  static String message(Throwable failure) {
    if (failure instanceof Client.AuthGoException auth) {
      if (auth.getCause() instanceof SealedClassLoader.UnsupportedFormatException detail)
        return "代码载荷不受支持：" + detail.getMessage();
      if (auth.code.matches("[A-Z0-9_]{1,64}")) return "授权或代码解锁失败：" + auth.code + "（退出码 77）";
    }
    return "加密程序启动失败，请检查构建时接入配置、载荷和授权状态（退出码 77）";
  }
}
