package io.authgo;

import java.io.ByteArrayInputStream;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.JarInputStream;

/** Remote-only probe using the actual Spring Boot loader artifact, not a mock. */
public final class NestedJarLauncherTests {
  private NestedJarLauncherTests() {}

  public static void main(String[] args) throws Exception {
    Map<String, byte[]> classes = new HashMap<>();
    try (var jar =
        new JarInputStream(new ByteArrayInputStream(Files.readAllBytes(Path.of(args[0]))))) {
      for (var entry = jar.getNextJarEntry(); entry != null; entry = jar.getNextJarEntry()) {
        if (entry.getName().endsWith(".class"))
          classes.put(
              entry.getName().replace('/', '.').replaceFirst("\\.class$", ""), jar.readAllBytes());
      }
    }
    var loader =
        new ClassLoader(NestedJarLauncherTests.class.getClassLoader()) {
          @Override
          protected Class<?> findClass(String name) throws ClassNotFoundException {
            byte[] value = classes.get(name);
            if (value == null) throw new ClassNotFoundException(name);
            return defineClass(name, value, 0, value.length);
          }
        };
    try {
      loader
          .loadClass("org.springframework.boot.loader.launch.JarLauncher")
          .getMethod("main", String[].class)
          .invoke(null, (Object) new String[0]);
      throw new AssertionError("Spring Boot unexpectedly launched from a pathless loader");
    } catch (InvocationTargetException failure) {
      Throwable root = failure.getCause();
      while (root.getCause() != null) root = root.getCause();
      System.out.println(
          "Spring Boot 3.4.0 pathless memory loader: "
              + root.getClass().getSimpleName()
              + ": "
              + root.getMessage());
      String message = String.valueOf(root.getMessage());
      if (!message.contains("code source")
          && !message.contains("CodeSource")
          && !message.contains("location"))
        throw new AssertionError("Unexpected launcher failure", failure);
      System.out.println("SPRING_BOOT_NESTED_JAR=UNSUPPORTED (no filesystem/code-source archive)");
    }
  }
}
