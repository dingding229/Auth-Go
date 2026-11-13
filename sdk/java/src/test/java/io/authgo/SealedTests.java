package io.authgo;

import static io.authgo.Client.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.tools.FileObject;
import javax.tools.ForwardingJavaFileManager;
import javax.tools.JavaFileObject;
import javax.tools.SimpleJavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;

/** Unit tests use synthetic keys and an in-memory Java compiler, never plaintext staging files. */
public final class SealedTests {
  private SealedTests() {}

  private static int cases;
  private static final byte[] KEY = new byte[32];
  private static final String MAIN = "sample.deep.Entry";
  private static final String WATERMARK_TAG = "0123456789abcdef0123456789abcdef";
  private static final String MARKER = "AUTHGO_MEMORY_JAVA_MARKER_6B";

  static {
    for (int i = 0; i < KEY.length; i++) KEY[i] = (byte) i;
  }

  @FunctionalInterface
  interface Action {
    void run() throws Exception;
  }

  static void check(boolean value) {
    if (!value) throw new AssertionError("sealed assertion failed");
  }

  static void equal(Object a, Object b) {
    if (!Objects.equals(a, b)) throw new AssertionError("sealed values differ: " + a + " != " + b);
  }

  static void same(byte[] a, byte[] b) {
    check(Arrays.equals(a, b));
  }

  static void error(String expected, Action action) throws Exception {
    try {
      action.run();
      throw new AssertionError("expected " + expected);
    } catch (AuthGoException actual) {
      equal(actual.code, expected);
    }
  }

  static void runCase(String name, Action action) throws Exception {
    action.run();
    cases++;
    System.out.println("sealed: " + name + " PASS");
  }

  static Map<String, Object> vector(String name) throws IOException {
    return obj(parse(Files.readAllBytes(Path.of("sdk/vectors/" + name))));
  }

  static byte[] hex(Object value) {
    return java.util.HexFormat.of().parseHex(value.toString());
  }

  static final class Backend implements Guard.Backend {
    final Client client;
    volatile String refused;
    final AtomicInteger unlocks = new AtomicInteger();
    volatile byte[] returned;
    volatile CountDownLatch entered, release;

    Backend() throws IOException {
      var p = Payload.parsePayload(canonical(vector("payload-cache-v2.json").get("payload")));
      var options = new Client.Options();
      options.fingerprint = "a".repeat(64);
      options.cacheDir = null;
      client = new Client(p.config(), options);
    }

    public long now() {
      return Instant.now().getEpochSecond();
    }

    Client.Result value() {
      return new Client.Result(
          client,
          map("features", Map.of(), "next_check_in", 3600, "floating", false),
          "proof",
          new byte[32],
          "online",
          now() + 3600,
          "");
    }

    public Client.Result verify() {
      validate("proof");
      return value();
    }

    public Client.Result heartbeat() {
      return verify();
    }

    public void validate(String ticket) {
      equal(ticket, "proof");
      if (refused != null) throw new AuthGoException(refused, true, null);
    }

    public void release() {}

    public byte[] unlockPayloadMaterial(Payload payload) {
      byte[] key=unlockPayload(payload);
      returned=concat(key,java.util.HexFormat.of().parseHex("19".repeat(32)));Arrays.fill(key,(byte)0);return returned;
    }
    public byte[] unlockPayload(Payload payload) {
      unlocks.incrementAndGet();
      if (entered != null) entered.countDown();
      if (release != null)
        try {
          check(release.await(5, TimeUnit.SECONDS));
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw new IllegalStateException(e);
        }
      returned = KEY.clone();
      return returned;
    }
  }

  static final class Fixture implements AutoCloseable {
    final Backend backend = new Backend();
    final Guard guard = new Guard(backend, backend.value(), null);
    final List<SealedClassLoader> loaders = new ArrayList<>();

    Fixture() throws IOException {}

    SealedClassLoader open(byte[] jar) {
      var loader = SealedClassLoader.open(guard, jar, MAIN);
      loaders.add(loader);
      return loader;
    }

    @Override
    public void close() {
      for (var loader : loaders) loader.close();
      Guards.clear(guard);
      guard.close();
      System.clearProperty("authgo.sealed.result");
    }
  }

  static Map<String, byte[]> compile() throws IOException {
    return compile(
        Map.of(
            MAIN,
            "package sample.deep; public class Entry { public static String marker(){return \""
                + MARKER
                + "\";} public static class Nested {public static int value(){return 17;}} public"
                + " static void main(String[] args)throws"
                + " Exception{io.authgo.Guards.current().require();try(var"
                + " in=Thread.currentThread().getContextClassLoader().getResourceAsStream(\"assets/nested/message.txt\")){System.setProperty(\"authgo.sealed.result\",new"
                + " String(in.readAllBytes(),java.nio.charset.StandardCharsets.UTF_8)+\":\"+args[0]);}}}",
            "sample.deep.Later",
            "package sample.deep; public class Later { public static int value(){return 42;} }",
            "sample.deep.Throws",
            "package sample.deep; public class Throws { public static void main(String[]"
                + " args){throw new IllegalStateException(\"business failure\");}}"));
  }

  static Map<String, byte[]> compile(Map<String, String> sources) throws IOException {
    var compiler = ToolProvider.getSystemJavaCompiler();
    check(compiler != null);
    Map<String, ByteArrayOutputStream> result = new HashMap<>();
    try (StandardJavaFileManager standard = compiler.getStandardFileManager(null, null, null);
        var manager =
            new ForwardingJavaFileManager<StandardJavaFileManager>(standard) {
              @Override
              public JavaFileObject getJavaFileForOutput(
                  Location location, String name, JavaFileObject.Kind kind, FileObject sibling) {
                return new SimpleJavaFileObject(
                    URI.create("memory:///" + name.replace('.', '/') + kind.extension), kind) {
                  @Override
                  public OutputStream openOutputStream() {
                    var out = new ByteArrayOutputStream();
                    result.put(name, out);
                    return out;
                  }
                };
              }
            }) {
      List<JavaFileObject> units = new ArrayList<>();
      for (var entry : sources.entrySet())
        units.add(
            new SimpleJavaFileObject(
                URI.create("string:///" + entry.getKey().replace('.', '/') + ".java"),
                JavaFileObject.Kind.SOURCE) {
              @Override
              public CharSequence getCharContent(boolean ignore) {
                String source = entry.getValue(); int brace = source.indexOf('{');
                StringBuilder field = new StringBuilder(" public static final String[] __AUTHGO_WATERMARK = new String[]{");
                for (int i=0;i<8;i++) { if(i!=0)field.append(','); field.append('"').append(i).append(WATERMARK_TAG).append("0".repeat(64)).append('"'); }
                field.append("}; "); return source.substring(0,brace+1)+field+source.substring(brace+1);
              }
            });
      check(
          Boolean.TRUE.equals(
              compiler
                  .getTask(
                      null,
                      manager,
                      null,
                      List.of(
                          "-proc:none",
                          "-g:none",
                          "-Xlint:all",
                          "-Werror",
                          "-classpath",
                          System.getProperty("java.class.path")),
                      null,
                      units)
                  .call()));
    }
    Map<String, byte[]> out = new LinkedHashMap<>();
    result.forEach((n, b) -> out.put(n.replace('.', '/') + ".class", b.toByteArray()));
    return out;
  }

  static byte[] jar(Map<String, byte[]> classes, Map<String, byte[]> extra, String manifest)
      throws IOException {
    var out = new ByteArrayOutputStream();
    try (var zip = new JarOutputStream(out)) {
      var all = new LinkedHashMap<String, byte[]>();
      all.put("META-INF/MANIFEST.MF", bytes(manifest));
      all.putAll(classes);
      all.putAll(extra);
      for (var entry : all.entrySet()) {
        zip.putNextEntry(new JarEntry(entry.getKey()));
        zip.write(entry.getValue());
        zip.closeEntry();
      }
    }
    return out.toByteArray();
  }

  static final String MANIFEST =
      "Manifest-Version: 1.0\r\nMain-Class: sample.deep.En\r\n try\r\n\r\n";

  static byte[] jar(Map<String, byte[]> classes) throws IOException {
    return jar(classes, Map.of("assets/nested/message.txt", bytes("resource-in-memory")), MANIFEST);
  }

  static Payload payload(long size, int index) throws IOException {
    var obj = new HashMap<>(obj(vector("payload-envelope.json").get("payload")));
    List<Object> files = new ArrayList<>();
    for (int i = 0; i < index; i++)
      files.add(
          map(
              "name",
              "other" + i,
              "kind",
              "node",
              "path",
              String.format(java.util.Locale.ROOT, "%08d.agc", i),
              "size",
              768,
              "chunk_size",
              1 << 20,
              "encoding",
              "raw"));
    files.add(
        map(
            "name",
            "app",
            "kind",
            "java",
            "path",
            String.format(java.util.Locale.ROOT, "%08d.agc", index),
            "size",
            size,
            "chunk_size",
            1 << 20,
            "encoding",
            "raw",
            "main_class",
            MAIN));
    files.add(map("name","__authgo_watermark","kind","watermark","path",String.format(java.util.Locale.ROOT,"%08d.agc",index+1),"size",1,"chunk_size",1<<20,"encoding","raw"));
    obj.put("manifest", b64(bytes(canonical(map("files", files)))));
    return Payload.parsePayload(canonical(obj));
  }

  static void watermarkEntries(byte[] jar, List<String> prefix, List<Object> entries) throws IOException {
    try(var input=new java.util.zip.ZipInputStream(new ByteArrayInputStream(jar))) { java.util.zip.ZipEntry entry;
      while((entry=input.getNextEntry())!=null) { byte[] data=input.readAllBytes(); var path=new ArrayList<String>(prefix);path.add(entry.getName());
        if(entry.getName().endsWith(".jar")) { watermarkEntries(data,path,entries); continue; }
        if(!entry.getName().endsWith(".class"))continue;var offsets=new ArrayList<String>();byte[] needle=bytes(WATERMARK_TAG+"0".repeat(64));
        for(int j=0;j<=data.length-96;j++)if(Arrays.equals(Arrays.copyOfRange(data,j,j+96),needle))offsets.add(Integer.toString(j));
        if(!offsets.isEmpty())entries.add(map("path",path,"offsets",offsets));
      }
    }
  }
  static Payload writeCurrentPayload(Path dir, byte[] jar, int index) throws Exception {
    Payload p=payload(jar.length,index);var privateFiles=new ArrayList<Object>();
    for(int i=0;i<index;i++){var offsets=new ArrayList<String>();for(int j=0;j<8;j++)offsets.add(Integer.toString(j*96));privateFiles.add(map("index",Integer.toString(i),"entries",List.of(map("path",List.of(),"offsets",offsets))));}
    var entries=new ArrayList<Object>();watermarkEntries(jar,List.of(),entries);privateFiles.add(map("index",Integer.toString(index),"entries",entries));
    byte[] privateIndex=bytes(canonical(map("v","1","tag",WATERMARK_TAG,"files",privateFiles)));var manifest=obj(parse(decode(p.manifest())));var files=list(manifest.get("files"));obj(files.get(files.size()-1)).put("size",privateIndex.length);
    p=new Payload(2,p.appKey(),p.version(),p.builtAt(),p.keyId(),p.config(),b64(bytes(canonical(manifest))),p.envelope()).validated();
    Files.writeString(dir.resolve("payload.json"),canonical(p.toMap()));Files.write(dir.resolve(String.format(java.util.Locale.ROOT,"%08d.agc",index)),encrypt(p,index,jar));Files.write(dir.resolve(String.format(java.util.Locale.ROOT,"%08d.agc",index+1)),encrypt(p,index+1,privateIndex));return p;
  }
  static byte[] encrypt(Payload p, int index, byte[] plain) throws Exception {
    var out = new ByteArrayOutputStream();
    long count = Math.max(1, (plain.length + (1L << 20) - 1) / (1 << 20));
    for (long j = 0; j < count; j++) {
      int at = (int) (j * (1 << 20)), n = Math.min(1 << 20, plain.length - at);
      byte[] nonce = ByteBuffer.allocate(12).putInt(index).putLong(j).array();
      byte[] aad =
          concat(
              bytes("authgo-payload-chunk-v1\0"),
              p.payloadBinding(),
              nonce,
              new byte[] {(byte) (j == count - 1 ? 1 : 0)});
      var cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"), new GCMParameterSpec(128, nonce));
      cipher.updateAAD(aad);
      out.write(cipher.doFinal(plain, at, n));
    }
    return out.toByteArray();
  }

  static void chunks() throws Exception {
    var v = vector("payload-envelope.json");
    var p = Payload.parsePayload(canonical(v.get("payload")));
    equal(java.util.HexFormat.of().formatHex(p.payloadBinding()), v.get("binding_hex"));
    Map<Integer, ByteArrayOutputStream> cts = new HashMap<>(), plains = new HashMap<>();
    for (Object value : list(v.get("chunks"))) {
      var item = obj(value);
      int index = (int) num(item, "file");
      long j = num(item, "chunk");
      byte[] plain;
      if (item.containsKey("plain_hex")) plain = hex(item.get("plain_hex"));
      else {
        plain = new byte[(int) num(item, "plain_repeat_count")];
        Arrays.fill(plain, hex(item.get("plain_repeat_hex"))[0]);
      }
      byte[] nonce = ByteBuffer.allocate(12).putInt(index).putLong(j).array();
      byte[] aad =
          concat(
              bytes("authgo-payload-chunk-v1\0"),
              p.payloadBinding(),
              nonce,
              new byte[] {(byte) (yes(item, "last") ? 1 : 0)});
      same(nonce, hex(item.get("nonce_hex")));
      same(aad, hex(item.get("aad_hex")));
      var cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(
          Cipher.ENCRYPT_MODE,
          new SecretKeySpec(hex(v.get("content_key_hex")), "AES"),
          new GCMParameterSpec(128, nonce));
      cipher.updateAAD(aad);
      byte[] ct = cipher.doFinal(plain);
      if (item.containsKey("cipher_hex")) same(ct, hex(item.get("cipher_hex")));
      else {
        same(Arrays.copyOf(ct, 32), hex(item.get("cipher_first32_hex")));
        same(Arrays.copyOfRange(ct, ct.length - 16, ct.length), hex(item.get("tag_hex")));
        equal(hash(ct), item.get("cipher_sha256_hex"));
      }
      cts.computeIfAbsent(index, k -> new ByteArrayOutputStream()).write(ct);
      plains.computeIfAbsent(index, k -> new ByteArrayOutputStream()).write(plain);
    }
    for (var entry : cts.entrySet()) {
      var output = new ByteArrayOutputStream();
      PayloadFiles.decryptPayloadFile(
          output, entry.getValue().toByteArray(), p, KEY, entry.getKey());
      same(output.toByteArray(), plains.get(entry.getKey()).toByteArray());
      equal(PayloadFiles.payloadCipherSize(output.size()), (long) entry.getValue().size());
    }
    System.out.println(
        "{\"language\":\"java\",\"payload_chunks\":\"PASS\",\"vector\":\"payload-envelope\"}");
  }

  static byte[] mode(byte[] original, String name, int unixMode) {
    byte[] zip = original.clone();
    for (int i = 0; i < zip.length - 46; i++) {
      ByteBuffer b = ByteBuffer.wrap(zip).order(ByteOrder.LITTLE_ENDIAN);
      if (b.getInt(i) == 0x02014b50) {
        int n = Short.toUnsignedInt(b.getShort(i + 28));
        if (i + 46 + n <= zip.length
            && new String(zip, i + 46, n, java.nio.charset.StandardCharsets.UTF_8).equals(name)) {
          b.putShort(i + 4, (short) 0x0314);
          b.putInt(i + 38, unixMode << 16);
          return zip;
        }
      }
    }
    throw new AssertionError("central entry missing");
  }

  static byte[] replace(byte[] original, String before, String after) {
    check(before.length() == after.length());
    byte[] out = original.clone(), a = bytes(before), b = bytes(after);
    for (int i = 0; i <= out.length - a.length; i++) {
      boolean found = true;
      for (int j = 0; j < a.length; j++)
        if (out[i + j] != a[j]) {
          found = false;
          break;
        }
      if (found) System.arraycopy(b, 0, out, i, b.length);
    }
    return out;
  }

  static void delete(Path dir) throws IOException {
    try (var paths = Files.walk(dir)) {
      for (Path path : paths.sorted(java.util.Comparator.reverseOrder()).toList())
        Files.delete(path);
    }
  }

  static void bootstrapProcess(boolean refuse) throws Exception {
    byte[] jar =
        jar(
            compile(
                Map.of(
                    MAIN,
                    "package sample.deep; public class Entry { public static void main(String[]"
                        + " args)throws Exception {io.authgo.Guards.current().require();try(var"
                        + " in=Thread.currentThread().getContextClassLoader().getResourceAsStream(\"assets/nested/message.txt\")){System.setProperty(\"authgo.sealed.result\",new"
                        + " String(in.readAllBytes(),java.nio.charset.StandardCharsets.UTF_8)+\":\"+args[0]);}"
                        + " new Thread(()->{try{Thread.sleep(150);System.out.println(\"BOOT_WORKER_ACTIVE=\"+(io.authgo.Guards.current()!=null));}catch(InterruptedException"
                        + " e){Thread.currentThread().interrupt();}},\"business-worker\").start();}}")));
    Path dir = Files.createTempDirectory("authgo-bootstrap-");
    try {
      Payload payload = writeCurrentPayload(dir, jar, 0);
      String encoded = canonical(payload.toMap()).replace("\\", "\\\\").replace("\"", "\\\"");
      String source =
          "package io.authgo; public final class BuildConfig { private static PayloadTests.Server"
              + " server; public static GuardOptions options() {try { server=new"
              + " PayloadTests.Server(Payload.parsePayload(\""
              + encoded
              + "\")); server.code=\""
              + (refuse ? "LICENSE_REVOKED" : "")
              + "\"; var o=new"
              + " GuardOptions();o.config=\"authgo2.\"+Client.b64(Client.bytes(Client.canonical(server.config)));o.version=\"999.0.0\";o.license=PayloadTests.LICENSE;o.sdkOptions.fingerprint=PayloadTests.FP;o.sdkOptions.cacheDir=java.nio.file.Path.of(\"\");o.sdkOptions.clock=()->server.now;o.sdkOptions.httpClient=new"
              + " PayloadTests.Transport(server);Runtime.getRuntime().addShutdownHook(new"
              + " Thread(()->{System.out.println(\"BOOT_RESULT=\"+System.getProperty(\"authgo.sealed.result\"));System.out.println(\"BOOT_VERSION=\"+server.observedVersion);}));return"
              + " o;}catch(Exception e){throw new IllegalStateException(e);}}}";
      Map<String, byte[]> compiled = compile(Map.of("io.authgo.BuildConfig", source));
      Path configuration = dir.resolve("io/authgo/BuildConfig.class");
      Files.createDirectories(configuration.getParent());
      Files.write(configuration, compiled.get("io/authgo/BuildConfig.class"));
      String classpath = dir + java.io.File.pathSeparator + System.getProperty("java.class.path");
      var builder =
          new ProcessBuilder(
                  Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                  "-Xmx128m",
                  "-cp",
                  classpath,
                  "io.authgo.Bootstrap",
                  "argument")
              .redirectErrorStream(true);
      builder.environment().put("AUTHGO_PAYLOAD_DIR", dir.toString());
      Process process = builder.start();
      if (!process.waitFor(20, TimeUnit.SECONDS)) {
        process.destroyForcibly();
        throw new AssertionError("Bootstrap did not exit");
      }
      String output =
          new String(
              process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
      if (refuse) {
        equal(process.exitValue(), 77);
        check(output.contains("LICENSE_REVOKED"));
      } else {
        if (process.exitValue() != 0) throw new AssertionError(output);
        if (!output.contains("BOOT_RESULT=resource-in-memory:argument")
            || !output.contains("BOOT_VERSION=" + payload.version())
            || !output.contains("BOOT_WORKER_ACTIVE=true"))
          throw new AssertionError("Bootstrap probe: " + output);
      }
      check(!output.contains(PayloadTests.LICENSE));
      check(!output.contains("authgo2."));
    } finally {
      delete(dir);
    }
  }

  static void watermarkLoaderV2() throws Exception {
    String tag="a".repeat(32),slot=tag+"0".repeat(64);
    var source=new StringBuilder("package sample.deep; public class Entry { public static void main(String[] a){} public static String[] values(){return new String[]{");
    for(int i=0;i<8;i++){if(i!=0)source.append(',');source.append('"').append(i).append(slot).append('"');}source.append("};}}");
    var compiled=compile(Map.of(MAIN,source.toString()));byte[] code=compiled.get("sample/deep/Entry.class"),needle=bytes(slot);var offsets=new ArrayList<String>();
    for(int i=0;i<=code.length-96;i++)if(Arrays.equals(Arrays.copyOfRange(code,i,i+96),needle))offsets.add(Integer.toString(i));equal(offsets.size(),8);
    byte[] nested=jar(compiled),outer=jar(Map.of(),Map.of("lib/core.jar",nested),MANIFEST);
    byte[] privateIndex=bytes(canonical(map("v","1","tag",tag,"files",List.of(map("index","0","entries",List.of(map("path",List.of("lib/core.jar","sample/deep/Entry.class"),"offsets",offsets)))))));
    Payload old=payload(outer.length,0);var manifest=obj(parse(decode(old.manifest())));var files=new ArrayList<Object>(list(manifest.get("files")));files.removeIf(f->str(obj(f),"kind").equals("watermark"));
    files.add(map("name","__authgo_watermark","kind","watermark","path","00000001.agc","size",privateIndex.length,"chunk_size",1048576,"encoding","raw"));
    Payload p=new Payload(2,old.appKey(),old.version(),old.builtAt(),old.keyId(),old.config(),b64(bytes(canonical(map("files",files)))),old.envelope()).validated();
    Path dir=Files.createTempDirectory("authgo-watermark-loader-");
    try(var fixture=new Fixture()){
      Files.writeString(dir.resolve("payload.json"),canonical(p.toMap()));Files.write(dir.resolve("00000000.agc"),encrypt(p,0,outer));Files.write(dir.resolve("00000001.agc"),encrypt(p,1,privateIndex));
      try(var loader=Bootstrap.load(fixture.guard,"app",dir)){
        var values=(String[])loader.loadClass(MAIN).getMethod("values").invoke(null);
        for(String value:values)equal(value.substring(33),"19".repeat(32));
        check(loader.loadClass(MAIN).getClassLoader()==loader);
      }
      for(byte b:fixture.backend.returned)equal(b,(byte)0);
      // Tampered final offset rejects the entire load before defineClass.
      var bad=obj(parse(privateIndex));var f=obj(list(bad.get("files")).get(0));var e=obj(list(f.get("entries")).get(0));var badOffsets=new ArrayList<>(list(e.get("offsets")));badOffsets.set(7,"999999");e.put("offsets",badOffsets);
      error("PAYLOAD_INVALID",()->SealedClassLoader.openV2(fixture.guard,outer,MAIN,PayloadWatermark.parseIndex(bytes(canonical(bad)),PayloadFiles.files(p)),0,concat(KEY,java.util.HexFormat.of().parseHex("19".repeat(32)))));
    }finally{try(var paths=Files.walk(dir)){for(Path f:paths.sorted(java.util.Comparator.reverseOrder()).toList())Files.deleteIfExists(f);}}
  }

  public static void run() throws Exception {
    Map<String, byte[]> classes = compile();
    byte[] jar = jar(classes);
    runCase("Go chunk vectors", SealedTests::chunks);
    runCase("v2 nested JAR exact byte arrays patched before defineClass",SealedTests::watermarkLoaderV2);
    runCase(
        "nested package and inner class",
        () -> {
          try (var f = new Fixture()) {
            var loader = f.open(jar);
            var main = loader.loadClass(MAIN);
            equal(main.getMethod("marker").invoke(null), MARKER);
            equal(loader.loadClass(MAIN + "$Nested").getMethod("value").invoke(null), 17);
            check(main.getClassLoader() == loader);
          }
        });
    runCase(
        "resources through streams URLs and enumerations",
        () -> {
          try (var f = new Fixture()) {
            var loader = f.open(jar);
            same(
                loader.getResourceAsStream("assets/nested/message.txt").readAllBytes(),
                bytes("resource-in-memory"));
            var url = loader.getResource("assets/nested/message.txt");
            equal(url.getProtocol(), "authgo-sealed");
            same(url.openStream().readAllBytes(), bytes("resource-in-memory"));
            check(loader.getResources("assets/nested/message.txt").hasMoreElements());
            check(loader.getResourceAsStream("absent") == null);
          }
        });
    runCase(
        "Main-Class continuation arguments context and Guards.current",
        () -> {
          try (var f = new Fixture()) {
            Guards.bind(f.guard);
            var loader = f.open(jar);
            ClassLoader before = Thread.currentThread().getContextClassLoader();
            Bootstrap.invoke(loader, new String[] {"argument"});
            equal(System.getProperty("authgo.sealed.result"), "resource-in-memory:argument");
            check(Thread.currentThread().getContextClassLoader() == before);
            check(Guards.current() == f.guard);
          }
        });
    runCase(
        "original business main exception propagates",
        () -> {
          try (var f = new Fixture()) {
            byte[] bad =
                jar(
                    classes,
                    Map.of(),
                    "Manifest-Version: 1.0\r\nMain-Class: sample.deep.Throws\r\n\r\n");
            try (var loader = SealedClassLoader.open(f.guard, bad, "sample.deep.Throws")) {
              try {
                Bootstrap.invoke(loader, new String[0]);
                throw new AssertionError();
              } catch (IllegalStateException expected) {
                equal(expected.getMessage(), "business failure");
              }
            }
          }
        });
    runCase(
        "refusal blocks new and previously requested classes",
        () -> {
          try (var f = new Fixture()) {
            var loader = f.open(jar);
            loader.loadClass(MAIN);
            f.backend.refused = "LICENSE_REVOKED";
            error("LICENSE_REVOKED", () -> loader.loadClass("sample.deep.Later"));
            error("LICENSE_REVOKED", () -> loader.loadClass(MAIN));
          }
        });
    runCase(
        "refusal blocks pre-obtained resource stream and URL",
        () -> {
          try (var f = new Fixture()) {
            var loader = f.open(jar);
            var stream = loader.getResourceAsStream("assets/nested/message.txt");
            var url = loader.getResource("assets/nested/message.txt");
            f.backend.refused = "LICENSE_REVOKED";
            error("LICENSE_REVOKED", stream::read);
            error("LICENSE_REVOKED", url::openStream);
            error("LICENSE_REVOKED", () -> loader.getResources("assets/nested/message.txt"));
          }
        });
    runCase(
        "closed guard and closed loader gate",
        () -> {
          try (var f = new Fixture()) {
            var loader = f.open(jar);
            loader.close();
            error("SDK_NOT_ACTIVATED", () -> loader.loadClass(MAIN));
            f.guard.close();
            error("SDK_NOT_ACTIVATED", () -> f.open(jar));
          }
        });
    runCase(
        "parallel definition resolves a single Class",
        () -> {
          try (var f = new Fixture()) {
            var loader = f.open(jar);
            var pool = Executors.newFixedThreadPool(8);
            try {
              List<Callable<Class<?>>> jobs = new ArrayList<>();
              for (int i = 0; i < 32; i++) jobs.add(() -> loader.loadClass(MAIN));
              Class<?> expected = null;
              for (var future : pool.invokeAll(jobs)) {
                Class<?> value = future.get();
                if (expected == null) expected = value;
                check(value == expected);
              }
            } finally {
              pool.shutdownNow();
            }
          }
        });
    runCase(
        "unsafe paths and special ZIP entries rejected",
        () -> {
          try (var f = new Fixture()) {
            for (String name :
                List.of("../outside", "/absolute", "a/../bad", "a//bad", "a\\bad", "a:bad"))
              error(
                  "PAYLOAD_INVALID",
                  () -> f.open(jar(classes, Map.of(name, new byte[0]), MANIFEST)));
            for (int mode : new int[] {0120777, 0020600, 0060600, 0010600})
              error("PAYLOAD_INVALID", () -> f.open(mode(jar, "assets/nested/message.txt", mode)));
          }
        });
    runCase(
        "duplicate local and central names rejected",
        () -> {
          try (var f = new Fixture()) {
            byte[] duplicate =
                jar(
                    classes,
                    Map.of("assets/a.txt", bytes("a"), "assets/b.txt", bytes("b")),
                    MANIFEST);
            error(
                "PAYLOAD_INVALID",
                () -> f.open(replace(duplicate, "assets/b.txt", "assets/a.txt")));
            error(
                "PAYLOAD_INVALID",
                () ->
                    f.open(
                        jar(classes, Map.of("meta-inf/manifest.mf", bytes(MANIFEST)), MANIFEST)));
          }
        });
    runCase(
        "nested Spring Boot jars and multi-release rejected explicitly",
        () -> {
          try (var f = new Fixture()) {
            for (String path :
                List.of(
                    "BOOT-INF/classes/test",
                    "BOOT-INF/lib/dep.jar",
                    "lib/inner.jar",
                    "META-INF/versions/17/foo.class"))
              error(
                  "PAYLOAD_INVALID",
                  () -> f.open(jar(classes, Map.of(path, new byte[0]), MANIFEST)));
            try {
              f.open(jar(classes, Map.of("BOOT-INF/lib/a.jar", new byte[0]), MANIFEST));
              throw new AssertionError();
            } catch (AuthGoException expected) {
              check(Bootstrap.message(expected).contains("Spring Boot"));
            }
          }
        });
    runCase(
        "SDK classes cannot shadow public trust root",
        () -> {
          try (var f = new Fixture()) {
            error(
                "PAYLOAD_INVALID",
                () ->
                    f.open(jar(classes, Map.of("io/authgo/Client.class", new byte[1]), MANIFEST)));
          }
        });
    runCase(
        "manifest missing main or mismatch fails",
        () -> {
          try (var f = new Fixture()) {
            error(
                "PAYLOAD_INVALID",
                () -> f.open(jar(classes, Map.of(), "Manifest-Version: 1.0\r\n\r\n")));
            error("PAYLOAD_INVALID", () -> SealedClassLoader.open(f.guard, jar, "sample.Wrong"));
          }
        });
    runCase(
        "truncation corruption and invalid ZIP64 rejected",
        () -> {
          try (var f = new Fixture()) {
            error("PAYLOAD_INVALID", () -> f.open(Arrays.copyOf(jar, jar.length - 1)));
            byte[] broken = jar.clone();
            broken[0] = 0;
            error("PAYLOAD_INVALID", () -> f.open(broken));
            byte[] zip64 = jar.clone();
            ByteBuffer.wrap(zip64)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putInt(zip64.length - 22 + 16, -1);
            error("PAYLOAD_INVALID", () -> f.open(zip64));
          }
        });
    runCase(
        "central compressed lengths and CRC must match actual entries",
        () -> {
          try (var f = new Fixture()) {
            for (int field : new int[] {16, 20}) {
              byte[] bad = jar.clone();
              ByteBuffer view = ByteBuffer.wrap(bad).order(ByteOrder.LITTLE_ENDIAN);
              for (int i = 0; i < bad.length - 46; i++)
                if (view.getInt(i) == 0x02014b50) {
                  view.putInt(i + field, view.getInt(i + field) + 1);
                  break;
                }
              error("PAYLOAD_INVALID", () -> f.open(bad));
            }
          }
        });
    runCase(
        "chunk tampering key lengths and total lengths",
        () -> {
          Payload p = payload(3, 0);
          byte[] ct = encrypt(p, 0, bytes("abc"));
          for (byte[] bad :
              List.of(
                  Arrays.copyOf(ct, ct.length - 1), concat(ct, new byte[1]), new byte[ct.length]))
            error(
                "PAYLOAD_INVALID",
                () -> PayloadFiles.decryptPayloadFile(new ByteArrayOutputStream(), bad, p, KEY, 0));
          error(
              "PAYLOAD_INVALID",
              () ->
                  PayloadFiles.decryptPayloadFile(
                      new ByteArrayOutputStream(), ct, p, new byte[32], 0));
          error(
              "PAYLOAD_INVALID",
              () -> PayloadFiles.decryptPayloadFile(new ByteArrayOutputStream(), ct, p, KEY, -1));
          for (long size : new long[] {-1, Long.MAX_VALUE})
            error("PAYLOAD_INVALID", () -> PayloadFiles.payloadCipherSize(size));
        });
    runCase(
        "block authentication before output and reordered chunks",
        () -> {
          byte[] plain = new byte[(1 << 20) + 3];
          Payload p = payload(plain.length, 0);
          byte[] ct = encrypt(p, 0, plain);
          ct[ct.length - 1] ^= 1;
          var out = new ByteArrayOutputStream();
          error("PAYLOAD_INVALID", () -> PayloadFiles.decryptPayloadFile(out, ct, p, KEY, 0));
          equal(out.size(), 1 << 20);
          byte[] many = new byte[3 << 20];
          Payload mp = payload(many.length, 0);
          byte[] mc = encrypt(mp, 0, many);
          int stride = (1 << 20) + 16;
          byte[] reordered =
              concat(
                  Arrays.copyOfRange(mc, stride, 2 * stride),
                  Arrays.copyOfRange(mc, 0, stride),
                  Arrays.copyOfRange(mc, 2 * stride, mc.length));
          error(
              "PAYLOAD_INVALID",
              () ->
                  PayloadFiles.decryptPayloadFile(
                      new ByteArrayOutputStream(), reordered, mp, KEY, 0));
        });
    runCase(
        "streaming input never requests a whole large file",
        () -> {
          byte[] plain = new byte[(2 << 20) + 5];
          Payload p = payload(plain.length, 0);
          byte[] ct = encrypt(p, 0, plain);
          var source =
              new ByteArrayInputStream(ct) {
                @Override
                public synchronized int read(byte[] target, int at, int length) {
                  check(length <= (1 << 20) + 16);
                  return super.read(target, at, length);
                }
              };
          var out = new ByteArrayOutputStream();
          PayloadFiles.decryptPayloadFile(out, source, ct.length, p, KEY, 0);
          same(out.toByteArray(), plain);
        });
    runCase(
        "Bootstrap decrypts selected index and leaves disk ciphertext-only",
        () -> {
          try (var f = new Fixture()) {
            Path dir = Files.createTempDirectory("authgo-sealed-");
            try {
              Payload p = writeCurrentPayload(dir, jar, 1);
              Map<Path, byte[]> before = new HashMap<>();
              try (var paths = Files.list(dir)) {
                for (Path path : paths.toList()) before.put(path, Files.readAllBytes(path));
              }
              try (var loader = Bootstrap.load(f.guard, "app", dir)) {
                equal(loader.loadClass(MAIN).getMethod("marker").invoke(null), MARKER);
              }
              equal(f.backend.unlocks.get(), 1);
              check(Arrays.equals(f.backend.returned, new byte[64]));
              try (var paths = Files.list(dir)) {
                equal(paths.count(), 3L);
              }
              for (var entry : before.entrySet()) {
                same(Files.readAllBytes(entry.getKey()), entry.getValue());
                check(
                    !new String(entry.getValue(), java.nio.charset.StandardCharsets.ISO_8859_1)
                        .contains(MARKER));
              }
            } finally {
              delete(dir);
            }
          }
        });
    runCase(
        "refusal after key acquisition never publishes classes and wipes key",
        () -> {
          try (var f = new Fixture()) {
            Path dir = Files.createTempDirectory("authgo-sealed-");
            var pool = Executors.newSingleThreadExecutor();
            try {
              Payload p = writeCurrentPayload(dir, jar, 0);
              f.backend.entered = new CountDownLatch(1);
              f.backend.release = new CountDownLatch(1);
              var loading = pool.submit(() -> Bootstrap.load(f.guard, "app", dir));
              check(f.backend.entered.await(2, TimeUnit.SECONDS));
              f.backend.refused = "LICENSE_REVOKED";
              f.backend.release.countDown();
              try {
                loading.get(3, TimeUnit.SECONDS);
                throw new AssertionError();
              } catch (java.util.concurrent.ExecutionException expected) {
                check(expected.getCause() instanceof AuthGoException);
                equal(((AuthGoException) expected.getCause()).code, "LICENSE_REVOKED");
              }
              check(Arrays.equals(f.backend.returned, new byte[64]));
            } finally {
              if (f.backend.release != null) f.backend.release.countDown();
              pool.shutdownNow();
              delete(dir);
            }
          }
        });
    runCase(
        "real Bootstrap Main-Class and compiled config with authenticated HTTP seam",
        () -> bootstrapProcess(false));
    runCase("Bootstrap refusal exits 77 without logging credentials", () -> bootstrapProcess(true));
    runCase(
        "closed loader zeroes retained entries",
        () -> {
          try (var f = new Fixture()) {
            var loader = f.open(jar);
            var entriesField = SealedClassLoader.class.getDeclaredField("entries");
            entriesField.setAccessible(true);
            Object raw = entriesField.get(loader);
            check(raw instanceof Map<?, ?>);
            Map<?, ?> entries = (Map<?, ?>) raw;
            Object first = entries.values().iterator().next();
            check(first instanceof byte[]);
            byte[] retained = (byte[]) first;
            loader.close();
            check(Arrays.equals(retained, new byte[retained.length]));
          }
        });
    runCase(
        "Guards.current absent conflict and safe diagnostics",
        () -> {
          error("SDK_NOT_ACTIVATED", Guards::current);
          try (var f = new Fixture()) {
            Guards.bind(f.guard);
            try {
              Guards.bind(f.guard);
              throw new AssertionError();
            } catch (IllegalStateException expected) {
              check(true);
            }
            Guards.clear(f.guard);
          }
          check(
              !Bootstrap.message(new IllegalStateException("AUTH-SHOULD-NOT-APPEAR"))
                  .contains("AUTH-SHOULD-NOT-APPEAR"));
        });
    System.out.println(
        "{\"language\":\"java\",\"sealed_tests\":" + cases + ",\"result\":\"PASS\"}");
  }

  public static void main(String[] args) throws Exception {
    run();
  }
}
