package io.authgo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Set;
import java.util.jar.Manifest;
import java.util.zip.CRC32;
import java.util.zip.ZipInputStream;

/** In-memory ordinary JAR loader. It never extracts entries or creates files. */
public final class SealedClassLoader extends ClassLoader implements AutoCloseable {
  static {
    registerAsParallelCapable();
  }

  private final Guard guard;
  private final Map<String, byte[]> entries;
  private final String mainClass;
  private boolean closed;

  private SealedClassLoader(Guard guard, Map<String, byte[]> entries, String mainClass) {
    super(SealedClassLoader.class.getClassLoader());
    this.guard = guard;
    this.entries = entries;
    this.mainClass = mainClass;
  }

  public String mainClass() {
    active();
    return mainClass;
  }

  void checkAccess() {
    active();
  }

  private void active() {
    guard.require();
    synchronized (entries) {
      if (closed) throw new Client.AuthGoException("SDK_NOT_ACTIVATED");
    }
  }

  static final class UnsupportedFormatException extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    UnsupportedFormatException(String message) {
      super(message);
    }
  }

  static Client.AuthGoException unsupported(String message) {
    return new Client.AuthGoException(
        "PAYLOAD_INVALID", false, new UnsupportedFormatException(message));
  }

  private record Entry(String name, long size, long compressed, long crc, int offset) {}

  private static int u16(byte[] b, int at) {
    bounds(b, at, 2);
    return Short.toUnsignedInt(ByteBuffer.wrap(b, at, 2).order(ByteOrder.LITTLE_ENDIAN).getShort());
  }

  private static long u32(byte[] b, int at) {
    bounds(b, at, 4);
    return Integer.toUnsignedLong(
        ByteBuffer.wrap(b, at, 4).order(ByteOrder.LITTLE_ENDIAN).getInt());
  }

  private static void bounds(byte[] b, int at, long length) {
    if (at < 0 || length < 0 || at + length > b.length) throw Payload.invalid();
  }

  private static String name(byte[] b, int at, int length) {
    bounds(b, at, length);
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(b, at, length))
          .toString();
    } catch (CharacterCodingException failure) {
      throw Payload.invalid();
    }
  }

  private static String safe(String value) {
    String n = value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    if (n.isEmpty()
        || n.startsWith("/")
        || n.contains("\\")
        || n.contains(":")
        || n.indexOf('\0') >= 0) throw Payload.invalid();
    for (String part : n.split("/", -1))
      if (part.isEmpty() || part.equals(".") || part.equals("..")) throw Payload.invalid();
    return n;
  }

  private static Map<String, Entry> directory(byte[] jar) {
    // Inspect central Unix mode bits: ZipInputStream alone cannot reject links.
    int end = -1;
    for (int i = jar.length - 22; i >= Math.max(0, jar.length - 65557); i--) {
      if (u32(jar, i) == 0x06054b50L && i + 22L + u16(jar, i + 20) == jar.length) {
        end = i;
        break;
      }
    }
    if (end < 0
        || u16(jar, end + 4) != 0
        || u16(jar, end + 6) != 0
        || u16(jar, end + 8) != u16(jar, end + 10)) throw Payload.invalid();
    int count = u16(jar, end + 10);
    long length = u32(jar, end + 12), start = u32(jar, end + 16);
    if (count == 65535 || length == 0xffffffffL || start == 0xffffffffL)
      throw unsupported("不支持 ZIP64，请使用普通 JAR");
    if (start + length != end || count == 0 || start > Integer.MAX_VALUE) throw Payload.invalid();
    int at = (int) start;
    Map<String, Entry> result = new HashMap<>();
    Set<String> normalized = new HashSet<>();
    List<long[]> ranges = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      bounds(jar, at, 46);
      if (u32(jar, at) != 0x02014b50L) throw Payload.invalid();
      int flags = u16(jar, at + 8),
          method = u16(jar, at + 10),
          n = u16(jar, at + 28),
          extra = u16(jar, at + 30),
          comment = u16(jar, at + 32);
      int mode = (int) (u32(jar, at + 38) >>> 16), type = mode & 0170000;
      long size = u32(jar, at + 24), compressed = u32(jar, at + 20), local = u32(jar, at + 42);
      if ((flags & ~0x0808) != 0
          || (method != 0 && method != 8)
          || u16(jar, at + 34) != 0
          || size >= Integer.MAX_VALUE
          || compressed == 0xffffffffL
          || local > Integer.MAX_VALUE
          || (type != 0 && type != 0100000 && type != 0040000)) throw Payload.invalid();
      String value = name(jar, at + 46, n), clean = safe(value);
      if (!normalized.add(clean)
          || ((type == 0040000 || (u32(jar, at + 38) & 16) != 0) && !value.endsWith("/"))
          || (type == 0100000 && value.endsWith("/"))) throw Payload.invalid();
      int offset = (int) local;
      bounds(jar, offset, 30);
      if (u32(jar, offset) != 0x04034b50L
          || u16(jar, offset + 6) != flags
          || u16(jar, offset + 8) != method
          || !name(jar, offset + 30, u16(jar, offset + 26)).equals(value)) throw Payload.invalid();
      long data = offset + 30L + u16(jar, offset + 26) + u16(jar, offset + 28),
          finish = data + compressed;
      if (finish > start || offset >= start) throw Payload.invalid();
      ranges.add(new long[] {offset, finish});
      result.put(value, new Entry(value, size, compressed, u32(jar, at + 16), offset));
      at = Math.addExact(at, 46 + n + extra + comment);
      if (at > end) throw Payload.invalid();
    }
    if (at != end) throw Payload.invalid();
    ranges.sort((a, b) -> Long.compare(a[0], b[0]));
    for (int i = 1; i < ranges.size(); i++)
      if (ranges.get(i)[0] < ranges.get(i - 1)[1]) throw Payload.invalid();
    return result;
  }

  /** Consumes an authenticated JAR; caller remains responsible for clearing it. */
  public static SealedClassLoader open(Guard guard, byte[] jar, String expectedMain) {
    guard.require();
    Map<String, byte[]> entries = new HashMap<>();
    try {
      Map<String, Entry> directory = directory(jar);
      Set<String> seen = new HashSet<>();
      String manifestName = null;
      try (var zip = new ZipInputStream(new ByteArrayInputStream(jar), StandardCharsets.UTF_8)) {
        for (var member = zip.getNextEntry(); member != null; member = zip.getNextEntry()) {
          String n = member.getName();
          Entry expected = directory.get(n);
          if (expected == null || !seen.add(n)) throw Payload.invalid();
          if (n.endsWith(".jar")
              || n.startsWith("BOOT-INF/")
              || n.startsWith("WEB-INF/")
              || n.startsWith("META-INF/versions/"))
            throw unsupported("不支持 Spring Boot 嵌套 JAR、WAR 或多版本 JAR，请发布普通展开依赖的 JAR");
          if (n.startsWith("io/authgo/") && n.endsWith(".class"))
            throw unsupported("业务 JAR 不能包含或覆盖 Auth Go SDK 类");
          byte[] value;
          try (var out = new WipingBuffer()) {
            byte[] block = new byte[8192];
            try {
              for (int count = zip.read(block); count != -1; count = zip.read(block)) {
                if ((long) out.size() + count > expected.size()) throw Payload.invalid();
                out.write(block, 0, count);
              }
              value = out.toByteArray();
            } finally {
              Arrays.fill(block, (byte) 0);
            }
          }
          CRC32 crc = new CRC32();
          crc.update(value);
          if (value.length != expected.size()
              || crc.getValue() != expected.crc()
              || member.getCompressedSize() != expected.compressed()
              || member.getSize() != expected.size()
              || member.getCrc() != expected.crc()) {
            Arrays.fill(value, (byte) 0);
            throw Payload.invalid();
          }
          if (member.isDirectory()) {
            if (value.length != 0) {
              Arrays.fill(value, (byte) 0);
              throw Payload.invalid();
            }
            continue;
          }
          entries.put(n, value);
          if (n.equalsIgnoreCase("META-INF/MANIFEST.MF")) {
            if (manifestName != null) throw Payload.invalid();
            manifestName = n;
          }
        }
      }
      if (seen.size() != directory.size() || manifestName == null) throw Payload.invalid();
      Manifest manifest = new Manifest(new ByteArrayInputStream(entries.get(manifestName)));
      String main = manifest.getMainAttributes().getValue("Main-Class");
      if (main == null
          || main.isBlank()
          || !main.equals(expectedMain)
          || !entries.containsKey(main.replace('.', '/') + ".class")) throw Payload.invalid();
      if ("true".equalsIgnoreCase(manifest.getMainAttributes().getValue("Multi-Release")))
        throw unsupported("不支持多版本 JAR，请使用当前运行 JDK 的普通 JAR");
      guard.require();
      return new SealedClassLoader(guard, entries, main);
    } catch (Client.AuthGoException failure) {
      wipe(entries);
      throw failure;
    } catch (Exception failure) {
      wipe(entries);
      throw Payload.invalid();
    }
  }

  /** v2 extracts once: the bytes checked/stamped here are exactly those passed to defineClass. */
  static SealedClassLoader openV2(Guard guard, byte[] jar, String expectedMain,
      PayloadWatermark.Index index, int fileIndex, byte[] material) {
    guard.require(); Map<String,byte[]> entries=new HashMap<>();
    Map<List<String>,byte[]> targets=new HashMap<>(); long[] budget={0,0};
    try {
      collectV2(jar,List.of(),entries,targets,budget);
      byte[] raw=entries.get("META-INF/MANIFEST.MF");if(raw==null)throw Payload.invalid();
      Manifest manifest=new Manifest(new ByteArrayInputStream(raw));
      String main=manifest.getMainAttributes().getValue("Main-Class"), start=manifest.getMainAttributes().getValue("Start-Class");
      if(expectedMain==null || !(expectedMain.equals(main)||expectedMain.equals(start)) || !entries.containsKey(expectedMain.replace('.', '/')+".class"))throw Payload.invalid();
      var pending=PayloadWatermark.prepare(targets,index,fileIndex);
      PayloadWatermark.apply(pending,material); guard.require();
      return new SealedClassLoader(guard,entries,expectedMain);
    }catch(Exception failure){wipe(entries);throw Payload.invalid();}
  }
  private static void collectV2(byte[] jar,List<String> prefix,Map<String,byte[]> entries,
      Map<List<String>,byte[]> targets,long[] budget) throws IOException {
    if(prefix.size()>=8)throw Payload.invalid();
    var directory=directory(jar);Set<String> seen=new HashSet<>(), aliases=new HashSet<>();
    for(String n:directory.keySet())if(!aliases.add(n.toLowerCase(Locale.ROOT)))throw Payload.invalid();
    try(var zip=new ZipInputStream(new ByteArrayInputStream(jar),StandardCharsets.UTF_8)){
      for(var member=zip.getNextEntry();member!=null;member=zip.getNextEntry()){
        String n=member.getName();Entry expected=directory.get(n);
        if(expected==null||!seen.add(n)||++budget[0]>65535||n.startsWith("META-INF/versions/"))throw Payload.invalid();
        byte[] value;
        try(var out=new WipingBuffer()){
          byte[] block=new byte[8192];try{for(int count=zip.read(block);count!=-1;count=zip.read(block)){
            budget[1]=Math.addExact(budget[1],count);
            if((long)out.size()+count>expected.size()||budget[1]>(256L<<20))throw Payload.invalid();out.write(block,0,count);
          }value=out.toByteArray();}finally{Arrays.fill(block,(byte)0);}
        }
        boolean retained=false;
        try {
          CRC32 crc=new CRC32();crc.update(value);
          if(value.length!=expected.size()||crc.getValue()!=expected.crc()||member.getSize()!=expected.size()||member.getCompressedSize()!=expected.compressed()||member.getCrc()!=expected.crc())throw Payload.invalid();
          if(member.isDirectory()){if(value.length!=0)throw Payload.invalid();continue;}
          PayloadWatermark.safe(n);List<String> path=new ArrayList<>(prefix);path.add(n);
          if(n.toLowerCase(Locale.ROOT).endsWith(".jar")){collectV2(value,List.copyOf(path),entries,targets,budget);continue;}
          String resource=n.startsWith("BOOT-INF/classes/")?n.substring(17):n.startsWith("WEB-INF/classes/")?n.substring(16):n;
          if(resource.startsWith("io/authgo/")&&resource.endsWith(".class"))throw Payload.invalid();
          if(resource.equalsIgnoreCase("META-INF/MANIFEST.MF")){
            Manifest manifest=new Manifest(new ByteArrayInputStream(value));
            if("true".equalsIgnoreCase(manifest.getMainAttributes().getValue("Multi-Release")))throw Payload.invalid();
            if(!prefix.isEmpty())continue;
          }
          if(entries.containsKey(resource)) {
            if(resource.endsWith(".class"))throw Payload.invalid();
            continue; // Class-path order for repeated dependency resources (LICENSE/services, etc.).
          }
          if(entries.keySet().stream().anyMatch(k->k.equalsIgnoreCase(resource)))throw Payload.invalid();
          entries.put(resource,value);if(resource.endsWith(".class"))targets.put(List.copyOf(path),value);retained=true;
        }finally{if(!retained)Arrays.fill(value,(byte)0);}
      }
    }
    if(seen.size()!=directory.size())throw Payload.invalid();
  }

  @Override
  protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
    active();
    synchronized (getClassLoadingLock(name)) {
      Class<?> found = findLoadedClass(name);
      if (found == null) {
        String resource = name.replace('.', '/') + ".class";
        boolean owned;
        synchronized (entries) {
          owned = entries.containsKey(resource);
        }
        if (owned
            && !name.startsWith("java.")
            && !name.startsWith("javax.")
            && !name.startsWith("jdk.")
            && !name.startsWith("sun.")
            && !name.startsWith("io.authgo.")) found = findClass(name);
        else found = super.loadClass(name, false);
      }
      if (resolve) resolveClass(found);
      return found;
    }
  }

  @Override
  protected Class<?> findClass(String name) throws ClassNotFoundException {
    active();
    synchronized (entries) {
      if (closed) throw new Client.AuthGoException("SDK_NOT_ACTIVATED");
      byte[] value = entries.get(name.replace('.', '/') + ".class");
      if (value == null) throw new ClassNotFoundException(name);
      return defineClass(name, value, 0, value.length);
    }
  }

  private InputStream stream(String name) {
    active();
    synchronized (entries) {
      if (!entries.containsKey(name)) return null;
    }
    return new InputStream() {
      private int offset;
      private boolean stopped;

      @Override
      public int read() {
        byte[] one = new byte[1];
        int count = read(one, 0, 1);
        return count == -1 ? -1 : Byte.toUnsignedInt(one[0]);
      }

      @Override
      public int read(byte[] target, int at, int length) {
        java.util.Objects.checkFromIndexSize(at, length, target.length);
        active();
        synchronized (entries) {
          if (stopped) throw new IllegalStateException("资源流已关闭");
          byte[] value = entries.get(name);
          if (value == null) throw new Client.AuthGoException("SDK_NOT_ACTIVATED");
          if (length == 0) return 0;
          if (offset == value.length) return -1;
          int count = Math.min(length, value.length - offset);
          System.arraycopy(value, offset, target, at, count);
          offset += count;
          return count;
        }
      }

      @Override
      public void close() {
        synchronized (entries) {
          stopped = true;
        }
      }
    };
  }

  @Override
  public InputStream getResourceAsStream(String name) {
    active();
    InputStream result = stream(name);
    return result == null ? super.getResourceAsStream(name) : result;
  }

  @Override
  // Java <20 lacks a replacement custom-handler URL API; suppress here to retain Java 17+ support.
  @SuppressWarnings("deprecation")
  public URL getResource(String name) {
    active();
    synchronized (entries) {
      if (!entries.containsKey(name)) return super.getResource(name);
    }
    try {
      return new URL(
          null,
          new URI("authgo-sealed", null, "/" + name, null).toASCIIString(),
          new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL url) {
              return new URLConnection(url) {
                @Override
                public void connect() {
                  active();
                  connected = true;
                }

                @Override
                public InputStream getInputStream() {
                  connect();
                  return stream(name);
                }
              };
            }
          });
    } catch (Exception failure) {
      throw Payload.invalid();
    }
  }

  @Override
  public Enumeration<URL> getResources(String name) throws IOException {
    active();
    List<URL> found = new ArrayList<>();
    synchronized (entries) {
      if (entries.containsKey(name)) found.add(getResource(name));
    }
    found.addAll(Collections.list(super.getResources(name)));
    return Collections.enumeration(found);
  }

  private static void wipe(Map<String, byte[]> entries) {
    for (byte[] value : entries.values()) Arrays.fill(value, (byte) 0);
    entries.clear();
  }

  @Override
  public void close() {
    synchronized (entries) {
      closed = true;
      wipe(entries);
    }
  }

  static final class WipingBuffer extends ByteArrayOutputStream {
    private void grow(int additional) {
      int needed = Math.addExact(count, additional);
      if (needed <= buf.length) return;
      int capacity =
          buf.length > Integer.MAX_VALUE / 2 ? Integer.MAX_VALUE : Math.max(32, buf.length * 2);
      byte[] next = Arrays.copyOf(buf, Math.max(needed, capacity));
      Arrays.fill(buf, (byte) 0);
      buf = next;
    }

    @Override
    public synchronized void write(int value) {
      grow(1);
      buf[count++] = (byte) value;
    }

    @Override
    public synchronized void write(byte[] value, int at, int length) {
      java.util.Objects.checkFromIndexSize(at, length, value.length);
      grow(length);
      System.arraycopy(value, at, buf, count, length);
      count += length;
    }

    @Override
    public synchronized void close() {
      Arrays.fill(buf, (byte) 0);
      reset();
    }
  }
}
