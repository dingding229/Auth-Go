package io.authgo;

import java.io.*;
import java.math.BigDecimal;
import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.spec.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.LongSupplier;
import java.util.regex.*;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Synchronous, dependency-free Java 17 SDK. Never log the configuration string. */
public final class Client {

  public static final Set<String> TEMPORARY = Set.of(
    "INTERNAL_ERROR",
    "RATE_LIMITED",
    "REPLAY_DETECTED",
    "TIMESTAMP_INVALID",
    "SIGNATURE_INVALID",
    "INVALID_REQUEST",
    "PAYLOAD_INVALID"
  );

  public static final class AuthGoException extends RuntimeException {

    private static final long serialVersionUID = 1L;
    public final String code;
    public final boolean authenticated;
    public String latestVersion = "";
    public String latestEntitledVersion = "";

    public AuthGoException(String code) {
      this(code, false, null);
    }

    public AuthGoException(
      String code,
      boolean authenticated,
      Throwable cause
    ) {
      super(
        code +
          (code.equals("SDK_INVALID_CONFIG")
            ? ": 请在后台重新复制接入配置"
            : ""),
        cause
      );
      this.code = code;
      this.authenticated = authenticated;
    }

    public String code() {
      return code;
    }

    public boolean refusal() {
      return authenticated && !TEMPORARY.contains(code);
    }
  }

  public static final class Options {

    public String fingerprint;
    public Path cacheDir;
    public String version = "";
    public LongSupplier clock = () -> Instant.now().getEpochSecond();
    public HttpClient httpClient;
  }

  public static final class Result {

    public final Map<String, Object> data;
    public final String status, reason;
    public final String maintenanceUntil, latestEntitledVersion;
    public final boolean offline;
    public final boolean isTrial;
    public final String cacheWarning;
    public final long heartbeatInterval;
    private final Client client;
    private final String ticket;
    private final byte[] seed;
    private final long end;

    Result(
      Client c,
      Map<String, Object> d,
      String t,
      byte[] seed,
      String status,
      long end,
      String reason
    ) {
      this.client = c;
      this.cacheWarning = c.cacheWarning;
      this.data = obj(parse(bytes(canonical(d))));
      this.maintenanceUntil = str(d,"maintenance_until");
      this.latestEntitledVersion = str(d,"latest_entitled_version");
      this.heartbeatInterval = heartbeat(d, num(c.state,"heartbeat_interval"));
      this.ticket = t;
      this.seed = seed.clone();
      this.status = status;
      this.offline = !status.equals("online");
      this.isTrial = yes(d,"is_trial");
      this.end = end;
      this.reason = reason;
    }

    private Result(Result other) {
      client=other.client; data=obj(parse(bytes(canonical(other.data))));ticket=other.ticket;
      seed=other.seed.clone();status=other.status;offline=other.offline;end=other.end;
      maintenanceUntil=other.maintenanceUntil;latestEntitledVersion=other.latestEntitledVersion;
      isTrial=other.isTrial;reason=other.reason;cacheWarning=other.cacheWarning;heartbeatInterval=other.heartbeatInterval;
    }
    Result snapshot() { return new Result(this); }
    long usableUntil() { return end; }

    public String ticket() {
      return ticket;
    }

  }

  private final Map<String, Object> config;
  private final String endpoint, fp;
  private final byte[] publicKey, gateway, aad, cacheKey;
  private final Path cache;
  private final Options options;
  private final HttpClient http;
  private Map<String, Object> state = new TreeMap<>();
  private long onlineUntil;
  private String onlineTicket = "", offlineTicket = "";
  private long offlineUntil;
  private boolean memoryCache;
  private boolean payloadReady, payloadNoCache;
  final PayloadCache payloadCache;
  public String cacheWarning = "";

  public Client(String config) {
    this(config, new Options());
  }

  public Client(String configuration, Options settings) {
    options = settings;
    try {
      if (
        configuration.length() > 32768 || !configuration.startsWith("authgo2.")
      ) throw new Exception();
      config = obj(parse(decode(configuration.substring(8))));
      if (
        !Set.of(
          "url",
          "app_key",
          "app_secret",
          "public_key",
          "gateway_key"
                  ).containsAll(config.keySet())
      ) throw new Exception();
      for (String k : List.of(
        "url",
        "app_key",
        "app_secret",
        "public_key",
        "gateway_key"
      ))
        if (str(config, k).isEmpty()) throw new Exception();
      URI uri = URI.create(str(config, "url"));
      validUrl(uri, false);
      publicKey = standard(str(config, "public_key"));
      gateway = decode(str(config, "gateway_key"));
      if (publicKey.length != 32 || gateway.length != 32) throw new Exception();
      String base = str(config, "url").replaceAll("/+$", "");
      endpoint = base.endsWith("/api/v1/client")
        ? base
        : base + "/api/v1/client";
    } catch (Exception e) {
      throw fail("SDK_INVALID_CONFIG");
    }
    boolean container = ContainerIdentity.detect();
    String home = System.getProperty("user.home"),
      root = System.getenv("XDG_CACHE_HOME");
    if (osName().equals("windows")) root = System.getenv("LOCALAPPDATA");
    else if (osName().equals("darwin")) root = home + "/Library/Caches";
    if (root == null || root.isEmpty()) root = home + "/.cache";
    String envDir = System.getenv("AUTHGO_CACHE_DIR"), envId = System.getenv("AUTHGO_INSTANCE_ID");
    Path dir = settings.cacheDir != null ? settings.cacheDir : envDir != null && !envDir.isEmpty() ? Path.of(envDir) : container ? Path.of("/var/lib/authgo") : Path.of(root,"authgo",hash(bytes(str(config,"app_key"))));
    memoryCache = dir.toString().isEmpty();
    if(options.fingerprint != null) fp=options.fingerprint.toLowerCase(Locale.ROOT);
    else if(envId != null && !envId.isEmpty())fp=ContainerIdentity.hash(envId);
    else if(container){var identity=ContainerIdentity.load(dir);fp=ContainerIdentity.hash(identity.id());memoryCache=identity.memory();if(memoryCache)cacheWarning="此实例重启后是新实例，没有断连宽限";}
    else fp=fingerprint();
    if(!fp.matches("[a-f0-9]{64}"))throw fail("SDK_INVALID_CONFIG");
    aad = bytes(
      "authgo/java/cache/v2\0" +
        endpoint +
        "\0" +
        str(config, "app_key") +
        "\0" +
        fp
    );
    cacheKey = hkdf(
      bytes(str(config, "app_secret")),
      digest(aad),
      bytes("authgo/multi/cache/key"),
      32
    );
    payloadCache = new PayloadCache(dir, endpoint, str(config,"app_key"), fp, publicKey);
    cache = dir.resolve(hash(aad) + ".cache");
    http =
      options.httpClient == null
        ? HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(10))
            .build()
        : options.httpClient;
    try {
      if (!memoryCache && Files.exists(cache) && Files.size(cache) <= 16777216) {
        byte[] b = Files.readAllBytes(cache);
        state = obj(
          parse(
            open(
              cacheKey,
              Arrays.copyOf(b, 12),
              Arrays.copyOfRange(b, 12, b.length),
              aad
            )
          )
        );
      }
    } catch (Exception ignored) {
      state = new TreeMap<>();
    }
  }

  static AuthGoException fail(String c) {
    return new AuthGoException(c);
  }

  long now() {
    return options.clock.getAsLong();
  }

  public static byte[] bytes(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  public static String b64(byte[] b) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
  }

  public static byte[] decode(String s) {
    try {
      byte[] b = Base64.getUrlDecoder().decode(s);
      if (!b64(b).equals(s)) throw new Exception();
      return b;
    } catch (Exception e) {
      throw fail("SDK_RESPONSE_INVALID");
    }
  }

  static byte[] standard(String s) {
    try {
      byte[] b = Base64.getDecoder().decode(s);
      if (
        !Base64.getEncoder().encodeToString(b).equals(s)
      ) throw new Exception();
      return b;
    } catch (Exception e) {
      throw fail("SDK_RESPONSE_INVALID");
    }
  }

  static byte[] digest(byte[] b) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(b);
    } catch (Exception e) {
      throw fail("SDK_RESPONSE_INVALID");
    }
  }

  public static String hash(byte[] b) {
    return HexFormat.of().formatHex(digest(b));
  }

  static byte[] random(int n) {
    byte[] b = new byte[n];
    new SecureRandom().nextBytes(b);
    return b;
  }

  static byte[] concat(byte[]... arrays) {
    ByteArrayOutputStream b = new ByteArrayOutputStream();
    for (byte[] a : arrays) b.writeBytes(a);
    return b.toByteArray();
  }

  static byte[] hmac(byte[] key, byte[] data) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(
        new SecretKeySpec(key.length == 0 ? new byte[32] : key, "HmacSHA256")
      );
      return mac.doFinal(data);
    } catch (Exception e) {
      throw fail("SDK_RESPONSE_INVALID");
    }
  }

  public static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int length) {
    byte[] prk = hmac(salt, ikm),
      out = new byte[0],
      last = new byte[0];
    for (int i = 1; out.length < length; i++) {
      last = hmac(prk, concat(last, info, new byte[] { (byte) i }));
      out = concat(out, last);
    }
    return Arrays.copyOf(out, length);
  }

  public static byte[] seal(byte[] key, byte[] n, byte[] b, byte[] aad) {
    return aes(Cipher.ENCRYPT_MODE, key, n, b, aad);
  }

  public static byte[] open(byte[] key, byte[] n, byte[] b, byte[] aad) {
    return aes(Cipher.DECRYPT_MODE, key, n, b, aad);
  }

  static byte[] aes(int mode, byte[] key, byte[] n, byte[] b, byte[] aad) {
    try {
      if (n.length != 12) throw new Exception();
      Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
      c.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, n));
      c.updateAAD(aad);
      return c.doFinal(b);
    } catch (Exception e) {
      throw fail("SDK_RESPONSE_INVALID");
    }
  }

  public static boolean verifySignature(byte[] key, byte[] data, byte[] sig) {
    try {
      var pk = KeyFactory.getInstance("Ed25519").generatePublic(
        new X509EncodedKeySpec(
          concat(HexFormat.of().parseHex("302a300506032b6570032100"), key)
        )
      );
      Signature s = Signature.getInstance("Ed25519");
      s.initVerify(pk);
      s.update(data);
      return s.verify(sig);
    } catch (Exception e) {
      return false;
    }
  }

  public static byte[] shared(byte[] secret, byte[] publicKey) {
    try {
      PrivateKey p = KeyFactory.getInstance("X25519").generatePrivate(
        new PKCS8EncodedKeySpec(
          concat(
            HexFormat.of().parseHex("302e020100300506032b656e04220420"),
            secret
          )
        )
      );
      var pub = KeyFactory.getInstance("X25519").generatePublic(
        new X509EncodedKeySpec(
          concat(HexFormat.of().parseHex("302a300506032b656e032100"), publicKey)
        )
      );
      KeyAgreement ka = KeyAgreement.getInstance("X25519");
      ka.init(p);
      ka.doPhase(pub, true);
      return ka.generateSecret();
    } catch (Exception e) {
      throw fail("SDK_RESPONSE_INVALID");
    }
  }

  public static byte[] pad(byte[] raw) {
    int n = Math.max(4096, ((raw.length + 4 + 511) / 512) * 512);
    byte[] out = random(n);
    ByteBuffer.wrap(out).putInt(raw.length);
    System.arraycopy(raw, 0, out, 4, raw.length);
    return out;
  }

  public static byte[] unpad(byte[] b) {
    if (b.length < 4) throw fail("SDK_RESPONSE_INVALID");
    int n = ByteBuffer.wrap(b).getInt();
    if (
      n < 1 ||
      n + 4 > b.length ||
      b.length != Math.max(4096, ((n + 4 + 511) / 512) * 512)
    ) throw fail("SDK_RESPONSE_INVALID");
    return Arrays.copyOfRange(b, 4, 4 + n);
  }

  public record JsonNumber(String lexeme) {
    @Override
    public String toString() {
      return lexeme;
    }
  }

  public static Object parse(byte[] raw) {
    String s = new String(raw, StandardCharsets.UTF_8);
    if (!Arrays.equals(bytes(s), raw)) throw fail("SDK_RESPONSE_INVALID");
    class Parser {

      int i = 0;

      void ws() {
        while (i < s.length() && " \r\n\t".indexOf(s.charAt(i)) >= 0) i++;
      }

      Object value(int depth) {
        if (depth > 100) throw fail("SDK_RESPONSE_INVALID");
        ws();
        if (i >= s.length()) throw fail("SDK_RESPONSE_INVALID");
        char c = s.charAt(i);
        if (c == '"') {
          i++;
          StringBuilder b = new StringBuilder();
          while (i < s.length()) {
            c = s.charAt(i++);
            if (c == '"') {
              String x = b.toString();
              for (int j = 0; j < x.length(); j++) if (
                Character.isSurrogate(x.charAt(j))
              ) {
                if (
                  !Character.isHighSurrogate(x.charAt(j)) ||
                  j + 1 >= x.length() ||
                  !Character.isLowSurrogate(x.charAt(++j))
                ) throw fail("SDK_RESPONSE_INVALID");
              }
              return x;
            }
            if (c < 32) throw fail("SDK_RESPONSE_INVALID");
            if (c == '\\') {
              c = s.charAt(i++);
              switch (c) {
                case '"', '\\', '/' -> b.append(c);
                case 'b' -> b.append('\b');
                case 'f' -> b.append('\f');
                case 'n' -> b.append('\n');
                case 'r' -> b.append('\r');
                case 't' -> b.append('\t');
                case 'u' -> {
                  b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                  i += 4;
                }
                default -> throw fail("SDK_RESPONSE_INVALID");
              }
            } else b.append(c);
          }
          throw fail("SDK_RESPONSE_INVALID");
        }
        if (c == '{' || c == '[') {
          i++;
          boolean object = c == '{';
          Map<String, Object> m = new TreeMap<>();
          List<Object> a = new ArrayList<>();
          char close = object ? '}' : ']';
          ws();
          if (i < s.length() && s.charAt(i) == close) {
            i++;
            return object ? m : a;
          }
          while (true) {
            if (object) {
              ws();
              if (s.charAt(i) != '"') throw fail("SDK_RESPONSE_INVALID");
              String k = (String) value(depth + 1);
              ws();
              if (s.charAt(i++) != ':' || m.containsKey(k)) throw fail(
                "SDK_RESPONSE_INVALID"
              );
              m.put(k, value(depth + 1));
            } else a.add(value(depth + 1));
            ws();
            if (s.charAt(i) == close) {
              i++;
              return object ? m : a;
            }
            if (s.charAt(i++) != ',') throw fail("SDK_RESPONSE_INVALID");
          }
        }
        Matcher matcher = Pattern.compile(
          "true|false|null|-?(?:0|[1-9]\\d*)(?:\\.\\d+)?(?:[eE][+-]?\\d+)?"
        ).matcher(s);
        matcher.region(i, s.length());
        if (!matcher.lookingAt()) throw fail("SDK_RESPONSE_INVALID");
        String v = matcher.group();
        i = matcher.end();
        return switch (v) {
          case "true" -> true;
          case "false" -> false;
          case "null" -> null;
          default -> new JsonNumber(v);
        };
      }
    }
    try {
      Parser p = new Parser();
      Object v = p.value(0);
      p.ws();
      if (p.i != s.length()) throw fail("SDK_RESPONSE_INVALID");
      return v;
    } catch (Exception e) {
      throw fail("SDK_RESPONSE_INVALID");
    }
  }

  public static String canonical(Object v) {
    if (v == null) return "null";
    if (v instanceof JsonNumber n) return n.lexeme();
    if (v instanceof Map<?, ?> m) {
      List<String> keys = m
        .keySet()
        .stream()
        .map(Object::toString)
        .sorted((x, y) -> {
          int[] a = x.codePoints().toArray(),
            b = y.codePoints().toArray();
          for (int i = 0; i < Math.min(a.length, b.length); i++) if (
            a[i] != b[i]
          ) return Integer.compare(a[i], b[i]);
          return Integer.compare(a.length, b.length);
        })
        .toList();
      return (
        "{" +
        String.join(
          ",",
          keys
            .stream()
            .map(k -> canonical(k) + ":" + canonical(m.get(k)))
            .toList()
        ) +
        "}"
      );
    }
    if (v instanceof List<?> a) return (
      "[" + String.join(",", a.stream().map(Client::canonical).toList()) + "]"
    );
    if (v instanceof Boolean || v instanceof Number) return v.toString();
    if (v instanceof String s) {
      StringBuilder b = new StringBuilder("\"");
      for (char c : s.toCharArray())
        switch (c) {
          case '"' -> b.append("\\\"");
          case '\\' -> b.append("\\\\");
          case '\n' -> b.append("\\n");
          case '\r' -> b.append("\\r");
          case '\t' -> b.append("\\t");
          case '\b' -> b.append("\\b");
          case '\f' -> b.append("\\f");
          case '<' -> b.append("\\u003c");
          case '>' -> b.append("\\u003e");
          case '&' -> b.append("\\u0026");
          case '\u2028' -> b.append("\\u2028");
          case '\u2029' -> b.append("\\u2029");
          default -> {
            if (c < 32) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
          }
        }
      return b.append('"').toString();
    }
    throw fail("SDK_RESPONSE_INVALID");
  }

  @SuppressWarnings("unchecked")
  public static Map<String, Object> obj(Object v) {
    if (!(v instanceof Map)) throw fail("SDK_RESPONSE_INVALID");
    return (Map<String, Object>) v;
  }

  @SuppressWarnings("unchecked")
  static List<Object> list(Object v) {
    if (v == null) return List.of();
    if (!(v instanceof List)) throw fail("SDK_RESPONSE_INVALID");
    return (List<Object>) v;
  }

  static String str(Map<String, Object> m, String k) {
    return m.get(k) instanceof String s ? s : "";
  }

  static long num(Map<String, Object> m, String k) {
    Object v = m.get(k);
    if (v == null) return 0;
    return new BigDecimal(
      v instanceof JsonNumber n ? n.lexeme() : v.toString()
    ).longValue();
  }

  static boolean yes(Map<String, Object> m, String k) {
    return Boolean.TRUE.equals(m.get(k));
  }

  static long heartbeat(Map<String,Object> grant,long cached) {
    if(cached>=1 && cached<=3600) return cached;
    if(Boolean.TRUE.equals(grant.get("floating"))) {
      long span=Math.max(1,Math.min(7200,date(grant.get("lease_expires_at"))-date(grant.get("issued_at"))));
      return Math.max(1,(span+1)/2);
    }
    return Math.max(1,Math.min(3600,num(grant,"next_check_in")));
  }

  static long date(Object x) {
    return x == null
      ? Long.MAX_VALUE
      : Instant.parse(x.toString()).getEpochSecond();
  }

  static Map<String, Object> map(Object... pairs) {
    Map<String, Object> m = new TreeMap<>();
    for (int i = 0; i < pairs.length; i += 2) m.put(
      (String) pairs[i],
      pairs[i + 1]
    );
    return m;
  }

  static void validUrl(URI u, boolean secure) {
    if (
      u.getHost() == null ||
      u.getUserInfo() != null ||
      (!secure && u.getRawQuery() != null) ||
      u.getRawFragment() != null ||
      (!secure && u.getRawPath().contains("%")) ||
      Arrays.stream(u.getPath().split("/")).anyMatch(
        s -> s.equals(".") || s.equals("..")
      ) ||
      (!u.getScheme().equals("https") &&
        (secure ||
          !u.getScheme().equals("http") ||
          !List.of("localhost", "127.0.0.1", "[::1]").contains(u.getHost())))
    ) throw fail("SDK_INVALID_CONFIG");
  }

  synchronized void save() {
    if(memoryCache)return;
    try {
      Path dir = cache.getParent();
      Files.createDirectories(dir);
      Path p = Files.createTempFile(dir, "authgo-", ".tmp");
      try {
        if (
          FileSystems.getDefault()
            .supportedFileAttributeViews()
            .contains("posix")
        ) Files.setPosixFilePermissions(
          p,
          PosixFilePermissions.fromString("rw-------")
        );
        byte[] n = random(12);
        try (FileOutputStream f = new FileOutputStream(p.toFile())) {
          f.write(concat(n, seal(cacheKey, n, bytes(canonical(state)), aad)));
          f.getFD().sync();
        }
        Files.move(
          p,
          cache,
          StandardCopyOption.ATOMIC_MOVE,
          StandardCopyOption.REPLACE_EXISTING
        );
      } finally {
        Files.deleteIfExists(p);
      }
    } catch (Exception e) {
      throw fail("SDK_CACHE_UNAVAILABLE");
    }
  }

  static String command(String... args) throws Exception {
    Process p = new ProcessBuilder(args)
      .redirectError(ProcessBuilder.Redirect.DISCARD)
      .start();
    var read = CompletableFuture.supplyAsync(() -> {
      try {
        return new String(
          p.getInputStream().readAllBytes(),
          StandardCharsets.UTF_8
        ).trim();
      } catch (Exception e) {
        return "";
      }
    });
    if (!p.waitFor(3, TimeUnit.SECONDS)) {
      p.destroyForcibly();
      throw new Exception();
    }
    if (p.exitValue() != 0) throw new Exception();
    return read.get();
  }

  public static String identityHash(String machine, String mac, String cpu) {
    mac = mac.trim().replace('-', ':').toLowerCase(Locale.ROOT);
    cpu = String.join(" ", cpu.strip().split("\\s+")).toLowerCase(Locale.ROOT);
    if (
      machine.isBlank() ||
      cpu.isBlank() ||
      !mac.matches("[a-f0-9]{2}(:[a-f0-9]{2}){5}(:[a-f0-9]{2}){0,2}")
    ) throw fail("SDK_FINGERPRINT_UNAVAILABLE");
    return hash(
      bytes(
        "authgo/fingerprint/v1\0" +
          machine.strip().toLowerCase(Locale.ROOT) +
          "\0" +
          mac +
          "\0" +
          cpu
      )
    );
  }

  public static void validateKey(String key) {
    String alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    String[] p = key.split("-", -1);
    if (p.length != 5 || p[0].length() < 1 || p[0].length() > 16) throw fail(
      "INVALID_LICENSE_KEY"
    );
    for (int i = 0; i < p.length; i++) {
      if (i > 0 && p[i].length() != 5) throw fail("INVALID_LICENSE_KEY");
      for (char c : p[i].toCharArray())
        if (alphabet.indexOf(c) < 0) throw fail("INVALID_LICENSE_KEY");
    }
    int check = p[0].length() % 32;
    for (char c : (
      p[0] +
      p[1] +
      p[2] +
      p[3] +
      p[4].substring(0, 4)
    ).toCharArray())
      check = (check * 17 + alphabet.indexOf(c)) % 32;
    if (p[4].charAt(4) != alphabet.charAt(check)) throw fail(
      "INVALID_LICENSE_KEY"
    );
  }

  public static String parseLinuxCPU(String raw) {
    String[] lines = raw.split("\n", -1);
    for (String line : lines) {
      String[] f = line.split(":", 2);
      if (
        f.length == 2 &&
        List.of("model name", "Hardware", "cpu model").contains(f[0].trim()) &&
        !f[1].trim().isEmpty()
      ) return f[1].trim();
    }
    String implementer = "",
      part = "",
      uarch = "";
    boolean seen = false,
      done = false;
    for (String line : lines) {
      if (line.isBlank() && seen) done = true;
      String[] f = line.split(":", 2);
      if (f.length != 2) continue;
      String k = f[0].trim(),
        v = f[1].trim();
      if (k.equals("uarch") && uarch.isEmpty()) uarch = v;
      if (!done) {
        if (k.equals("CPU implementer")) {
          seen = true;
          if (implementer.isEmpty()) implementer = v
            .replaceAll("\\s", "")
            .toLowerCase(Locale.ROOT);
        }
        if (k.equals("CPU part")) {
          seen = true;
          if (part.isEmpty()) part = v
            .replaceAll("\\s", "")
            .toLowerCase(Locale.ROOT);
        }
      }
    }
    return !implementer.isEmpty() && !part.isEmpty()
      ? "arm:" + implementer + ":" + part
      : uarch;
  }

  public static String fingerprint() {
    try {
      String machine,
        cpu,
        preferred = "";
      if (osName().equals("linux")) {
        machine = Files.readString(
          Files.exists(Path.of("/etc/machine-id"))
            ? Path.of("/etc/machine-id")
            : Path.of("/var/lib/dbus/machine-id")
        );
        cpu = parseLinuxCPU(Files.readString(Path.of("/proc/cpuinfo")));
        preferred = Files.lines(Path.of("/proc/net/route"))
          .map(s -> s.trim().split("\\s+"))
          .filter(f -> f.length > 3 && f[1].equals("00000000"))
          .map(f -> f[0])
          .findFirst()
          .orElse("");
      } else if (osName().equals("darwin")) {
        Matcher m = Pattern.compile(
          "\"IOPlatformUUID\"\\s*=\\s*\"([^\"]+)\""
        ).matcher(
          command("/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
        );
        if (!m.find()) throw new Exception();
        machine = m.group(1);
        try {
          cpu = command("/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string");
        } catch (Exception e) {
          cpu = command("/usr/sbin/sysctl", "-n", "hw.model");
        }
        try {
          m = Pattern.compile("interface:\\s*(\\S+)").matcher(
            command("/sbin/route", "-n", "get", "default")
          );
          if (m.find()) preferred = m.group(1);
        } catch (Exception ignored) {}
      } else if (osName().equals("windows")) {
        String root = System.getenv().getOrDefault("SystemRoot", "C:\\Windows"),
          reg = root + "\\System32\\reg.exe";
        machine = command(
          reg,
          "query",
          "HKLM\\SOFTWARE\\Microsoft\\Cryptography",
          "/v",
          "MachineGuid",
          "/reg:64"
        )
          .split("REG_SZ", 2)[1]
          .trim();
        cpu = command(
          reg,
          "query",
          "HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
          "/v",
          "ProcessorNameString"
        )
          .split("REG_SZ", 2)[1]
          .trim();
        preferred = command(
          root + "\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          "-NoProfile",
          "-NonInteractive",
          "-Command",
          "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty InterfaceIndex"
        );
      } else throw new Exception();
      List<NetworkInterface> nics = Collections.list(
        NetworkInterface.getNetworkInterfaces()
      )
        .stream()
        .filter(n -> {
          try {
            return (
              !n.isLoopback() &&
              n.getHardwareAddress() != null &&
              !hash(n.getHardwareAddress()).equals(
                hash(new byte[n.getHardwareAddress().length])
              )
            );
          } catch (Exception e) {
            return false;
          }
        })
        .sorted(Comparator.comparingInt(NetworkInterface::getIndex))
        .toList();
      NetworkInterface nic = null;
      for (var n : nics)
        if (
          n.getName().equals(preferred) ||
          Integer.toString(n.getIndex()).equals(preferred)
        ) {
          nic = n;
          break;
        }
      if (nic == null) for (var n : nics)
        if (n.isUp()) {
          nic = n;
          break;
        }
      if (nic == null) nic = nics.get(0);
      return identityHash(
        machine,
        HexFormat.ofDelimiter(":").formatHex(nic.getHardwareAddress()),
        cpu
      );
    } catch (Exception e) {
      throw fail("SDK_FINGERPRINT_UNAVAILABLE");
    }
  }

  static String osName() {
    String s = System.getProperty("os.name").toLowerCase(Locale.ROOT);
    return s.contains("win")
      ? "windows"
      : s.contains("mac")
        ? "darwin"
        : "linux";
  }

  static String arch() {
    String s = System.getProperty("os.arch");
    return List.of("aarch64", "arm64").contains(s) ? "arm64" : "amd64";
  }

  void saveWarning(){if(!memoryCache)cacheWarning="";try{save();}catch(AuthGoException e){cacheWarning="无法保存本地缓存，重启后没有断连宽限";}}
  void revokeCache() {
    payloadReady = false;
    clearPayloadKeys();
    state.put("ticket", "");
    state.put("seed", "");
    state.put("refused", true);
    try {
      save();
    } catch (AuthGoException e) {
      try {
        Files.deleteIfExists(cache);
      } catch (IOException ignored) {}
    }
  }

  Map<String, Object> body() {
    return map(
      "instance_session", ContainerIdentity.SESSION,
      "license_key",
      str(state, "key"),
      "activation_token",
      str(state, "token"),
      "device_fingerprint",
      fp,
      "client_version",
      options.version,
      "hostname",
      "",
      "os",
      osName()
    );
  }

  record Response(int status, Map<String, List<String>> headers, byte[] body) {}

  // The timer intentionally closes the response early to enforce the total body deadline.
  @SuppressWarnings("try")
  Response fetch(String url, byte[] body, long timeout, int limit) {
    long started = System.nanoTime();
    try {
      var builder = HttpRequest.newBuilder(URI.create(url)).timeout(
        Duration.ofSeconds(timeout)
      );
      if (body == null) builder.GET();
      else builder
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofByteArray(body));
      var r = http.send(
        builder.build(),
        HttpResponse.BodyHandlers.ofInputStream()
      );
      if (r.statusCode() != 200) {
        r.body().close();
        throw fail("SDK_RESPONSE_INVALID");
      }
      var timer = Executors.newSingleThreadScheduledExecutor();
      try (
        InputStream in = r.body();
        ByteArrayOutputStream out = new ByteArrayOutputStream()
      ) {
        timer.schedule(
          () -> {
            try {
              in.close();
            } catch (IOException ignored) {}
          },
          Math.max(
            1,
            TimeUnit.SECONDS.toNanos(timeout) - (System.nanoTime() - started)
          ),
          TimeUnit.NANOSECONDS
        );
        byte[] b = new byte[65536];
        int n;
        while ((n = in.read(b)) >= 0) {
          if (out.size() + n > limit) throw fail("SDK_RESPONSE_INVALID");
          out.write(b, 0, n);
        }
        return new Response(
          r.statusCode(),
          r.headers().map(),
          out.toByteArray()
        );
      } finally {
        timer.shutdownNow();
      }
    } catch (AuthGoException e) {
      throw e;
    } catch (Exception e) {
      throw new AuthGoException(
        e instanceof javax.net.ssl.SSLException
          ? "SDK_RESPONSE_INVALID"
          : "SDK_NETWORK_ERROR",
        false,
        e
      );
    }
  }

  record Answer(Map<String, Object> data, String challenge) {}

  Answer request(String op, Map<String, Object> body) {
    String challenge = b64(random(32)),
      nonce = b64(random(32)),
      ts = Long.toString(now());
    if (body != null) body.put("challenge", challenge);
    String raw = body == null ? "" : canonical(body),
      signature = HexFormat.of().formatHex(
        hmac(
          bytes(str(config, "app_secret")),
          bytes(op + ts + nonce + hash(bytes(raw)))
        )
      );
    Map<String, Object> env;
    try {
      KeyPair pair = KeyPairGenerator.getInstance("X25519").generateKeyPair();
      byte[] pk = pair.getPublic().getEncoded();
      String ep = b64(Arrays.copyOfRange(pk, pk.length - 32, pk.length)),
        k = hash(gateway).substring(0, 16);
      byte[] secret = pair.getPrivate().getEncoded();
      byte[] shared = shared(
          Arrays.copyOfRange(secret, secret.length - 32, secret.length),
          gateway
        ),
        context = bytes("authgo-gateway-v2\0" + k + "\0" + ep),
        salt = digest(context),
        n = random(12);
      String inner = canonical(
        map(
          "app_key",
          str(config, "app_key"),
          "op",
          op,
          "timestamp",
          ts,
          "nonce",
          nonce,
          "signature",
          signature,
          "body",
          body
        )
      );
      byte[] ct = seal(
        hkdf(shared, salt, bytes("authgo/v2/request"), 32),
        n,
        pad(bytes(inner)),
        context
      );
      var packet = map("v", 2, "k", k, "e", ep, "n", b64(n), "c", b64(ct));
      var outer = obj(
        parse(
          fetch(
            endpoint + "/gateway",
            bytes(canonical(packet)),
            10,
            2097152
          ).body()
        )
      );
      if (!outer.keySet().equals(Set.of("n", "c"))) throw fail(
        "SDK_RESPONSE_INVALID"
      );
      byte[] responseContext = concat(
        context,
        bytes("\0" + hash(bytes(b64(n) + "." + b64(ct))))
      );
      env = obj(
        parse(
          unpad(
            open(
              hkdf(shared, salt, bytes("authgo/v2/response"), 32),
              decode(str(outer, "n")),
              decode(str(outer, "c")),
              responseContext
            )
          )
        )
      );
    } catch (AuthGoException e) {
      throw e;
    } catch (Exception e) {
      throw fail("SDK_RESPONSE_INVALID");
    }
    try {
      if (
        !verifySignature(
          publicKey,
          bytes(
            canonical(
              map(
                "code",
                env.get("code"),
                "data",
                env.get("data"),
                "ts",
                env.get("ts")
              )
            )
          ),
          standard(str(env, "signature"))
        )
      ) throw new Exception();
    } catch (Exception e) {
      throw fail("SDK_RESPONSE_SIGNATURE_INVALID");
    }
    var data = obj(env.get("data"));
    if (
      !str(env, "nonce").equals(nonce) ||
      !str(data, "request_nonce").equals(nonce)
    ) throw fail("SDK_RESPONSE_NONCE_INVALID");
    if (Math.abs(num(env, "ts") - now()) > 300) throw fail(
      "SDK_RESPONSE_TIMESTAMP_INVALID"
    );
    if (!str(env,"code").equals("OK")) { var error=new AuthGoException(str(env,"code"),true,null);error.latestVersion=str(data,"latest_version");error.latestEntitledVersion=str(data,"latest_entitled_version");throw error; }
    return new Answer(data, challenge);
  }

  Map<String, Object> grant(String ticket) {
    try {
      String[] p = ticket.split("\\.", -1);
      if (p.length != 2) throw new Exception();
      byte[] raw = decode(p[0]);
      if (
        !verifySignature(
          publicKey,
          concat(bytes("authgo-ticket-v2\0"), raw),
          decode(p[1])
        )
      ) throw new Exception();
      var g = obj(parse(raw));
      if (
        num(g, "v") != 2 ||
        !str(g, "app_key").equals(str(config, "app_key")) ||
        !str(g, "status").equals("active") ||
        num(g, "license_id") <= 0 ||
        !str(g, "device_hash").equals(hash(bytes(fp))) ||
        decode(str(g, "challenge")).length != 32 ||
        num(g, "next_check_in") < 1 ||
        num(g, "next_check_in") > 86400 ||
        date(g.get("grace_until")) < date(g.get("issued_at"))
      ) throw new Exception();
      return g;
    } catch (Exception e) {
      throw fail("SDK_RESPONSE_SIGNATURE_INVALID");
    }
  }

  void valid(Map<String, Object> g) {
    if (now() + 300 < num(state, "observed")) throw fail("SDK_CLOCK_ROLLBACK");
    if (
      g.get("starts_at") != null && now() < date(g.get("starts_at"))
    ) throw fail("LICENSE_NOT_STARTED");
    if (now() >= date(g.get("expires_at"))) throw fail("LICENSE_EXPIRED");
  }

  public synchronized void validate(String ticket) {
    if (yes(state, "refused")) throw fail("SDK_NOT_ACTIVATED");
    ensureInstance(null);
    var g = grant(ticket);
    valid(g);
    if(yes(g,"floating") && (g.get("lease_expires_at")==null || now()>=date(g.get("lease_expires_at"))) && !(offlineTicket.equals(ticket)&&now()<offlineUntil))throw fail("LEASE_EXPIRED");
    if (
      now() < date(g.get("grace_until")) ||
      (onlineTicket.equals(ticket) && now() < onlineUntil)
    ) return;
    if (now() >= date(g.get("grace_until"))) throw fail("SDK_GRACE_EXPIRED");
  }

  synchronized Result guardCheck(String key) {
    if(key!=null && !key.isEmpty()) return check(key);
    key=str(state,"trial_key");
    if(key.isEmpty()) {
      var answer=request("trial",map("device_fingerprint",fp));
      if(!str(answer.data(),"challenge").equals(answer.challenge()))throw fail("SDK_RESPONSE_NONCE_INVALID");
      key=str(answer.data(),"license_key");validateKey(key);
      state.put("trial_key",key);saveWarning();
    }
    return check(key);
  }
  Result fallback(AuthGoException cause) {
    Map<String, Object> g;
    byte[] seed;
    try {
      if (
        yes(state, "refused") || str(state, "ticket").isEmpty()
      ) throw new Exception();
      g = grant(str(state, "ticket"));
      seed = decode(str(state, "seed"));
      if (!hash(seed).equals(str(g, "unlock_hash"))) throw new Exception();
    } catch (Exception e) {
      throw cause;
    }
    if (yes(g,"is_trial")) throw fail("SDK_GRACE_EXPIRED");
    if (now() + 300 < num(state, "observed")) throw fail("SDK_CLOCK_ROLLBACK");
    state.put("observed", Math.max(now(), num(state, "observed")));
    save();
    valid(g);
    state.put("observed", Math.max(now(), num(state, "observed")));
    saveWarning();
    long end = Math.min(date(g.get("grace_until")),date(g.get("expires_at")));
    offlineTicket=str(state,"ticket");offlineUntil=end;
    saveWarning();
    if (now() < end) return new Result(
      this,
      g,
      str(state, "ticket"),
      seed,
      "grace",
      end,
      cause.code
    );
    throw new AuthGoException("SDK_GRACE_EXPIRED", false, cause);
  }

  void validGrantTime(Map<String, Object> g) {
    try {
      if (
        g.get("starts_at") != null && now() < date(g.get("starts_at"))
      ) throw fail("LICENSE_NOT_STARTED");
      if (now() >= date(g.get("expires_at"))) throw fail("LICENSE_EXPIRED");
      if (
        yes(g, "floating") &&
        (g.get("lease_expires_at") == null ||
          now() >= date(g.get("lease_expires_at")))
      ) throw fail("LEASE_EXPIRED");
    } catch (AuthGoException e) {
      throw e;
    } catch (Exception e) {
      throw fail("SDK_RESPONSE_INVALID");
    }
  }

  synchronized Result authorization(String op, String key) {
    try {
      Result result = authorize(op, key);
      if (op.equals("deactivate")) {
        payloadReady = false;
        clearPayloadKeys();
      } else if (result != null) recordPayloadResult(result);
      return result;
    } catch (AuthGoException error) {
      if (error.refusal()) {
        payloadReady = false;
        clearPayloadKeys();
      }
      throw error;
    }
  }

  private Result authorize(String op, String key) {
    if (key != null) validateKey(key);
    ensureInstance(op.equals("activate")?key:null);
    if(op.equals("verify") && !str(state,"ticket").isEmpty()){try{var cached=grant(str(state,"ticket"));if(yes(cached,"floating") && now()>=date(cached.get("lease_expires_at")))op="heartbeat";}catch(AuthGoException ignored){}}
    var previous = new LinkedHashMap<String, Object>(state);
    if (op.equals("activate")) {
      if (!str(state, "key").equals(key)) state = map(
        "trial_key",state.get("trial_key"),
        "observed",
        state.get("observed")
      );
      state.put("key", key);
    } else if (str(state, "token").isEmpty()) throw fail("SDK_NOT_ACTIVATED");
    try {
      var input = body();
      if(op.equals("deactivate"))input.remove("instance_session");
      if (op.equals("activate")) input.put("activation_token", "");
      Answer response = request(op, input);
      var d = response.data();
      if (op.equals("deactivate")) {
        if (!yes(d, "deactivated")) throw fail("SDK_RESPONSE_INVALID");
        state.put("ticket", "");
        state.put("seed", "");
        state.put("token", "");
        state.put("refused", true);
        save();
        return null;
      }
      var g = grant(str(d, "ticket"));
      validGrantTime(g);
      if (
        !canonical(g.get("license_id")).equals(
          canonical(d.get("license_id"))
        ) ||
        !canonical(g.get("next_check_in")).equals(
          canonical(d.get("next_check_in"))
        )
      ) throw fail("SDK_RESPONSE_INVALID");
      byte[] seed = decode(str(d, "unlock_seed"));
      if (!str(g, "challenge").equals(response.challenge())) throw fail(
        "SDK_RESPONSE_NONCE_INVALID"
      );
      if (Math.abs(date(g.get("issued_at")) - now()) > 300) throw fail(
        "SDK_RESPONSE_TIMESTAMP_INVALID"
      );
      if (
        seed.length != 32 || !hash(seed).equals(str(g, "unlock_hash"))
      ) throw fail("SDK_RESPONSE_SIGNATURE_INVALID");
      if (op.equals("activate")) {
        if (
          !str(d, "activation_token").matches("act_[A-Za-z0-9_-]{43}")
        ) throw fail("SDK_RESPONSE_INVALID");
        state.put("token", d.get("activation_token"));
      }
      state.put("heartbeat_interval",heartbeat(g,num(d,"heartbeat_interval")));
      state.put("ticket", d.get("ticket"));
      state.remove("status"); state.remove("availability"); state.remove("guard");
      state.put("seed", d.get("unlock_seed"));
      state.put("refused", false);
      state.put("observed", Math.max(now(), date(g.get("issued_at"))));
      offlineTicket="";offlineUntil=0;
      onlineTicket = str(d, "ticket");
      onlineUntil = now() + num(g, "next_check_in");
      saveWarning();
      validate(onlineTicket);
      long end = Math.min(
        Math.min(
          Math.max(date(g.get("grace_until")), onlineUntil),
          date(g.get("expires_at"))
        ),
        yes(g, "floating") ? date(g.get("lease_expires_at")) : Long.MAX_VALUE
      );
      return new Result(this, g, onlineTicket, seed, "online", end, "");
    } catch (AuthGoException e) {
      if(e.authenticated && e.code.equals("INSTANCE_REPLACED")){state=previous;ContainerIdentity.REPLACED.add(instanceKey(op.equals("activate")?key:null));offlineUntil=onlineUntil=0;throw e;}
      if (op.equals("activate") && !str(previous, "key").equals(key)) {
        state = previous;
        throw e;
      }
      if (op.equals("activate") && e.refusal()) {
        state.put("token", "");
        revokeCache();
        throw e;
      }
      if (op.equals("verify") || op.equals("heartbeat")) {
        onlineUntil = 0;
        if (e.refusal()) {
          revokeCache();
          throw e;
        }
        return fallback(e);
      }
      throw e;
    } catch (Exception cause) {
      if (op.equals("activate") && !str(previous, "key").equals(key)) state =
        previous;
      var error = new AuthGoException("SDK_RESPONSE_INVALID", false, cause);
      if (op.equals("verify") || op.equals("heartbeat")) {
        onlineUntil = 0;
        return fallback(error);
      }
      throw error;
    }
  }

  private void recordPayloadResult(Result result) {
    Map<String,Object> g = grant(result.ticket());
    payloadReady = true;
    payloadNoCache = yes(g,"is_trial") || date(g.get("grace_until")) <= date(g.get("issued_at"));
    if (payloadNoCache) clearPayloadKeys();
  }

  private boolean payloadCacheDisabled(Result result) {
    return payloadNoCache || memoryCache || result == null || result.isTrial || result.status.equals("offline");
  }

  /** Best-effort encrypted content-key cache, serialized with authorization. */
  public synchronized void savePayloadKey(Payload payload, Result result, byte[] key) {
    if (payload == null) throw Payload.invalid();
    Payload p = payload.validated();
    try {
      if (payloadCacheDisabled(result)) return;
      payloadCache.save(p, grant(result.ticket()), now(), false, key);
    } catch (Exception ignored) { /* An unavailable cache does not fail online unlock. */ }
  }

  public synchronized byte[] loadPayloadKey(Payload payload, Result result) {
    if (payload == null) throw Payload.invalid();
    Payload p = payload.validated();
    if (payloadCacheDisabled(result)) throw fail("SDK_CACHE_UNAVAILABLE");
    return payloadCache.load(p, grant(result.ticket()), now(), false);
  }

  public synchronized void clearPayloadKeys() { payloadCache.clear(memoryCache); }

  private Result payloadCachedResult() {
    String ticket = str(state,"ticket");
    var g = grant(ticket);
    byte[] seed = decode(str(state,"seed"));
    if (seed.length != 32 || !hash(seed).equals(str(g,"unlock_hash"))) throw fail("SDK_RESPONSE_SIGNATURE_INVALID");
    // Accepted offline floating grace remains usable even after the original lease expires.
    if (g.get("starts_at") != null && now() < date(g.get("starts_at"))) throw fail("LICENSE_NOT_STARTED");
    if (now() >= date(g.get("expires_at"))) throw fail("LICENSE_EXPIRED");
    return new Result(this,g,ticket,seed,"online",date(g.get("grace_until")),"");
  }

  private Result payloadFreshResult(Map<String,Object> data, String challenge, Result previous) {
    try {
      if (!data.keySet().containsAll(Set.of("license_id","status","expires_at","features","next_check_in","grace_until","heartbeat_interval","satisfied_methods","ticket","unlock_seed"))) throw fail("SDK_RESPONSE_INVALID");
      var g = grant(str(data,"ticket"));
      if (g.get("issued_at") == null || g.get("grace_until") == null) throw fail("SDK_RESPONSE_INVALID");
      var id = Payload.integer(data.get("license_id"));
      var methods = list(data.get("satisfied_methods"));
      if (id.signum() <= 0 || id.bitLength() > 63 || !id.equals(Payload.integer(g.get("license_id"))) ||
          !str(data,"status").equals("active") || !(data.get("features") instanceof Map<?,?>) ||
          !Payload.integer(data.get("next_check_in")).equals(Payload.integer(g.get("next_check_in"))) ||
          Payload.integer(data.get("heartbeat_interval")).compareTo(java.math.BigInteger.ONE)<0 ||
          Payload.integer(data.get("heartbeat_interval")).compareTo(java.math.BigInteger.valueOf(3600))>0 ||
          !methods.contains("KEY") || new HashSet<>(methods).size()!=methods.size() ||
          methods.stream().anyMatch(m -> !(m instanceof String) || !Set.of("KEY","FLOATING").contains(m)) ||
          methods.contains("FLOATING") && data.get("lease_expires_at")==null || data.get("grace_until")==null) throw fail("SDK_RESPONSE_INVALID");
      date(data.get("grace_until"));
      var periods = new TreeMap<>(data); periods.put("floating",methods.contains("FLOATING"));
      validGrantTime(periods);
      if (Math.abs(date(g.get("issued_at"))-now())>300) throw fail("SDK_RESPONSE_TIMESTAMP_INVALID");
      byte[] seed=decode(str(data,"unlock_seed"));
      if (seed.length!=32 || !hash(seed).equals(str(g,"unlock_hash")) || !str(g,"challenge").equals(challenge) ||
          !id.equals(Payload.integer(previous.data.get("license_id")))) throw fail("SDK_RESPONSE_INVALID");
      return new Result(this,g,str(data,"ticket"),seed,"online",date(g.get("grace_until")),"");
    } catch (AuthGoException error) {
      // Payload schema failures are malformed fresh grants, never recoverable channel errors.
      if (error.code.equals("PAYLOAD_INVALID")) throw fail("SDK_RESPONSE_INVALID");
      throw error;
    } catch (Exception error) { throw fail("SDK_RESPONSE_INVALID"); }
  }

  private byte[] payloadFailure(Payload payload, Result result, AuthGoException error) {
    if (error.refusal()) {
      payloadReady=false; clearPayloadKeys();
      if (error.code.equals("INSTANCE_REPLACED")) {
        ContainerIdentity.REPLACED.add(instanceKey(null)); offlineUntil=onlineUntil=0;
      } else revokeCache();
      throw error;
    }
    try { return loadPayloadKey(payload,result); } catch (AuthGoException unavailable) { throw error; }
  }

  /** Return the authenticated 32-byte content key. Caller must zero it after use. */
  public synchronized byte[] unlockPayload(Payload payload) {
    byte[] material=unlockPayloadMaterial(payload);
    if(material.length==32)return material;
    try{return Arrays.copyOf(material,32);}finally{Arrays.fill(material,(byte)0);}
  }
  synchronized byte[] unlockPayloadMaterial(Payload payload) {
    if (!payloadReady || yes(state,"refused") || str(state,"ticket").isEmpty() || ContainerIdentity.REPLACED.contains(instanceKey(null))) throw fail("SDK_NOT_ACTIVATED");
    if (payload == null) throw Payload.invalid();
    Payload p = payload.validated();
    if (!p.appKey().equals(str(config,"app_key"))) throw Payload.invalid();
    Result previous = payloadCachedResult();
    if (now()+300 < num(state,"observed")) throw fail("SDK_CLOCK_ROLLBACK");
    if (offlineTicket.equals(previous.ticket()) && onlineUntil==0) return loadPayloadKey(p,previous);
    byte[] privateKey=null;
    try {
      KeyPair pair=KeyPairGenerator.getInstance("X25519").generateKeyPair();
      privateKey=Payload.rawPrivate(pair);
      byte[] ephemeral=Payload.rawPublic(pair);
      Map<String,Object> body=body();
      body.keySet().retainAll(Set.of("license_key","activation_token","device_fingerprint","instance_session"));
      body.put("payload",p.toMap()); body.put("ephemeral_public_key",b64(ephemeral));
      Answer response;
      try { response=request("payload.unlock",body); }
      catch(AuthGoException error) { return payloadFailure(p,previous,error); }
      catch(Exception error) { return payloadFailure(p,previous,fail("SDK_RESPONSE_INVALID")); }
      // A malformed fresh ticket or failed unwrap must not be hidden by cached data.
      var data=response.data();
      Result fresh=payloadFreshResult(data,response.challenge(),previous);
      if(fresh.isTrial || date(fresh.data.get("grace_until"))<=date(fresh.data.get("issued_at"))) {
        payloadNoCache=true;clearPayloadKeys();
      }
      if(p.v()==2){byte[] wm=PayloadWatermark.response(data.get("watermark"));Arrays.fill(wm,(byte)0);}
      for(String field:List.of("e","n","c")) if(!data.containsKey(field) || data.get(field)!=null && !(data.get(field) instanceof String))
        return payloadFailure(p,previous,fail("SDK_RESPONSE_INVALID"));
      byte[] watermark=p.v()==2?PayloadWatermark.response(data.get("watermark")):null;
      try {
      byte[] key=p.unwrap(new Payload.Envelope(str(data,"e"),str(data,"n"),str(data,"c")),privateKey,ephemeral,decode(response.challenge()));
      if(watermark!=null){byte[] material=concat(key,watermark);Arrays.fill(key,(byte)0);key=material;}
      savePayloadKey(p,fresh,key); return key;
      }finally{if(watermark!=null)Arrays.fill(watermark,(byte)0);}
    } catch (GeneralSecurityException error) { throw fail("INTERNAL_ERROR"); }
    finally { if(privateKey!=null)Arrays.fill(privateKey,(byte)0); }
  }

  public synchronized Result check(String key) {
    return authorization(
      str(state, "key").equals(key) && !str(state, "token").isEmpty()
        ? "verify"
        : "activate",
      key
    );
  }

  public Result activate(String key) {
    return authorization("activate", key);
  }

  public Result verify() {
    return authorization("verify", null);
  }

  public Result heartbeat() {
    return authorization("heartbeat", null);
  }

  String instanceKey(String key){return endpoint+"\0"+str(config,"app_key")+"\0"+fp+"\0"+str(config,"public_key")+"\0"+(key==null?str(state,"key"):key)+"\0"+ContainerIdentity.SESSION;}
  void ensureInstance(String key){if(ContainerIdentity.REPLACED.contains(instanceKey(key)))throw fail("INSTANCE_REPLACED");}
  public synchronized void releaseSeat(){
    if(str(state,"ticket").isEmpty()||!yes(grant(str(state,"ticket")),"floating"))return;
    try{request("release-seat",body());}catch(AuthGoException e){
      if(e.refusal()){payloadReady=false;clearPayloadKeys();}
      if(e.authenticated&&e.code.equals("INSTANCE_REPLACED")){ContainerIdentity.REPLACED.add(instanceKey(null));offlineUntil=onlineUntil=0;}
      else if(e.refusal())revokeCache();throw e;
    }
  }
  public void deactivate() {
    authorization("deactivate", null);
  }

  public List<Object> announcements() {
    return list(request("announcement", null).data().get("items"));
  }

  public synchronized Map<String, Object> checkUpdate(String current) {
    if (str(state, "token").isEmpty()) throw fail("SDK_NOT_ACTIVATED");
    var b = body();
    b.put("current_version", current);
    b.put("client_version", current);
    var d = request("update.check", b).data();
    d.keySet().retainAll(Set.of("available", "docker_image", "docker_pull", "version", "changelog", "mandatory", "published_at", "maintenance_until", "latest_entitled_version", "renewal_required"));
    return d;
  }

}
