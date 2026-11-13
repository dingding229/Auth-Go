package io.authgo;

import static io.authgo.Client.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyPair;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.ResolverStyle;
import java.util.*;
import java.util.regex.*;

/** Complete original payload.json; config is public binding data, never a connection target. */
public record Payload(int v, String appKey, String version, String builtAt, String keyId,
                      String config, String manifest, Envelope envelope) {
  public record Envelope(String e, String n, String c) {}
  private static final Set<String> FIELDS = Set.of("v", "app_key", "version", "built_at", "key_id", "config", "manifest", "envelope");
  private static final Pattern NAME = Pattern.compile("[a-z0-9_-]+");
  private static final Pattern SEMVER = Pattern.compile("(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\\.[0-9A-Za-z-]+)*)?(\\+[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?");
  private static final DateTimeFormatter UTC = DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss'Z'", Locale.ROOT).withResolverStyle(ResolverStyle.STRICT);

  static Client.AuthGoException invalid() { return fail("PAYLOAD_INVALID"); }
  static Map<String,Object> object(Object value, Set<String> required, Set<String> optional) {
    Map<String,Object> m = obj(value);
    Set<String> allowed = new HashSet<>(required); allowed.addAll(optional);
    if (!m.keySet().containsAll(required) || !allowed.containsAll(m.keySet())) throw invalid();
    return m;
  }
  static String text(Object value) {
    if (!(value instanceof String s)) throw invalid();
    for (int i=0; i<s.length(); i++) if (Character.isSurrogate(s.charAt(i))) {
      if (!Character.isHighSurrogate(s.charAt(i)) || i+1>=s.length() || !Character.isLowSurrogate(s.charAt(++i))) throw invalid();
    }
    return s;
  }
  static BigInteger integer(Object value) {
    String token = canonical(value);
    if (!token.matches("-?(0|[1-9][0-9]*)")) throw invalid();
    return new BigInteger(token);
  }
  static byte[] lp(String value) {
    byte[] raw=bytes(value);
    return concat(ByteBuffer.allocate(4).putInt(raw.length).array(), raw);
  }
  static byte[] lpAll(String... values) {
    byte[] out=new byte[0]; for(String value:values)out=concat(out,lp(value)); return out;
  }
  /** Go net/url.Parse HTTPS predicate, not URI/URL normalization or host validation. */
  static void https(String value) {
    text(value);
    if (Pattern.compile("[\\x00-\\x1f\\x7f]").matcher(value).find()) throw invalid();
    Matcher m=Pattern.compile("(?i:https)://([^/?#]*)([^?#]*)(?:\\?([^#]*))?(?:#(.*))?").matcher(value);
    if(!m.matches())throw invalid();
    String authority=m.group(1), path=m.group(2), query=m.group(3), fragment=m.group(4);
    if(authority.isEmpty() || authority.contains("@") || query!=null&&!query.isEmpty() || fragment!=null&&!fragment.isEmpty())throw invalid();
    if(authority.contains("[")&&!authority.startsWith("["))throw invalid();
    if(authority.startsWith("[")) {
      int end=authority.lastIndexOf(']');
      if(end<0 || authority.substring(1,end).isEmpty())throw invalid();
      String suffix=authority.substring(end+1);
      if(!suffix.isEmpty()&&!suffix.matches(":[0-9]*"))throw invalid();
    } else if(authority.contains(":")) {
      int end=authority.lastIndexOf(':');
      if(authority.substring(0,end).isEmpty() || !authority.substring(end+1).matches("[0-9]*"))throw invalid();
    }
    for(int i=0;i<authority.length();i++) {
      char c=authority.charAt(i);
      if(c<128 && !((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||"_.~!$&'()*+,;=:[]<>\"%-".indexOf(c)>=0))throw invalid();
    }
    if(Pattern.compile("%(?![0-9a-fA-F]{2})").matcher(authority+path).find())throw invalid();
    Matcher escapes=Pattern.compile("%([0-9a-fA-F]{2})").matcher(authority);
    while(escapes.find()){int code=Integer.parseInt(escapes.group(1),16);if(code<128&&code!=37)throw invalid();}
  }
  static void validConfig(String value, String appKey) {
    if(bytes(value).length>32768 || !value.startsWith("authgo2."))throw invalid();
    var c=object(parse(decode(value.substring(8))),Set.of("url","app_key","app_secret","public_key","gateway_key"),Set.of());
    for(String field:List.of("url","app_key","app_secret","public_key","gateway_key"))text(c.get(field));
    if(!appKey.equals(c.get("app_key")) || str(c,"app_secret").isEmpty())throw invalid();
    https(str(c,"url"));
    if(standard(str(c,"public_key")).length!=32 || decode(str(c,"gateway_key")).length!=32)throw invalid();
  }
  static byte[] validManifest(String value) { return validManifest(value,1); }
  static byte[] validManifest(String value,int version) {
    byte[] raw=decode(value); if(raw.length>(8<<20))throw invalid();
    var m=object(parse(raw),Set.of("files"),Set.of());
    if(!(m.get("files") instanceof List<?> files) || files.isEmpty() || files.size()>65535)throw invalid();
    Set<String> names=new HashSet<>(); int metadata=0;
    for(int i=0;i<files.size();i++) {
      var f=object(files.get(i),Set.of("name","kind","path","size","chunk_size","encoding"),Set.of("python_version","main_class","architecture"));
      for(String key:f.keySet())if(!Set.of("size","chunk_size").contains(key))text(f.get(key));
      String name=str(f,"name"),kind=str(f,"kind"),encoding=str(f,"encoding");
      BigInteger size=integer(f.get("size"));
      if(!NAME.matcher(name).matches() || bytes(name).length>128 || !names.add(name) ||
          !str(f,"path").equals(String.format(Locale.ROOT,"%08d.agc",i)) || size.signum()<0 || size.compareTo(BigInteger.valueOf(Long.MAX_VALUE/2))>0 ||
          !integer(f.get("chunk_size")).equals(BigInteger.valueOf(1048576)))throw invalid();
      if(kind.equals("watermark")) {
        if(version!=2 || !name.equals("__authgo_watermark") || !encoding.equals("raw") || size.signum()<=0 || size.compareTo(BigInteger.valueOf(8<<20))>0 || f.size()!=6)throw invalid();
        metadata++; continue;
      }
      if(version==2 && name.equals("__authgo_watermark"))throw invalid();
      String expected=switch(kind){case "python","php","dotnet"->"tar";case "node","java","protect"->"raw";default->"";};
      if(expected.isEmpty() || !expected.equals(encoding) || kind.equals("python")&&str(f,"python_version").isEmpty() ||
          kind.equals("protect")&&!Set.of("amd64","arm64").contains(str(f,"architecture")))throw invalid();
    }
    if(version==2 && (metadata!=1 || files.size()<2))throw invalid();
    return raw;
  }
  byte[] aad() {
    if(v!=2)throw invalid();
    for(String value:new String[]{appKey,version,builtAt,keyId,config,manifest})text(value);
    if(appKey.isEmpty() || bytes(appKey).length>256 || bytes(keyId).length>128 || !NAME.matcher(keyId).matches() ||
       bytes(version).length>256 || !SEMVER.matcher(version).matches())throw invalid();
    String core=version.split("\\+",2)[0]; int dash=core.indexOf('-');
    if(dash>=0)for(String part:core.substring(dash+1).split("\\."))if(part.matches("0[0-9]+"))throw invalid();
    if(!builtAt.matches("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z"))throw invalid();
    LocalDateTime.parse(builtAt,UTC);
    validConfig(config,appKey);
    return concat(bytes("authgo-payload-envelope-v"+v+"\0"),lpAll(appKey,version,builtAt,keyId,config),digest(validManifest(manifest,v)));
  }
  public byte[] payloadBinding() {
    try {
      byte[] aad=aad(), e=decode(envelope.e()), n=decode(envelope.n()), c=decode(envelope.c());
      if(e.length!=32 || n.length!=12 || c.length!=48)throw invalid();
      return digest(concat(aad,e,n,c));
    }catch(Exception error){throw invalid();}
  }
  public Map<String,Object> toMap() {
    return map("v",v,"app_key",appKey,"version",version,"built_at",builtAt,"key_id",keyId,"config",config,"manifest",manifest,
      "envelope",map("e",envelope.e(),"n",envelope.n(),"c",envelope.c()));
  }
  public static Payload parsePayload(String raw) {
    try{return parsePayload(bytes(text(raw)));}catch(Exception error){throw invalid();}
  }
  public static Payload parsePayload(byte[] raw) {
    try {
      if(raw==null || raw.length>65536)throw invalid();
      var p=object(parse(raw),FIELDS,Set.of());
      int version=integer(p.get("v")).intValueExact(); if(version!=2)throw invalid();
      var e=object(p.get("envelope"),Set.of("e","n","c"),Set.of());
      Payload out=new Payload(version,text(p.get("app_key")),text(p.get("version")),text(p.get("built_at")),text(p.get("key_id")),text(p.get("config")),text(p.get("manifest")),
        new Envelope(text(e.get("e")),text(e.get("n")),text(e.get("c"))));
      out.payloadBinding();return out;
    }catch(Exception error){throw invalid();}
  }
  Payload validated() { try{payloadBinding();return parsePayload(bytes(canonical(toMap())));}catch(Exception error){throw invalid();} }
  byte[] rewrapAAD(byte[] ephemeral, byte[] challenge) {
    if(ephemeral.length!=32 || challenge.length!=32)throw invalid();
    return concat(bytes("authgo-payload-rewrap-v"+v+"\0"),lpAll(appKey,version,builtAt,keyId),digest(decode(manifest)),ephemeral,challenge);
  }
  byte[] cacheLabel(String fingerprint) {
    return concat(bytes("authgo-payload-cache-v"+v+"\0"),lpAll(appKey,fingerprint,keyId,version),digest(decode(manifest)),payloadBinding());
  }
  static byte[] rawPublic(KeyPair pair) {byte[] raw=pair.getPublic().getEncoded();return Arrays.copyOfRange(raw,raw.length-32,raw.length);}
  static byte[] rawPrivate(KeyPair pair) {byte[] raw=pair.getPrivate().getEncoded();return Arrays.copyOfRange(raw,raw.length-32,raw.length);}
  byte[] unwrap(Envelope wrapped, byte[] privateKey, byte[] ephemeral, byte[] challenge) {
    byte[] shared=null,kek=null;
    try {
      byte[] e=decode(wrapped.e()),n=decode(wrapped.n()),c=decode(wrapped.c());
      if(e.length!=32 || n.length!=12 || c.length!=48)throw invalid();
      shared=shared(privateKey,e);
      byte[] aad=rewrapAAD(ephemeral,challenge);
      kek=hkdf(shared,digest(aad),bytes("authgo/payload/v1/rewrap"),32);
      byte[] key=open(kek,n,c,aad);if(key.length!=32)throw invalid();return key;
    }catch(Exception error){throw fail("SDK_RESPONSE_INVALID");}
    finally{if(shared!=null)Arrays.fill(shared,(byte)0);if(kek!=null)Arrays.fill(kek,(byte)0);}
  }
}
