package io.authgo;

import static io.authgo.Client.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.*;
import java.security.spec.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.*;

/** In-memory HTTP seam; request HMAC, v2 AEAD, signed envelopes/tickets and rewrap are real. */
public final class PayloadTests {
  static final String LICENSE="AUTH-RNMSQ-VSQQA-4S4NH-JDGCM";
  static final String FP="c4ffc8a324a624018c71f7b23e99eafda2093769f82cddba01a2f1fb32d18bcd";
  static int cases;
  private PayloadTests() {}
  interface Action { void run() throws Exception; }
  static void check(boolean value){if(!value)throw new AssertionError();}
  static void equal(Object actual,Object expected){if(!Objects.equals(actual,expected))throw new AssertionError("payload assertion mismatch");}
  static void same(byte[] actual,byte[] expected){check(Arrays.equals(actual,expected));}
  static byte[] hex(Object value){return HexFormat.of().parseHex(value.toString());}
  static Map<String,Object> read(String file)throws IOException{return obj(parse(Files.readAllBytes(Path.of("sdk/vectors",file))));}
  static Map<String,Object> copy(Map<String,Object> value){return obj(parse(bytes(canonical(value))));}
  static void error(String code,Action action)throws Exception {
    try{action.run();throw new AssertionError("expected "+code);}catch(AuthGoException actual){equal(actual.code,code);}
  }
  static void runCase(String name,Action action)throws Exception {action.run();cases++;System.out.println("payload: "+name+" PASS");}
  static String iso(long now){return Instant.ofEpochSecond(now).toString();}
  static byte[] sign(PrivateKey signer,byte[] bytes)throws GeneralSecurityException {
    Signature signature=Signature.getInstance("Ed25519");signature.initSign(signer);signature.update(bytes);return signature.sign();
  }
  static KeyPair xpair(byte[] privateKey,byte[] publicKey)throws GeneralSecurityException {
    var factory=KeyFactory.getInstance("X25519");
    return new KeyPair(factory.generatePublic(new X509EncodedKeySpec(concat(hex("302a300506032b656e032100"),publicKey))),
      factory.generatePrivate(new PKCS8EncodedKeySpec(concat(hex("302e020100300506032b656e04220420"),privateKey))));
  }
  static List<Path> caches(Path directory)throws IOException {
    try(var files=Files.list(directory)){return files.filter(f->f.getFileName().toString().startsWith("authgo-payload-v2-")).toList();}
  }
  record Reply(int status,byte[] body) {}
  record HttpReply(HttpRequest request,int statusCode,InputStream body) implements HttpResponse<InputStream> {
    public Optional<HttpResponse<InputStream>> previousResponse(){return Optional.empty();}
    public HttpHeaders headers(){return HttpHeaders.of(Map.of(),(a,b)->true);}
    public Optional<SSLSession> sslSession(){return Optional.empty();}
    public URI uri(){return request.uri();}
    public HttpClient.Version version(){return HttpClient.Version.HTTP_1_1;}
  }
  static final class Transport extends HttpClient {
    final Server server;
    Transport(Server server){this.server=server;}
    public Optional<CookieHandler> cookieHandler(){return Optional.empty();}
    public Optional<Duration> connectTimeout(){return Optional.empty();}
    public Redirect followRedirects(){return Redirect.NEVER;}
    public Optional<ProxySelector> proxy(){return Optional.empty();}
    public SSLContext sslContext(){try{return SSLContext.getDefault();}catch(GeneralSecurityException error){throw new AssertionError(error);}}
    public SSLParameters sslParameters(){return new SSLParameters();}
    public Optional<Authenticator> authenticator(){return Optional.empty();}
    public Version version(){return Version.HTTP_1_1;}
    public Optional<Executor> executor(){return Optional.empty();}
    @SuppressWarnings("unchecked")
    public <T> HttpResponse<T> send(HttpRequest request,HttpResponse.BodyHandler<T> handler)throws IOException,InterruptedException {
      var ready=new CompletableFuture<byte[]>();var bytes=new ByteArrayOutputStream();
      request.bodyPublisher().orElseThrow().subscribe(new Flow.Subscriber<ByteBuffer>() {
        public void onSubscribe(Flow.Subscription subscription){subscription.request(Long.MAX_VALUE);}
        public void onNext(ByteBuffer value){byte[] chunk=new byte[value.remaining()];value.get(chunk);bytes.writeBytes(chunk);}
        public void onError(Throwable error){ready.completeExceptionally(error);}
        public void onComplete(){ready.complete(bytes.toByteArray());}
      });
      try {
        equal(request.uri().toString(),"https://PAYLOAD.EXAMPLE.TEST/api/v1/client/gateway");
        Reply reply=server.reply(ready.get(5,TimeUnit.SECONDS));
        return (HttpResponse<T>)new HttpReply(request,reply.status(),new ByteArrayInputStream(reply.body()));
      }catch(InterruptedException error){throw error;}catch(IOException error){throw error;}
      catch(Exception error){throw new AssertionError(error);}
    }
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,HttpResponse.BodyHandler<T> handler){throw new UnsupportedOperationException();}
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request,HttpResponse.BodyHandler<T> handler,HttpResponse.PushPromiseHandler<T> push){throw new UnsupportedOperationException();}
  }
  static final class Server {
    final KeyPair signer=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    final KeyPair gateway=KeyPairGenerator.getInstance("X25519").generateKeyPair();
    final Payload payload;
    final byte[] dek=hex(read("payload-cache-v2.json").get("content_key_hex")), seed=new byte[32];
    final Map<String,Object> config;
    volatile String observedVersion="";
    final List<String> calls=new CopyOnWriteArrayList<>();
    final AtomicInteger inFlight=new AtomicInteger(),maximum=new AtomicInteger();
    volatile long now=num(read("payload-cache-v2.json"),"proof_now");
    String mode="",code="";
    long grace=120,id=42;
    boolean trial,floating;
    String expires;
    Map<String,Object> changes=new TreeMap<>(),grantChanges=new TreeMap<>();
    CountDownLatch entered,proceed;
    Server()throws Exception {this(Payload.parsePayload(canonical(read("payload-cache-v2.json").get("payload"))));}
    Server(Payload original)throws Exception {
      payload=original;config=obj(parse(decode(payload.config().substring(8))));
      Arrays.fill(seed,(byte)0x27);
      config.put("public_key",Base64.getEncoder().encodeToString(Payload.rawPublic(signer)));
      config.put("gateway_key",b64(Payload.rawPublic(gateway)));config.put("url","https://PAYLOAD.EXAMPLE.TEST");
    }
    Client client(Path directory){return client(directory,FP);}
    Client client(Path directory,String fingerprint){
      Client.Options options=new Client.Options();options.fingerprint=fingerprint;options.cacheDir=directory;options.clock=()->now;options.httpClient=new Transport(this);
      return new Client("authgo2."+b64(bytes(canonical(config))),options);
    }
    Map<String,Object> ticket(Map<String,Object> body){return map("v",2,"app_key",config.get("app_key"),"challenge",body.get("challenge"),"license_id",id,
      "license_ref","public-synthetic-ref","device_hash",hash(bytes(str(body,"device_fingerprint"))),"status","active","issued_at",iso(now),"starts_at",null,"expires_at",expires,
      "features",map("export",true),"next_check_in",10,"grace_until",iso(now+grace),
      "lease_expires_at",floating?iso(now+20):null,"floating",floating,"is_trial",trial,"unlock_hash",hash(seed));}
    String signed(Map<String,Object> grant)throws GeneralSecurityException {
      byte[] raw=bytes(canonical(grant));return b64(raw)+"."+b64(sign(signer.getPrivate(),concat(bytes("authgo-ticket-v2\0"),raw)));
    }
    Reply reply(byte[] packet)throws Exception {
      maximum.accumulateAndGet(inFlight.incrementAndGet(),Math::max);
      try {
        calls.add("transport");
        if(mode.equals("network"))throw new IOException("fixture unreachable");
        if(mode.equals("status"))return new Reply(502,bytes("<html>not signed</html>"));
        if(mode.equals("html"))return new Reply(200,bytes("<html>not signed</html>"));
        var outer=obj(parse(packet));byte[] aad=bytes("authgo-gateway-v2\0"+str(outer,"k")+"\0"+str(outer,"e"));
        byte[] shared=shared(Payload.rawPrivate(gateway),decode(str(outer,"e"))),salt=digest(aad);
        var inner=obj(parse(unpad(open(hkdf(shared,salt,bytes("authgo/v2/request"),32),decode(str(outer,"n")),decode(str(outer,"c")),aad))));
        var body=obj(inner.get("body"));String op=str(inner,"op"),nonce=str(inner,"nonce");
        if(!op.equals("payload.unlock"))observedVersion=str(body,"client_version");
        equal(str(inner,"signature"),HexFormat.of().formatHex(hmac(bytes(str(config,"app_secret")),bytes(op+str(inner,"timestamp")+nonce+hash(bytes(canonical(body)))))));
        equal(decode(str(body,"challenge")).length,32);calls.set(calls.size()-1,op);
        var g=ticket(body);var data=new TreeMap<>(g);
        data.put("unlock_seed",b64(seed));data.put("request_nonce",nonce);data.put("heartbeat_interval",5);data.put("satisfied_methods",floating?List.of("KEY","FLOATING"):List.of("KEY"));
        if(op.equals("activate"))data.put("activation_token","act_"+b64(new byte[32]));
        if(op.equals("deactivate"))data.put("deactivated",true);
        if(op.equals("release-seat"))data.put("released",true);
        if(op.equals("payload.unlock")) {
          equal(body.keySet(),Set.of("license_key","activation_token","device_fingerprint","instance_session","payload","ephemeral_public_key","challenge"));
          equal(body.get("license_key"),LICENSE);check(str(body,"activation_token").startsWith("act_"));
          same(Payload.parsePayload(canonical(body.get("payload"))).payloadBinding(),payload.payloadBinding());
          if(entered!=null){entered.countDown();check(proceed.await(5,TimeUnit.SECONDS));}
          byte[] ephemeral=decode(str(body,"ephemeral_public_key")),challenge=decode(str(body,"challenge"));
          var pair=KeyPairGenerator.getInstance("X25519").generateKeyPair();
          byte[] rewrap=payload.rewrapAAD(ephemeral,challenge),kek=hkdf(shared(Payload.rawPrivate(pair),ephemeral),digest(rewrap),bytes("authgo/payload/v1/rewrap"),32),n=random(12);
          if(payload.v()==2)data.put("watermark","19".repeat(32));
          data.put("e",b64(Payload.rawPublic(pair)));data.put("n",b64(n));data.put("c",b64(seal(kek,n,dek,rewrap)));
          switch(mode) {
            case "challenge"->g.put("challenge",b64(new byte[32]));
            case "license"->{g.put("license_id",41);data.put("license_id",41);}
            case "seed"->data.put("unlock_seed",b64(new byte[32]));
            case "issued"->{g.put("issued_at",iso(now+301));g.put("grace_until",iso(now+500));}
            case "wrap"->data.put("c",b64(new byte[48]));
            case "missing-wrap"->data.remove("e");
            case "trial"->g.put("is_trial",true);
            case "zero"->g.put("grace_until",g.get("issued_at"));
            default->{ }
          }
        }
        g.putAll(grantChanges);data.put("ticket",signed(g));data.putAll(changes);
        var env=map("code",code.isEmpty()?"OK":code,"data",data,"ts",now,"nonce",nonce);
        env.put("signature",Base64.getEncoder().encodeToString(sign(signer.getPrivate(),bytes(canonical(map("code",env.get("code"),"data",data,"ts",now))))));
        if(mode.equals("signature"))env.put("signature",Base64.getEncoder().encodeToString(new byte[64]));
        if(mode.equals("watermark-tamper")&&op.equals("payload.unlock")){
          // Keep the signature; replace only the valid watermark before encryption.
          data.put("watermark","2a".repeat(32));
        }
        if(mode.equals("nonce"))env.put("nonce","wrong");
        byte[] n=random(12),context=concat(aad,bytes("\0"+hash(bytes(str(outer,"n")+"."+str(outer,"c")))));
        return new Reply(200,bytes(canonical(map("n",b64(n),"c",b64(seal(hkdf(shared,salt,bytes("authgo/v2/response"),32),n,pad(bytes(canonical(env))),context))))));
      }finally{inFlight.decrementAndGet();}
    }
  }
  static final class Fixture implements AutoCloseable {
    final Path dir=Files.createTempDirectory("authgo-payload-");
    final Server server=new Server();
    final Client client=server.client(dir);
    final Payload payload=server.payload;
    Client.Result result;
    Fixture()throws Exception {}
    Fixture prime(){result=client.check(LICENSE);same(client.unlockPayload(payload),server.dek);return this;}
    public void close()throws IOException {
      try(var paths=Files.walk(dir)){for(Path file:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(file);}
    }
  }

  static void vectors()throws Exception {
    var v=read("payload-unlock-v2.json");Payload p=Payload.parsePayload(canonical(v.get("payload")));
    byte[] priv=hex(v.get("client_private_hex")),ephemeral=hex(v.get("client_public_hex")),challenge=hex(v.get("challenge_hex"));
    same(Payload.rawPublic(xpair(priv,ephemeral)),ephemeral);
    byte[] aad=p.rewrapAAD(ephemeral,challenge);equal(HexFormat.of().formatHex(aad),v.get("rewrap_aad_hex"));
    byte[] secret=shared(priv,hex(v.get("server_public_hex")));equal(HexFormat.of().formatHex(secret),v.get("shared_hex"));
    equal(hash(aad),v.get("salt_hex"));equal(HexFormat.of().formatHex(hkdf(secret,digest(aad),bytes("authgo/payload/v1/rewrap"),32)),v.get("kek_hex"));
    var response=obj(v.get("response"));same(p.unwrap(new Payload.Envelope(str(response,"e"),str(response,"n"),str(response,"c")),priv,ephemeral,challenge),hex(v.get("content_key_hex")));
    var original=read("payload-envelope.json");Payload payload=Payload.parsePayload(canonical(original.get("payload")));
    equal(HexFormat.of().formatHex(payload.payloadBinding()),original.get("binding_hex"));
    byte[] envelope=concat(payload.aad(),decode(payload.envelope().e()));equal(HexFormat.of().formatHex(envelope),original.get("envelope_aad_hex"));
    byte[] originalShared=shared(hex(original.get("recipient_private_hex")),decode(payload.envelope().e()));equal(HexFormat.of().formatHex(originalShared),original.get("shared_hex"));
    equal(hash(envelope),original.get("salt_hex"));byte[] wrapKey=hkdf(originalShared,digest(envelope),bytes("authgo/payload/v1/wrap"),32);equal(HexFormat.of().formatHex(wrapKey),original.get("kek_hex"));
    same(open(wrapKey,decode(payload.envelope().n()),decode(payload.envelope().c()),envelope),hex(original.get("content_key_hex")));
    var c=read("payload-cache-v2.json");Payload cp=Payload.parsePayload(canonical(c.get("payload")));
    byte[] label=cp.cacheLabel(str(c,"fingerprint"));equal(HexFormat.of().formatHex(label),c.get("label_hex"));
    byte[] info=concat(bytes("authgo-unlock-v2\0"),label);equal(HexFormat.of().formatHex(info),c.get("resource_info_hex"));
    byte[] key=hkdf(hex(c.get("unlock_hash_hex")),new byte[0],info,32);equal(HexFormat.of().formatHex(key),c.get("cache_key_hex"));
    byte[] fileAAD=concat(bytes("authgo-payload-cache-file-v2\0"),digest(label),ByteBuffer.allocate(8).putLong(num(c,"license_id")).array());equal(HexFormat.of().formatHex(fileAAD),c.get("aad_hex"));
    byte[] cipher=seal(key,hex(c.get("nonce_hex")),hex(c.get("material_hex")),fileAAD);equal(HexFormat.of().formatHex(cipher),c.get("ciphertext_hex"));
    equal(PayloadCache.PREFIX+b64(concat(hex(c.get("nonce_hex")),cipher)),c.get("file_utf8"));
    try(Fixture f=new Fixture()) {
      Client.Options options=new Client.Options();options.cacheDir=f.dir;options.fingerprint=str(c,"fingerprint");options.clock=()->num(c,"proof_now");
      Client client=new Client(cp.config(),options);
      equal(client.payloadCache.identity,c.get("cache_identity_utf8"));
      PayloadCache spelling=new PayloadCache(f.dir,"HTTPS://EXAMPLE.TEST/Keep%2FPath?Case=YES","app",FP,new byte[32]);
      check(spelling.identity.startsWith("https://example.test/Keep%2FPath?Case=YES\0app\0"));
      Client.Result result=new Client.Result(client,client.grant(str(c,"ticket")),str(c,"ticket"),new byte[0],"online",Long.MAX_VALUE,"");
      try(var material=client.payloadCache.material(cp,result.data,options.clock.getAsLong(),false)) {
        equal(material.file().getFileName().toString(),c.get("filename"));same(material.key(),key);same(material.aad(),fileAAD);
        Files.writeString(material.file(),str(c,"file_utf8"),StandardOpenOption.CREATE_NEW);Files.setPosixFilePermissions(material.file(),PayloadCache.MODE);
        same(client.loadPayloadKey(cp,result),hex(c.get("material_hex")));
        client.savePayloadKey(cp,result,hex(c.get("material_hex")));same(client.loadPayloadKey(cp,result),hex(c.get("material_hex")));
        equal(Files.getPosixFilePermissions(material.file()),PayloadCache.MODE);
      }
      try(var entries=Files.list(f.dir)){check(entries.noneMatch(path->path.getFileName().toString().contains("proof")));}
    }
    System.out.println("{\"language\":\"java\",\"payload_vectors\":\"PASS\",\"vectors\":[\"payload-envelope\",\"payload-unlock-v2\",\"payload-cache-v2\"]}");
  }

  static Payload v2() throws Exception {
    return Payload.parsePayload(canonical(read("payload-cache-v2.json").get("payload")));
  }
  static void watermarkSignatureTamperV2() throws Exception {
    Payload p=v2();Path dir=Files.createTempDirectory("authgo-v2-watermark-tamper-");
    Server server=new Server(p);Client c=server.client(dir);
    try {
      c.check(LICENSE);
      try(var paths=Files.list(dir)){check(paths.noneMatch(f->f.getFileName().toString().startsWith("authgo-payload-v")));}
      int before=server.calls.size();server.mode="watermark-tamper";
      error("SDK_RESPONSE_SIGNATURE_INVALID",()->c.unlockPayloadMaterial(p));
      try(var paths=Files.list(dir)){check(paths.noneMatch(f->f.getFileName().toString().startsWith("authgo-payload-v")));}
      error("SDK_RESPONSE_SIGNATURE_INVALID",()->c.unlockPayload(p));
      try(var paths=Files.list(dir)){check(paths.noneMatch(f->f.getFileName().toString().startsWith("authgo-payload-v")));}
      equal(server.calls.subList(before,server.calls.size()),List.of("payload.unlock","payload.unlock"));
      server.mode="";same(c.unlockPayloadMaterial(p),concat(server.dek,hex("19".repeat(32))));
    }finally{try(var paths=Files.walk(dir)){for(Path f:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(f);}}
  }

  static void watermarkV2() throws Exception {
    Payload p=v2();same(Payload.parsePayload(canonical(p.toMap())).payloadBinding(),p.payloadBinding());
    check(new String(p.aad(),java.nio.charset.StandardCharsets.ISO_8859_1).startsWith("authgo-payload-envelope-v2\0"));
    error("PAYLOAD_INVALID",()->new Payload(99,p.appKey(),p.version(),p.builtAt(),p.keyId(),p.config(),p.manifest(),p.envelope()).validated());
    var m=obj(parse(decode(p.manifest())));var meta=obj(list(m.get("files")).get(list(m.get("files")).size()-1));meta.put("main_class","");
    error("PAYLOAD_INVALID",()->new Payload(2,p.appKey(),p.version(),p.builtAt(),p.keyId(),p.config(),b64(bytes(canonical(m))),p.envelope()).validated());
    for(Object bad:List.of("0".repeat(64),"AA".repeat(32),"1",32))error("SDK_RESPONSE_INVALID",()->PayloadWatermark.response(bad));
    Path dir=Files.createTempDirectory("authgo-v2-");Server server=new Server(p);Client c=server.client(dir);
    try {
      var result=c.check(LICENSE);same(c.unlockPayload(p),server.dek);byte[] material=c.unlockPayloadMaterial(p);
      same(material,concat(server.dek,hex("19".repeat(32))));same(c.loadPayloadKey(p,result),material);
      try(var paths=Files.list(dir)){check(paths.anyMatch(f->f.getFileName().toString().startsWith("authgo-payload-v2-")));}
      var grant=obj(parse(decode(result.ticket().split("\\.")[0])));var otherGrant=copy(grant);otherGrant.put("license_id",43);
      error("SDK_CACHE_INVALID",()->c.payloadCache.load(p,otherGrant,server.now,false));
      try(var derived=c.payloadCache.material(p,grant,server.now,false)){
        byte[] saved=Files.readAllBytes(derived.file()),nonce=random(12);
        Files.writeString(derived.file(),"AUTHGO-PAYLOAD-CACHE-v2."+b64(concat(nonce,seal(derived.key(),nonce,server.dek,derived.aad()))));
        error("SDK_CACHE_INVALID",()->c.payloadCache.load(p,grant,server.now,false));Files.write(derived.file(),saved);
      }
      server.changes.put("watermark","0".repeat(64));error("SDK_RESPONSE_INVALID",()->c.unlockPayloadMaterial(p));server.changes.clear();
      server.mode="network";same(c.unlockPayloadMaterial(p),material);server.now+=121;error("SDK_NETWORK_ERROR",()->c.unlockPayloadMaterial(p));server.now-=121;
      server.mode="";server.code="LICENSE_REVOKED";error("LICENSE_REVOKED",()->c.unlockPayloadMaterial(p));
      try(var paths=Files.list(dir)){check(paths.noneMatch(f->f.getFileName().toString().startsWith("authgo-payload-v2-")));}
      equal(caches(dir).size(),0);
      server.code="";c.check(LICENSE);server.trial=true;c.unlockPayloadMaterial(p);
      try(var paths=Files.list(dir)){check(paths.noneMatch(f->f.getFileName().toString().startsWith("authgo-payload-v2-")));}
      Arrays.fill(material,(byte)0);
    }finally{try(var paths=Files.walk(dir)){for(Path f:paths.sorted(Comparator.reverseOrder()).toList())Files.deleteIfExists(f);}}
    String tag="a".repeat(32),slot=tag+"0".repeat(64);byte[] target=bytes(slot.repeat(8));
    var files=List.of(new PayloadFiles.File("app","java","00000000.agc",target.length,"Main"));
    var offsets=new ArrayList<String>();for(int i=0;i<8;i++)offsets.add(Integer.toString(i*96));
    var index=map("v","1","tag",tag,"files",List.of(map("index","0","entries",List.of(map("path",List.of("Main.class"),"offsets",offsets)))));
    byte[] raw=bytes(canonical(index));var parsed=PayloadWatermark.parseIndex(raw,files);
    target[target.length-1]='1';error("PAYLOAD_INVALID",()->PayloadWatermark.prepare(Map.of(List.of("Main.class"),target),parsed,0));equal(target[32],(byte)'0');target[target.length-1]='0';
    byte[] material=concat(new byte[32],hex("19".repeat(32)));PayloadWatermark.apply(PayloadWatermark.prepare(Map.of(List.of("Main.class"),target),parsed,0),material);equal(new String(target,32,64,java.nio.charset.StandardCharsets.US_ASCII),"19".repeat(32));
    for(String bad:List.of(canonical(index).replace("\"v\":\"1\"","\"v\":2"),canonical(index).replace("Main.class","../Main.class"),canonical(index).replace("\"0\",\"96\"","\"0\",\"95\""),canonical(index).replace("\"v\":\"1\"","\"v\":\"1\",\"v\":\"1\"")))error("PAYLOAD_INVALID",()->PayloadWatermark.parseIndex(bytes(bad),files));
  }

  public static void run()throws Exception {
    cases=0;
    runCase("cross-language vectors",PayloadTests::vectors);
    runCase("v2 strict schema material cache refusal trial expiry and atomic slots",PayloadTests::watermarkV2);
    runCase("v2 post-signature valid watermark tamper rejects signature without payload cache",PayloadTests::watermarkSignatureTamperV2);
    runCase("NOT_ACTIVATED and restored cache",()->{try(Fixture f=new Fixture()){
      error("SDK_NOT_ACTIVATED",()->f.client.unlockPayload(f.payload));equal(f.server.calls.size(),0);
      f.client.check(LICENSE);Client restored=f.server.client(f.dir);int calls=f.server.calls.size();
      error("SDK_NOT_ACTIVATED",()->restored.unlockPayload(f.payload));equal(f.server.calls.size(),calls);
    }});
    runCase("authenticated unlock and encrypted files only",()->{try(Fixture f=new Fixture().prime()){
      equal(caches(f.dir).size(),1);Path file=caches(f.dir).get(0);String raw=Files.readString(file);
      check(raw.startsWith(PayloadCache.PREFIX));check(!raw.contains(b64(f.server.dek)));check(!file.toString().contains(LICENSE));
      try(var entries=Files.list(f.dir)){check(entries.noneMatch(p->p.getFileName().toString().contains("proof")));}
      error("SDK_CACHE_UNAVAILABLE",()->f.client.loadPayloadKey(f.payload,new Client.Result(f.client,Map.of(),"",new byte[0],"offline",Long.MAX_VALUE,"")));
    }});
    runCase("offline ticket avoids repeated network timeout",()->{try(Fixture f=new Fixture()){
      f.server.floating=true;f.prime();f.server.now+=25;f.server.mode="network";equal(f.client.check(LICENSE).status,"grace");
      int calls=f.server.calls.size();same(f.client.unlockPayload(f.payload),f.server.dek);equal(f.server.calls.size(),calls);
      Client restored=f.server.client(f.dir);equal(restored.check(LICENSE).status,"grace");calls=f.server.calls.size();same(restored.unlockPayload(f.payload),f.server.dek);equal(f.server.calls.size(),calls);
    }});
    runCase("tamper permissions symlink size",()->{try(Fixture f=new Fixture().prime()){
      Path file=caches(f.dir).get(0);byte[] raw=Files.readAllBytes(file);
      Files.writeString(file,PayloadCache.PREFIX+b64(new byte[60]));error("SDK_CACHE_INVALID",()->f.client.loadPayloadKey(f.payload,f.result));
      Files.write(file,raw);Files.setPosixFilePermissions(file,PosixFilePermissions.fromString("rw-r--r--"));error("SDK_CACHE_UNAVAILABLE",()->f.client.loadPayloadKey(f.payload,f.result));
      Files.setPosixFilePermissions(file,PayloadCache.MODE);Files.write(file,new byte[257]);error("SDK_CACHE_UNAVAILABLE",()->f.client.loadPayloadKey(f.payload,f.result));
      Files.delete(file);Path target=f.dir.resolve("target");Files.write(target,raw);Files.setPosixFilePermissions(target,PayloadCache.MODE);Files.createSymbolicLink(file,target);
      error("SDK_CACHE_UNAVAILABLE",()->f.client.loadPayloadKey(f.payload,f.result));f.client.savePayloadKey(f.payload,f.result,concat(f.server.dek,hex("19".repeat(32))));check(Files.isSymbolicLink(file));same(Files.readAllBytes(target),raw);
    }});
    runCase("atomic replacement and old cache",()->{try(Fixture f=new Fixture().prime()){
      Path file=caches(f.dir).get(0);byte[] old=Files.readAllBytes(file);f.client.savePayloadKey(f.payload,f.result,new byte[1]);same(Files.readAllBytes(file),old);
      same(f.client.unlockPayload(f.payload),f.server.dek);same(f.client.loadPayloadKey(f.payload,f.result),concat(f.server.dek,hex("19".repeat(32))));
      try(var entries=Files.list(f.dir)){check(entries.noneMatch(p->p.toString().endsWith(".tmp")));}
    }});
    runCase("unwritable cache best effort",()->{try(Fixture f=new Fixture()){
      Path file=f.dir.resolve("not-directory");Files.writeString(file,"file");Client client=f.server.client(file);
      client.check(LICENSE);same(client.unlockPayload(f.payload),f.server.dek);
    }});
    runCase("memory cache never persists content key",()->{try(Fixture f=new Fixture()){
      Client client=f.server.client(Path.of(""));Client.Result result=client.check(LICENSE);same(client.unlockPayload(f.payload),f.server.dek);
      error("SDK_CACHE_UNAVAILABLE",()->client.loadPayloadKey(f.payload,result));equal(caches(f.dir).size(),0);
    }});
    runCase("trial and zero grace clear old caches",()->{try(Fixture f=new Fixture().prime()){
      for(String mode:List.of("trial","zero")){f.server.mode="";f.client.verify();f.client.unlockPayload(f.payload);equal(caches(f.dir).size(),1);f.server.mode=mode;same(f.client.unlockPayload(f.payload),f.server.dek);equal(caches(f.dir).size(),0);}
    }});
    runCase("ordinary checks and deactivate clean caches",()->{try(Fixture f=new Fixture().prime()){
      f.server.trial=true;f.client.verify();equal(caches(f.dir).size(),0);
      f.server.trial=false;f.client.verify();f.client.unlockPayload(f.payload);equal(caches(f.dir).size(),1);
      f.client.deactivate();equal(caches(f.dir).size(),0);error("SDK_NOT_ACTIVATED",()->f.client.unlockPayload(f.payload));
    }});
    runCase("cache scope and license binding",()->{try(Fixture f=new Fixture().prime()){
      Client other=f.server.client(f.dir,"ab".repeat(32));other.check(LICENSE);other.unlockPayload(f.payload);
      Path proof=f.dir.resolve("authgo-payload-proof-v1-untouched.cache");Files.writeString(proof,"untouched");
      var g=copy(f.result.data);g.put("license_id",43);Client.Result wrong=new Client.Result(f.client,g,f.server.signed(g),new byte[0],"online",Long.MAX_VALUE,"");
      error("SDK_CACHE_INVALID",()->f.client.loadPayloadKey(f.payload,wrong));f.client.clearPayloadKeys();equal(caches(f.dir).size(),1);equal(Files.readString(proof),"untouched");
    }});
    runCase("cache expiry future issue and starts_at",()->{try(Fixture f=new Fixture().prime()){
      var g=copy(f.result.data);g.put("grace_until",iso(f.server.now));
      error("SDK_GRACE_EXPIRED",()->f.client.loadPayloadKey(f.payload,result(f,g)));
      g.put("issued_at",iso(f.server.now+301));g.put("grace_until",iso(f.server.now+500));error("SDK_GRACE_EXPIRED",()->f.client.loadPayloadKey(f.payload,result(f,g)));
      g.put("issued_at",iso(f.server.now));g.put("starts_at",iso(f.server.now+1));error("LICENSE_NOT_STARTED",()->f.client.loadPayloadKey(f.payload,result(f,g)));
    }});
    runCase("grace exact boundary expiry and clock rollback",()->{try(Fixture f=new Fixture().prime()){
      long initial=f.server.now;f.server.now+=120;error("SDK_GRACE_EXPIRED",()->f.client.loadPayloadKey(f.payload,f.result));
      f.client.clearPayloadKeys();f.client.savePayloadKey(f.payload,f.result,concat(f.server.dek,hex("19".repeat(32))));equal(caches(f.dir).size(),0);
      f.server.now=initial-301;error("SDK_CLOCK_ROLLBACK",()->f.client.unlockPayload(f.payload));f.server.now=initial;
      var g=copy(f.result.data);g.put("expires_at",iso(initial));error("LICENSE_EXPIRED",()->f.client.loadPayloadKey(f.payload,result(f,g)));
    }});
    runCase("authenticated refusals invalidate unlock verify heartbeat",()->{try(Fixture f=new Fixture()){
      for(String code:List.of("LICENSE_REVOKED","VERSION_DISABLED","MAINTENANCE_EXPIRED","UNKNOWN_NEW_REFUSAL"))for(int op=0;op<3;op++){
        f.server.code="";f.prime();f.server.code=code;int action=op;
        error(code,()->{if(action==0)f.client.unlockPayload(f.payload);else if(action==1)f.client.verify();else f.client.heartbeat();});
        equal(caches(f.dir).size(),0);error("SDK_NOT_ACTIVATED",()->f.client.unlockPayload(f.payload));
      }
    }});
    runCase("instance replaced retains proof but clears keys",()->{try(Fixture f=new Fixture().prime()){
      var stateField=Client.class.getDeclaredField("state");stateField.setAccessible(true);var before=copy(obj(stateField.get(f.client)));
      f.server.code="INSTANCE_REPLACED";error("INSTANCE_REPLACED",()->f.client.unlockPayload(f.payload));equal(caches(f.dir).size(),0);
      error("SDK_NOT_ACTIVATED",()->f.client.unlockPayload(f.payload));error("INSTANCE_REPLACED",f.client::verify);
      var after=obj(stateField.get(f.client));equal(after.get("ticket"),before.get("ticket"));equal(after.get("seed"),before.get("seed"));check(!yes(after,"refused"));
    }});
    runCase("PAYLOAD_INVALID and unauthenticated errors preserve caches",()->{try(Fixture f=new Fixture().prime()){
      Path file=caches(f.dir).get(0);byte[] before=Files.readAllBytes(file);
      for(String mode:List.of("network","status","html","signature","nonce","")){
        f.server.mode=mode;f.server.code=mode.isEmpty()?"PAYLOAD_INVALID":"";same(f.client.unlockPayload(f.payload),f.server.dek);same(Files.readAllBytes(file),before);
      }
      f.client.clearPayloadKeys();error("PAYLOAD_INVALID",()->f.client.unlockPayload(f.payload));check(TEMPORARY.contains("PAYLOAD_INVALID"));
    }});
    runCase("wrap field schema recovers but null/string invalid does not",()->{try(Fixture f=new Fixture().prime()){
      for(Object value:List.of(17,true,Map.of(),List.of())){f.server.changes=map("e",value);same(f.client.unlockPayload(f.payload),f.server.dek);}
      f.server.changes=map();f.server.mode="missing-wrap";same(f.client.unlockPayload(f.payload),f.server.dek);f.server.mode="";
      for(String value:new String[]{null,"bad","="}){f.server.changes=map("e",value);error("SDK_RESPONSE_INVALID",()->f.client.unlockPayload(f.payload));}
    }});
    runCase("fresh invalid grants or unwrap never fall back",()->{try(Fixture f=new Fixture().prime()){
      Path file=caches(f.dir).get(0);byte[] before=Files.readAllBytes(file);
      for(String mode:List.of("challenge","license","seed","issued","wrap")){
        f.server.mode=mode;error(mode.equals("issued")?"SDK_RESPONSE_TIMESTAMP_INVALID":"SDK_RESPONSE_INVALID",()->f.client.unlockPayload(f.payload));same(Files.readAllBytes(file),before);
      }
      f.server.mode="";f.server.changes=map("ticket","bad");error("SDK_RESPONSE_SIGNATURE_INVALID",()->f.client.unlockPayload(f.payload));
    }});
    runCase("copy and rename into another instance rejected",()->{try(Fixture f=new Fixture().prime()){
      Client other=f.server.client(f.dir,"cd".repeat(32));Client.Result result=other.check(LICENSE);
      try(var material=other.payloadCache.material(f.payload,result.data,f.server.now,false)){
        Files.copy(caches(f.dir).get(0),material.file());error("SDK_CACHE_INVALID",()->other.loadPayloadKey(f.payload,result));
      }
    }});
    runCase("strict payload schema duplicates aliases bounds and config binding",()->{try(Fixture f=new Fixture()){
      var base=f.payload.toMap();for(String key:base.keySet()){var wrong=copy(base);wrong.remove(key);error("PAYLOAD_INVALID",()->Payload.parsePayload(canonical(wrong)));}
      for(String raw:List.of("null","[]","{}","{\"v\":2,\"v\":2}","{".repeat(66000)))error("PAYLOAD_INVALID",()->Payload.parsePayload(raw));
      for(var entry:map("v",true,"key_id","bad.key","version","1.2.3-01","built_at","2026-02-30T00:00:00Z","app_key","a".repeat(257),"manifest","__==","App_Key","wrong","config","authgo2.bad").entrySet()){
        var wrong=copy(base);wrong.put(entry.getKey(),entry.getValue());error("PAYLOAD_INVALID",()->Payload.parsePayload(canonical(wrong)));
      }
      var config=obj(parse(decode(f.payload.config().substring(8))));config.put("app_secret","changed");var changed=copy(base);changed.put("config","authgo2."+b64(bytes(canonical(config))));
      check(!Arrays.equals(Payload.parsePayload(canonical(changed)).payloadBinding(),f.payload.payloadBinding()));
      f.prime();config.put("app_key","other-app");changed.put("app_key","other-app");changed.put("config","authgo2."+b64(bytes(canonical(config))));
      Payload wrongApp=Payload.parsePayload(canonical(changed));int calls=f.server.calls.size();
      error("PAYLOAD_INVALID",()->f.client.unlockPayload(wrongApp));equal(f.server.calls.size(),calls);
    }});
    runCase("JSON exact size integer metadata and 64-bit precision",()->{try(Fixture f=new Fixture()){
      String raw=canonical(f.payload.toMap());Payload.parsePayload(raw+" ".repeat(65536-bytes(raw).length));
      error("PAYLOAD_INVALID",()->Payload.parsePayload(raw+" ".repeat(65537-bytes(raw).length)));
      for(String token:List.of("2.0","2e0","\"2\""))error("PAYLOAD_INVALID",()->Payload.parsePayload(raw.replace("\"v\":2","\"v\":"+token)));
      var manifest=obj(parse(decode(f.payload.manifest())));var file=obj(list(manifest.get("files")).get(0));
      for(Object size:List.of("0",-1,new JsonNumber("4611686018427387904"))){file.put("size",size);var wrong=f.payload.toMap();wrong.put("manifest",b64(bytes(canonical(manifest))));error("PAYLOAD_INVALID",()->Payload.parsePayload(canonical(wrong)));}
      file.put("size",new JsonNumber("4611686018427387903"));var good=f.payload.toMap();good.put("manifest",b64(bytes(canonical(manifest))));Payload.parsePayload(canonical(good));
      for(String field:List.of("python_version","main_class","architecture")) {
        var wrongManifest=copy(manifest);obj(list(wrongManifest.get("files")).get(0)).put(field,null);
        var wrong=f.payload.toMap();wrong.put("manifest",b64(bytes(canonical(wrongManifest))));error("PAYLOAD_INVALID",()->Payload.parsePayload(canonical(wrong)));
      }
      for(String date:List.of("2026-02-29T00:00:00Z","2026-11-07T24:00:00Z","2026-11-07T00:60:00Z","2026-11-07T00:00:60Z","2026-11-07T00:00:00+00:00")) {
        var wrong=f.payload.toMap();wrong.put("built_at",date);error("PAYLOAD_INVALID",()->Payload.parsePayload(canonical(wrong)));
      }
      var leap=f.payload.toMap();leap.put("built_at","2024-02-29T00:00:00Z");Payload.parsePayload(canonical(leap));
      var cfg=obj(parse(decode(f.payload.config().substring(8))));

      f.server.id=9007199254740993L;f.prime();same(f.client.loadPayloadKey(f.payload,f.result),concat(f.server.dek,hex("19".repeat(32))));
    }});
    runCase("Go HTTPS predicate",()->{try(Fixture f=new Fixture()){
      var config=obj(parse(decode(f.payload.config().substring(8))));
      for(String url:List.of("http://host","https:host","https:///host","https://host\n"," https://host","https://user@host","https://host?x=1","https://host#x","https://host:abc","https://ho%41st","https://ho{st","https://ho|st","https://ho}st","https://host/path%zz"))
        for(String field:List.of("url")){var c=copy(config);c.put(field,field.equals("url")?url:List.of(url));var wrong=f.payload.toMap();wrong.put("config","authgo2."+b64(bytes(canonical(c))));error("PAYLOAD_INVALID",()->Payload.parsePayload(canonical(wrong)));}
      for(String url:List.of("HTTPS://host","https://ho]st","https://[syntactic-host]","https://host:65536","https://host:","https://host/path space","https://host/path?","https://host#")){
        var c=copy(config);c.put("url",url);var p=f.payload.toMap();p.put("config","authgo2."+b64(bytes(canonical(c))));Payload.parsePayload(canonical(p));
      }
    }});
    runCase("unwrap rejects altered binding low-order and challenge",()->{
      var v=read("payload-unlock-v2.json");Payload p=Payload.parsePayload(canonical(v.get("payload")));var response=obj(v.get("response"));
      byte[] priv=hex(v.get("client_private_hex")),ephemeral=hex(v.get("client_public_hex")),challenge=hex(v.get("challenge_hex"));
      var changed=p.toMap();changed.put("version","2.0.0");Payload other=Payload.parsePayload(canonical(changed));var wrap=new Payload.Envelope(str(response,"e"),str(response,"n"),str(response,"c"));
      error("SDK_RESPONSE_INVALID",()->other.unwrap(wrap,priv,ephemeral,challenge));error("SDK_RESPONSE_INVALID",()->p.unwrap(new Payload.Envelope(b64(new byte[32]),wrap.n(),wrap.c()),priv,ephemeral,challenge));
      error("SDK_RESPONSE_INVALID",()->p.unwrap(wrap,priv,ephemeral,new byte[32]));
    });
    runCase("concurrent unlock verify and cache clear serialized",()->{try(Fixture f=new Fixture().prime()){
      var pool=Executors.newFixedThreadPool(4);
      try {
        var jobs=new ArrayList<Future<?>>();for(int i=0;i<12;i++){int action=i%3;jobs.add(pool.submit(()->{if(action==0)f.client.verify();else if(action==1)same(f.client.unlockPayload(f.payload),f.server.dek);else same(f.client.loadPayloadKey(f.payload,f.result),concat(f.server.dek,hex("19".repeat(32))));}));}
        for(var job:jobs)job.get(5,TimeUnit.SECONDS);equal(f.server.maximum.get(),1);
        f.server.entered=new CountDownLatch(1);f.server.proceed=new CountDownLatch(1);
        var unlock=pool.submit(()->f.client.unlockPayload(f.payload));check(f.server.entered.await(2,TimeUnit.SECONDS));
        var clear=pool.submit(f.client::clearPayloadKeys);f.server.proceed.countDown();same(unlock.get(5,TimeUnit.SECONDS),f.server.dek);clear.get(5,TimeUnit.SECONDS);equal(caches(f.dir).size(),0);
      }finally{if(f.server.proceed!=null)f.server.proceed.countDown();pool.shutdownNow();}
    }});
    runCase("release-seat refusal clears cached keys",()->{try(Fixture f=new Fixture()){
      f.server.floating=true;f.prime();f.server.code="LICENSE_REVOKED";error("LICENSE_REVOKED",f.client::releaseSeat);equal(caches(f.dir).size(),0);error("SDK_NOT_ACTIVATED",()->f.client.unlockPayload(f.payload));
    }});
    System.out.println("{\"language\":\"java\",\"payload_tests\":\"PASS\",\"tests\":"+cases+"}");
  }
  static Client.Result result(Fixture f,Map<String,Object> g)throws GeneralSecurityException{return new Client.Result(f.client,g,f.server.signed(g),new byte[0],"online",Long.MAX_VALUE,"");}
  public static void main(String[] args)throws Exception{run();}
}
