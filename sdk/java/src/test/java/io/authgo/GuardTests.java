package io.authgo;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

public final class GuardTests {
  static void check(boolean value){if(!value)throw new AssertionError("guard assertion");}
  static class Fake implements Guard.Backend {
    final Client c; volatile String failure, status="grace";
    final AtomicInteger calls=new AtomicInteger(),releases=new AtomicInteger(),heartbeats=new AtomicInteger();
    volatile CountDownLatch block,validation;
    final CountDownLatch entered=new CountDownLatch(1);
    volatile String releaseFailure;
    Fake() throws Exception {
      var v=Client.obj(Client.parse(Files.readAllBytes(Path.of("sdk/vectors/v2.json"))));
      var opts=new Client.Options();opts.fingerprint="a".repeat(64);opts.cacheDir=Path.of("");
      c=new Client(config(v),opts);
    }
    static String config(Map<String,Object> v){return "authgo2."+Client.b64(Client.bytes(Client.canonical(Map.of("url","http://127.0.0.1:1","app_key","unit","app_secret","test","public_key",Base64.getEncoder().encodeToString(Client.decode(v.get("ed25519_public").toString())),"gateway_key",v.get("gateway_public")))));}
    public long now(){return Instant.now().getEpochSecond();}
    Client.Result value(){
      var d=new TreeMap<String,Object>();d.put("features",new TreeMap<>(Map.of("export",true,"nested",new TreeMap<>(Map.of("n",new Client.JsonNumber("1"))))));
      d.put("floating",true);d.put("next_check_in",new Client.JsonNumber("10"));d.put("issued_at",Instant.ofEpochSecond(now()).toString());d.put("lease_expires_at",Instant.ofEpochSecond(now()+2).toString());
      return new Client.Result(c,d,"proof",new byte[32],status,now()+30,"");
    }
    public Client.Result verify(){calls.incrementAndGet();await(block);if(failure!=null)throw new Client.AuthGoException(failure);return value();}
    public Client.Result heartbeat(){heartbeats.incrementAndGet();return verify();}
    public void validate(String ticket){check(ticket.equals("proof"));entered.countDown();await(validation);}
    public void release(){releases.incrementAndGet();if(releaseFailure!=null)throw new Client.AuthGoException(releaseFailure);}
    static void await(CountDownLatch block){if(block!=null)try{block.await();}catch(InterruptedException e){Thread.currentThread().interrupt();}}
  }
  static void waitFor(java.util.function.BooleanSupplier test) throws Exception {long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(3);while(!test.getAsBoolean()){check(System.nanoTime()<end);Thread.sleep(10);}}
  public static void run() throws Exception {
    try{Guard.start(new GuardOptions());throw new AssertionError();}catch(Client.AuthGoException e){check(e.code.equals("SDK_INVALID_CONFIG"));}
    var f=new Fake();var options=new GuardOptions();options.config=Fake.config(Client.obj(Client.parse(Files.readAllBytes(Path.of("sdk/vectors/v2.json")))));options.license="abc";options.sdkOptions.fingerprint="a".repeat(64);options.sdkOptions.cacheDir=Path.of("");
    try{Guard.start(options);throw new AssertionError();}catch(Client.AuthGoException e){check(e.code.equals("INVALID_LICENSE_KEY"));}
    var changed=new CountDownLatch(1);var g=new Guard(f,f.value(),(r,e)->changed.countDown());check(changed.await(2,TimeUnit.SECONDS));
    check(!g.done().isDone());check(g.result().heartbeatInterval==1);check(!g.result().data.containsKey("heartbeat_interval"));
    var pool=Executors.newFixedThreadPool(8);
    try {
      var jobs=new ArrayList<Future<?>>();for(int i=0;i<8;i++)jobs.add(pool.submit(()->{for(int j=0;j<100;j++){var r=g.result();Client.obj(Client.obj(r.data.get("features")).get("nested")).put("n",99);g.require("export");}}));
      for(var job:jobs)job.get();check(Client.obj(Client.obj(g.result().data.get("features")).get("nested")).get("n").toString().equals("1"));
      try{g.require("missing");throw new AssertionError();}catch(Client.AuthGoException e){check(e.code.equals("INVALID_POLICY"));}
      waitFor(()->f.heartbeats.get()>0);check(f.calls.get()<=3);
      f.failure="SDK_GRACE_EXPIRED";waitFor(()->g.done().isDone());check(g.error().code.equals(f.failure));
      try{g.require();throw new AssertionError();}catch(Client.AuthGoException e){check(e.code.equals(f.failure));}
      g.close();g.close();check(f.releases.get()==1);
    }finally{pool.shutdownNow();g.close();}
    var releasing=new Fake();releasing.releaseFailure="SDK_NETWORK_ERROR";var releaseGuard=new Guard(releasing,releasing.value(),null);
    try{releaseGuard.close();throw new AssertionError();}catch(Client.AuthGoException e){check(e.code.equals("SDK_NETWORK_ERROR"));check(!releaseGuard.done().isDone());}
    var reading=new Fake();reading.validation=new CountDownLatch(1);var rg=new Guard(reading,reading.value(),null);
    var reader=CompletableFuture.runAsync(()->{try{rg.require();throw new AssertionError();}catch(Client.AuthGoException e){check(e.code.equals("SDK_NOT_ACTIVATED"));}});
    check(reading.entered.await(1,TimeUnit.SECONDS));
    var failsafe=new Thread(()->{try{Thread.sleep(2000);}catch(InterruptedException ignored){}reading.validation.countDown();});failsafe.setDaemon(true);failsafe.start();
    long closeStart=System.nanoTime();rg.close();check(System.nanoTime()-closeStart<TimeUnit.SECONDS.toNanos(1));reading.validation.countDown();reader.get(1,TimeUnit.SECONDS);
    var blocked=new Fake();blocked.block=new CountDownLatch(1);var b=new Guard(blocked,blocked.value(),null);waitFor(()->blocked.calls.get()>0);long start=System.nanoTime();
    try{b.close();throw new AssertionError();}catch(Client.AuthGoException e){check(e.code.equals("SDK_NETWORK_ERROR"));check(System.nanoTime()-start<TimeUnit.MILLISECONDS.toNanos(5500));}finally{blocked.block.countDown();}
    Thread.sleep(30);check(blocked.releases.get()==0);check(Guard.EXIT_LICENSE==77);
    System.out.println("Java Guard lifecycle/concurrency/heartbeat/close PASS");
  }
}
