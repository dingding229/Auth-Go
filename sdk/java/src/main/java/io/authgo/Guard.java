package io.authgo;

import java.util.concurrent.*;
import java.util.function.BiConsumer;

/** An in-process guard. The application owns signals and process exit. */
public final class Guard implements AutoCloseable {
  public static final int EXIT_LICENSE = 77;
  interface Backend {
    long now(); Client.Result verify(); Client.Result heartbeat();
    void validate(String ticket); void release();
    default byte[] unlockPayloadMaterial(Payload payload) { return unlockPayload(payload); }
    default byte[] unlockPayload(Payload payload) { throw new Client.AuthGoException("SDK_NOT_ACTIVATED"); }
  }
  private final Backend client;
  private final Object gate = new Object();
  private final CountDownLatch stop = new CountDownLatch(1), stopped = new CountDownLatch(1);
  private final CompletableFuture<Void> done = new CompletableFuture<>();
  private CompletableFuture<Void> closed;
  private long closeDeadline;
  private Client.Result result;
  private Client.AuthGoException error;
  private final BiConsumer<Client.Result, Client.AuthGoException> onChange;

  public static Guard start(GuardOptions opts) {
    if (opts == null || opts.config == null || opts.config.isEmpty()) throw new Client.AuthGoException("SDK_INVALID_CONFIG");
    var src = opts.sdkOptions == null ? new Client.Options() : opts.sdkOptions;
    var options = new Client.Options();
    options.fingerprint = src.fingerprint; options.cacheDir = src.cacheDir;
    options.clock = src.clock; options.httpClient = src.httpClient;
    options.version = opts.version;
    var c = new Client(opts.config, options);
    String key = opts.license == null || opts.license.isEmpty() ? System.getenv("AUTHGO_LICENSE") : opts.license;
    var first = c.guardCheck(key == null ? "" : key); // Failure never starts a loop.
    return new Guard(new Backend() {
      public long now() { return c.now(); }
      public Client.Result verify() { return c.verify(); }
      public Client.Result heartbeat() { return c.heartbeat(); }
      public void validate(String ticket) { c.validate(ticket); }
      public void release() { c.releaseSeat(); }
      public byte[] unlockPayload(Payload payload) { return c.unlockPayload(payload); }
      public byte[] unlockPayloadMaterial(Payload payload) { return c.unlockPayloadMaterial(payload); }
    }, first, opts.onChange);
  }
  Guard(Backend backend, Client.Result first, BiConsumer<Client.Result,Client.AuthGoException> change) {
    client = backend; result = first.snapshot(); onChange = change;
    var worker = new Thread(this::run, "authgo-guard"); worker.setDaemon(true); worker.start();
  }
  public Client.Result result() { synchronized(gate) { return result.snapshot(); } }
  public CompletableFuture<Void> done() { return done; }
  public Client.AuthGoException error() { synchronized(gate) { return error; } }
  public void require(String feature) {
    Client.Result proof;
    synchronized(gate) { active(); proof = result.snapshot(); }
    client.validate(proof.ticket()); // Never hold lifecycle lock behind Client's I/O lock.
    synchronized(gate) {
      active();
      if (feature != null && !feature.isEmpty() && !Boolean.TRUE.equals(Client.obj(proof.data.get("features")).get(feature)))
        throw new Client.AuthGoException("INVALID_POLICY");
    }
  }
  public void require() { require(""); }
  byte[] unlockPayload(Payload payload) { require(); return client.unlockPayload(payload); }
  byte[] unlockPayloadMaterial(Payload payload) { require(); return client.unlockPayloadMaterial(payload); }
  private void active() {
    if (error != null) throw error;
    if (stop.getCount() == 0 || done.isDone()) throw new Client.AuthGoException("SDK_NOT_ACTIVATED");
  }
  private void notifyChange(Client.Result value, Client.AuthGoException problem) {
    boolean failed=false;
    synchronized(gate) {
      if (stop.getCount() == 0) return;
      if (value != null) result = value.snapshot();
      if (problem != null && error == null) { error = problem; failed=true; }
    }
    if (failed) done.complete(null);
    if (onChange != null) onChange.accept(value == null ? null : value.snapshot(), problem);
  }
  private void run() {
    try {
      if (stop.getCount() == 0) return;
      Client.Result r = client.verify(); notifyChange(r,null);
      long verify = client.now() + Client.num(r.data,"next_check_in"), heartbeat = client.now()+r.heartbeatInterval;
      while (stop.getCount() != 0) {
        boolean floating = Boolean.TRUE.equals(r.data.get("floating"));
        long next = Math.min(verify, floating ? heartbeat : Long.MAX_VALUE);
        next = Math.min(next,Client.date(r.data.get("expires_at")));
        next = Math.min(next,r.status.equals("grace") ? r.usableUntil() : Client.date(r.data.get("lease_expires_at")));
        if (stop.await(Math.max(0,next-client.now()),TimeUnit.SECONDS)) return;
        long now=client.now();
        if (now>=verify || now>=next && (!floating || now<heartbeat)) {
          r=client.verify();notifyChange(r,null);verify=client.now()+Client.num(r.data,"next_check_in");
        }
        if (Boolean.TRUE.equals(r.data.get("floating")) && client.now()>=heartbeat && stop.getCount()!=0) {
          r=client.heartbeat();notifyChange(r,null);heartbeat=client.now()+r.heartbeatInterval;
        }
      }
    } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
      catch (Client.AuthGoException e) { notifyChange(null,e); }
      catch (RuntimeException e) { notifyChange(null,new Client.AuthGoException("SDK_RESPONSE_INVALID",false,e)); }
    finally { stopped.countDown(); }
  }
  @Override public void close() {
    CompletableFuture<Void> completion;
    synchronized(gate) {
      if (closed == null) {
        stop.countDown(); closeDeadline = System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
        closed = new CompletableFuture<>();
        var release = new Thread(() -> {
          try {
            if (!stopped.await(Math.max(0,closeDeadline-System.nanoTime()),TimeUnit.NANOSECONDS) || System.nanoTime()>=closeDeadline || closed.isDone())
              throw new Client.AuthGoException("SDK_NETWORK_ERROR");
            client.release(); closed.complete(null);
          } catch (Exception e) { closed.completeExceptionally(e); }
        },"authgo-release");
        release.setDaemon(true); release.start();
      }
      completion = closed;
    }
    try { completion.get(Math.max(0,closeDeadline-System.nanoTime()),TimeUnit.NANOSECONDS); }
    catch (InterruptedException e) { Thread.currentThread().interrupt();throw new Client.AuthGoException("SDK_NETWORK_ERROR",false,e); }
    catch (TimeoutException e) {
      var failure=new Client.AuthGoException("SDK_NETWORK_ERROR",false,e);completion.completeExceptionally(failure);throw failure;
    } catch (ExecutionException e) {
      if (e.getCause() instanceof Client.AuthGoException problem) throw problem;
      throw new Client.AuthGoException("SDK_NETWORK_ERROR",false,e);
    }
  }
}
