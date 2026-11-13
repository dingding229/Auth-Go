import io.authgo.*;
import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.util.Properties;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

public final class Main {
  public static void main(String[] args) throws Exception {
    var stopping = new CountDownLatch(1);
    var guard = new AtomicReference<Guard>();
    var exitCode = new AtomicInteger();
    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      stopping.countDown(); var g=guard.get();
      if(g!=null)try {g.close();}catch(Exception e){System.err.println("释放席位: "+e);}
      System.out.flush();System.err.flush();Runtime.getRuntime().halt(exitCode.get());
    },"business-shutdown"));
    var build = new Properties();
    try(var resource=Main.class.getResourceAsStream("/authgo-build.properties")) {
      if(resource==null)throw new IllegalStateException("缺少构建配置");build.load(resource);
    }
    var opts = new GuardOptions();opts.config=build.getProperty("config","");opts.version=build.getProperty("version","");
    opts.onChange=(r,e)->{
      if(e!=null)System.err.println("授权检查: "+e);
      if(r!=null){System.out.println("授权状态: "+r.status);if(!r.cacheWarning.isEmpty())System.out.println("缓存提示: "+r.cacheWarning);}
    };
    try {guard.set(Guard.start(opts));}
    catch(Client.AuthGoException e){System.err.println("授权验证失败: "+e);exitCode.set(Guard.EXIT_LICENSE);System.exit(Guard.EXIT_LICENSE);return;}
    var g=guard.get();
    if(g.result().isTrial)System.out.println("当前为试用");
    if(!g.result().cacheWarning.isEmpty())System.out.println("缓存提示: "+g.result().cacheWarning);
    String addr="0.0.0.0:8080";
    for(int i=0;i+1<args.length;i++)if(args[i].equals("-listen"))addr=args[i+1];
    String[] parts=addr.split(":");
    var server=HttpServer.create(new InetSocketAddress(parts[0],Integer.parseInt(parts[1])),0);
    server.setExecutor(Executors.newCachedThreadPool(r->{var t=new Thread(r,"business-http");t.setDaemon(true);return t;}));
    server.createContext("/",exchange->{
      byte[] body=Client.canonical(java.util.Map.of("features",g.result().data.get("features"))).getBytes(java.nio.charset.StandardCharsets.UTF_8);int status=200;
      exchange.getResponseHeaders().set("Content-Type","application/json");
      try{g.require();}catch(Client.AuthGoException e){status=503;body=e.code.getBytes(java.nio.charset.StandardCharsets.UTF_8);}
      exchange.sendResponseHeaders(status,body.length);try(var out=exchange.getResponseBody()){out.write(body);}
    });
    server.start();System.out.println("HTTP已启动 version="+opts.version);
    g.done().thenRun(stopping::countDown);stopping.await();server.stop(0);
    int code=g.error()==null?0:Guard.EXIT_LICENSE;
    if(g.error()!=null)System.err.println("授权已失效: "+g.error());
    try{g.close();}catch(Exception e){System.err.println("释放席位: "+e);}
    exitCode.set(code);System.exit(code);
  }
}
