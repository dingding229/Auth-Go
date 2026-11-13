package io.authgo;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;
import java.time.Instant;
public final class ClockAgent {
  public static void main(String[] args) throws Exception {
    var build=new Properties();try(var in=ClockAgent.class.getResourceAsStream("/authgo-build.properties")){build.load(in);}
    if(args.length==1&&args[0].equals("--reclaim-probe")){ReclaimProbe.run(build.getProperty("config"));return;}
    var advance=new AtomicBoolean();var opts=new GuardOptions();opts.config=build.getProperty("config");opts.version="1.0.0";
    opts.sdkOptions.clock=()->Instant.now().getEpochSecond()+(advance.get()?72*3600+1:0);
    opts.onChange=(r,e)->{if(r!=null){System.out.println("clock agent: "+r.status);if(r.status.equals("grace"))advance.set(true);}if(e!=null)System.out.println("clock agent: "+e);};
    try(var guard=Guard.start(opts)){System.out.println("clock ready");guard.done().join();System.out.println("clock stopped: "+guard.error());}
    catch(Client.AuthGoException e){System.out.println("clock error: "+e);}
    System.exit(Guard.EXIT_LICENSE);
  }
}
