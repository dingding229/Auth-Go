import io.authgo.Bootstrap;
import io.authgo.GuardOptions;

/** Compile this public entry with the SDK; keep the business JAR encrypted. */
public final class ProtectedExample {
  private static final String CONFIG = "authgo2.请在构建时替换为后台接入配置";

  private ProtectedExample() {}

  public static void main(String[] args) throws Exception {
    GuardOptions options = new GuardOptions();
    options.config = CONFIG;
    Bootstrap.run(options, "app", args);
  }
}
