import io.authgo.Client;

public class Example {

  private static final String AUTH_CONFIG = "authgo2.请在构建时替换为后台接入配置";

  public static void main(String[] args) {
    var client = new Client(AUTH_CONFIG);
    var result = client.check(System.getenv("AUTHGO_LICENSE"));
    System.out.println(result.status);
  }
}
