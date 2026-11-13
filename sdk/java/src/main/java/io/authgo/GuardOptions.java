package io.authgo;

import java.util.function.BiConsumer;

/** Configuration is a mandatory build-time trust root, never an environment fallback. */
public final class GuardOptions {
  public String config = "", license = "", version = "";
  public Client.Options sdkOptions = new Client.Options();
  public BiConsumer<Client.Result, Client.AuthGoException> onChange;
}
