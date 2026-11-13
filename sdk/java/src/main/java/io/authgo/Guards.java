package io.authgo;

import java.util.concurrent.atomic.AtomicReference;

/** Process-wide guard for business code loaded by Bootstrap, including workers. */
public final class Guards {
  private static final AtomicReference<Guard> CURRENT = new AtomicReference<>();

  private Guards() {}

  public static Guard current() {
    Guard guard = CURRENT.get();
    if (guard == null) throw new Client.AuthGoException("SDK_NOT_ACTIVATED");
    guard.require();
    return guard;
  }

  static void bind(Guard guard) {
    guard.require();
    if (!CURRENT.compareAndSet(null, guard)) throw new IllegalStateException("已有加密程序正在运行");
  }

  static void clear(Guard expected) {
    CURRENT.compareAndSet(expected, null);
  }
}
