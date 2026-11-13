import { Client, AuthGoError } from "./index.js";

export const EXIT_LICENSE = 77;
const failure = code => new AuthGoError(code);
const date = value => value == null ? Infinity : Date.parse(value) / 1000;

class Guard {
  #client; #result; #error; #closed = false; #timer; #resolve;
  #flight = Promise.resolve(); #close; #onChange; #verifyAt; #heartbeatAt;
  #sealedCleanup;
  constructor(client, result, onChange) {
    this.#client = client; this.#result = result._guardSnapshot(); this.#onChange = onChange;
    this.done = new Promise(resolve => { this.#resolve = resolve; });
    this.#timer = setTimeout(() => this.#tick(true), 0);
    this.#timer.unref();
  }
  result() { return this.#result._guardSnapshot(); }
  get error() { return this.#error; }
  require(feature = "") {
    if (this.#error) { this.#sealedCleanup?.(); throw this.#error; }
    if (this.#closed) { this.#sealedCleanup?.(); throw failure("SDK_NOT_ACTIVATED"); }
    try { this.#client.validate(this.#result.ticket()); }
    catch (error) { this.#sealedCleanup?.(); throw error; }
    if (feature && this.#result.features[feature] !== true) throw failure("INVALID_POLICY");
  }
  async requireSealed(name) {
    this.require();
    const { requireSealed, clearSealed } = await import("./sealed.js");
    this.#sealedCleanup = () => clearSealed(this);
    return requireSealed(this, this.#client, name);
  }
  #notify(result, error) {
    if (this.#closed) return;
    if (result) this.#result = result._guardSnapshot();
    if (error) { this.#error = error; this.#sealedCleanup?.(); this.#resolve(); }
    this.#onChange?.(result?._guardSnapshot() ?? null, error ?? null);
  }
  #tick(first = false) {
    if (this.#closed || this.#error) return;
    this.#flight = this.#step(first);
  }
  async #step(first) {
    try {
      const c = this.#client;
      let r = this.#result;
      if (first || c.now() >= this.#verifyAt || (!r.data.floating || c.now() < this.#heartbeatAt)) {
        r = await c.verify();
        this.#notify(r);
        this.#verifyAt = c.now() + Number(r.data.next_check_in);
      }
      if (first) this.#heartbeatAt = c.now() + r.heartbeatInterval;
      if (!this.#closed && r.data.floating && c.now() >= this.#heartbeatAt) {
        r = await c.heartbeat(); this.#notify(r);
        this.#heartbeatAt = c.now() + r.heartbeatInterval;
      }
      if (this.#closed) return;
      const deadline = Math.min(this.#verifyAt, r.data.floating ? this.#heartbeatAt : Infinity,
        date(r.data.expires_at), r.status === "grace" ? r._guardDeadline() : date(r.data.lease_expires_at));
      this.#timer = setTimeout(() => this.#tick(), Math.max(0, (deadline - c.now()) * 1000));
      this.#timer.unref();
    } catch (error) { this.#notify(null, error); }
  }
  close() {
    if (!this.#close) {
      this.#closed = true; clearTimeout(this.#timer);
      this.#sealedCleanup?.();
      let timer, expired = false;
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => { expired = true; reject(failure("SDK_NETWORK_ERROR")); }, 5000);
      });
      const release = this.#flight.then(() => {
        if (expired) throw failure("SDK_NETWORK_ERROR");
        return this.#client.releaseSeat();
      });
      this.#close = Promise.race([release, timeout]).finally(() => clearTimeout(timer));
    }
    return this.#close;
  }
}

export async function startGuard({ config, version = "", license = process.env.AUTHGO_LICENSE ?? "", onChange, ...sdkOptions } = {}) {
  if (!config) throw new AuthGoError("SDK_INVALID_CONFIG", "接入配置必须编译进程序");
  const client = new Client(config, { ...sdkOptions, version });
  const key = license || process.env.AUTHGO_LICENSE || "";
  const result = key ? await client.check(key) : await client._guardCheck("");
  return new Guard(client, result, onChange);
}
