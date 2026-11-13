"""In-process guard. Signals and process exit belong to the application."""
import copy
import os
import threading
import time

from . import Client, Error, stamp

EXIT_LICENSE = 77


def _snapshot(result):
    value = copy.copy(result)
    value.data = copy.deepcopy(result.data)
    value.features = value.data.get("features", {})
    return value


class Guard:
    def __init__(self, client, result, on_change=None):
        self._client = client
        self._result = _snapshot(result)
        self._on_change = on_change
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._stopped = threading.Event()
        self._closed = threading.Event()
        self._closing = False
        self._close_error = None
        self._error = None
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    @property
    def result(self):
        with self._lock:
            return _snapshot(self._result)

    @property
    def done(self):
        return self._done

    @property
    def error(self):
        with self._lock:
            return self._error

    def require(self, feature=""):
        def active():
            if self._error:
                self._clear_sealed()
                raise self._error
            if self._stop.is_set() or self._done.is_set():
                self._clear_sealed()
                raise Error("SDK_NOT_ACTIVATED", "授权守卫已关闭")
        with self._lock:
            active()
            result = _snapshot(self._result)
        # Never hold the guard lock while waiting for the Client's state lock:
        # an in-flight network check must not delay close beyond five seconds.
        try:
            self._client.validate(result.ticket())
        except Error:
            self._clear_sealed()
            raise
        with self._lock:
            active()
            if feature and result.features.get(feature) is not True:
                raise Error("INVALID_POLICY")

    def _clear_sealed(self):
        # Leave closed finders installed so plaintext packages cannot become a
        # fallback. Their code references, including root co_consts, are gone.
        with self._lock:
            for finder in getattr(self, "_sealed_loaders", ()):
                finder.modules.clear()
            self._sealed_loaders = []

    def install_sealed(self, name):
        """Install a Python package from authenticated ciphertext, in memory."""
        from .sealed import install_sealed

        return install_sealed(self, name)

    def _notify(self, result=None, error=None):
        with self._lock:
            if self._stop.is_set():
                return
            if result is not None:
                self._result = _snapshot(result)
            if error is not None:
                self._error = error
                self._done.set()
                self._clear_sealed()
        if self._on_change:
            self._on_change(_snapshot(result) if result is not None else None, error)

    def _run(self):
        try:
            if self._stop.is_set():
                return
            result = self._client.verify()
            self._notify(result)
            verify_at = self._client.now() + int(result.data["next_check_in"])
            heartbeat_at = self._client.now() + result.heartbeat_interval
            while not self._stop.is_set():
                floating = bool(result.data.get("floating"))
                next_at = min(verify_at, heartbeat_at if floating else float("inf"),
                              stamp(result.data.get("expires_at")),
                              result._end if result.status == "grace" else stamp(result.data.get("lease_expires_at")))
                if self._stop.wait(max(0, next_at - self._client.now())):
                    return
                now = self._client.now()
                if now >= verify_at or (now >= next_at and (not floating or now < heartbeat_at)):
                    result = self._client.verify()
                    self._notify(result)
                    verify_at = self._client.now() + int(result.data["next_check_in"])
                if result.data.get("floating") and self._client.now() >= heartbeat_at and not self._stop.is_set():
                    result = self._client.heartbeat()
                    self._notify(result)
                    heartbeat_at = self._client.now() + result.heartbeat_interval
        except Error as error:
            self._notify(error=error)
        finally:
            self._stopped.set()

    def close(self):
        # One shared close operation, including loop shutdown and seat release.
        with self._lock:
            if not self._closing:
                self._closing = True
                self._stop.set()
                self._clear_sealed()
                deadline = time.monotonic() + 5
                def release():
                    try:
                        if not self._stopped.wait(max(0, deadline - time.monotonic())):
                            raise Error("SDK_NETWORK_ERROR", "关闭授权守卫超时")
                        if time.monotonic() >= deadline:
                            raise Error("SDK_NETWORK_ERROR", "关闭授权守卫超时")
                        self._client.release_seat()
                    except Error as error:
                        with self._lock:
                            if not self._closed.is_set():
                                self._close_error = error
                    finally:
                        self._closed.set()
                threading.Thread(target=release, daemon=True).start()
        if not self._closed.wait(5):
            with self._lock:
                if not self._closed.is_set():
                    self._close_error = Error("SDK_NETWORK_ERROR", "关闭授权守卫超时")
                    self._closed.set()
        if self._close_error:
            raise self._close_error

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def start_guard(*, config, version="", license=None, on_change=None, **sdk_options):
    if not config:
        raise Error("SDK_INVALID_CONFIG", "接入配置必须编译进程序")
    client = Client(config, version=version, **sdk_options)
    key = license or os.environ.get("AUTHGO_LICENSE", "")
    result = client.check(key) if key else client._guard_check("")
    return Guard(client, result, on_change)
