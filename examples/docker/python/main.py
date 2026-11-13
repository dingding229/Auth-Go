"""Signals belong to this business program, not to the SDK."""
import signal
# Cover module loading as well as the later synchronous first check. This is
# business-program signal handling, never installed by the SDK.
def _boot_stop(*_): raise SystemExit(0)
signal.signal(signal.SIGTERM, _boot_stop)
signal.signal(signal.SIGINT, _boot_stop)
import argparse
import http.server
import queue
import threading
import authgo
from _authgo_build import CONFIG, VERSION


def change(result, error):
    print("授权检查: " + str(error) if error else "授权状态: " + result.status, flush=True)
    if result and result.cache_warning: print("缓存提示: " + str(result.cache_warning), flush=True)


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("-listen", default=":8080")
    args = parser.parse_args()
    stop = threading.Event()
    guard = None
    def request_stop(*_):
        stop.set()
        if guard is None:
            # Initial verification has not yielded an owned seat/token yet.
            raise SystemExit(0)
    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    ready = queue.Queue(maxsize=1)
    def initialize():
        try:
            ready.put((authgo.start_guard(config=CONFIG, version=VERSION, on_change=change), None))
        except Exception as error:
            ready.put((None, error if isinstance(error, authgo.Error) else authgo.Error("SDK_NETWORK_ERROR", "启动授权守卫失败")))
    # The main signal loop must stay responsive even during DNS/TLS startup.
    threading.Thread(target=initialize, daemon=True).start()
    while guard is None:
        try: guard, error = ready.get(timeout=.05)
        except queue.Empty: continue
        if error:
            print("授权验证失败: " + str(error), flush=True)
            return authgo.EXIT_LICENSE
    if guard.result.is_trial: print("当前为试用", flush=True)
    if guard.result.cache_warning: print("缓存提示: " + str(guard.result.cache_warning), flush=True)
    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(.5)
        def do_GET(self):
            try: guard.require("")
            except authgo.Error:
                self.send_error(403, "license unavailable")
                return
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(authgo.canonical({"features":guard.result.features}).encode())
        def log_message(self, *_): pass
    host, port = args.listen.rsplit(":", 1)
    class Server(http.server.ThreadingHTTPServer):
        daemon_threads = True
        block_on_close = False
    server = Server((host, int(port)), Handler)
    server.timeout = .2
    print("HTTP已启动 version=" + VERSION, flush=True)
    try:
        while not stop.is_set() and not guard.done.is_set(): server.handle_request()
        if guard.done.is_set():
            print("授权已失效: " + str(guard.error), flush=True)
            return authgo.EXIT_LICENSE
        return 0
    finally:
        server.server_close()
        try: guard.close()
        except authgo.Error as error: print("释放席位: " + str(error), flush=True)


if __name__ == "__main__": raise SystemExit(run())
