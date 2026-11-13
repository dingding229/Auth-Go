"""Public launcher; build.py freezes the trust root into main.pyc."""
import signal
import threading
import argparse
import http.server
import authgo

CONFIG = None
VERSION = None


def run():
    stop = threading.Event()
    def stopping(*_):
        stop.set()
    signal.signal(signal.SIGTERM, stopping)
    signal.signal(signal.SIGINT, stopping)
    parser = argparse.ArgumentParser()
    parser.add_argument("-listen", default=":8080")
    args = parser.parse_args()
    guard = None
    server = None
    try:
        guard = authgo.start_guard(config=CONFIG, version=VERSION)
        if stop.is_set():
            return 0
        guard.install_sealed("core")
        import core
        class Handler(http.server.BaseHTTPRequestHandler):
            def setup(self):
                super().setup()
                self.connection.settimeout(.5)
            def do_GET(self):
                try:
                    body = authgo.canonical(core.response(guard)).encode()
                except authgo.Error:
                    self.send_error(503, "license unavailable")
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *_):
                pass
        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True
            block_on_close = False
        host, port = args.listen.rsplit(":", 1)
        server = Server((host or "0.0.0.0", int(port)), Handler)
        server.timeout = .2
        print("HTTP已启动 version=" + VERSION, flush=True)
        while not stop.is_set() and not guard.done.is_set():
            server.handle_request()
        return 0 if stop.is_set() else authgo.EXIT_LICENSE
    except authgo.Error as error:
        print("授权验证失败: " + str(error), flush=True)
        return authgo.EXIT_LICENSE
    finally:
        if server is not None:
            server.server_close()
        if guard is not None:
            try:
                guard.close()
            except authgo.Error as error:
                print("释放席位: " + str(error), flush=True)


if __name__ == "__main__":
    raise SystemExit(run())
