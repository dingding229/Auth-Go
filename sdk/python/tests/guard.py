"""Lifecycle tests use an in-process fake; protocol/container tests use real HTTP."""
import pathlib
import sys
import threading
import time
import unittest
from unittest.mock import patch
sys.path.insert(0, str(pathlib.Path(__file__).parents[1]))
import authgo as a

class Fake:
    def __init__(self):
        self.cache_warning = None
        self.state = {"heartbeat_interval": 1}
        self.next_check = 1
        self.heartbeats = 0
        self.code = None
        self.status = "online"
        self.calls = self.releases = 0
        self.block = None
        self.release_error = None
        self.validate_block = None
        self.validating = threading.Event()
    def now(self): return time.time()
    def check(self, key):
        self.key = key
        if self.code: raise a.Error(self.code)
        return self.value()
    def value(self):
        return a.Result(self, {"features": {"export": True, "nested": {"x": 1}},
            "next_check_in": self.next_check, "floating": True},
            "signed-proof", b"a" * 32, self.status, time.time() + 30)
    def verify(self):
        self.calls += 1
        if self.block: self.block.wait()
        if self.code: raise a.Error(self.code)
        return self.value()
    def heartbeat(self):
        self.heartbeats += 1
        return self.verify()
    def validate(self, ticket):
        self.validating.set()
        if self.validate_block: self.validate_block.wait()
        assert ticket == "signed-proof"
        if self.code: raise a.Error(self.code)
    def release_seat(self):
        self.releases += 1
        if self.release_error: raise a.Error(self.release_error)

class Guards(unittest.TestCase):
    def start(self, fake, **kw):
        with patch("authgo.guard.Client", return_value=fake):
            return a.start_guard(config="built-in", license="license", **kw)
    def test_required_config_and_first_failure(self):
        with patch("authgo.guard.Client") as client:
            with self.assertRaises(a.Error) as e: a.start_guard(config="")
            self.assertEqual(e.exception.code, "SDK_INVALID_CONFIG")
            client.assert_not_called()
        fake = Fake(); fake.code = "LICENSE_REVOKED"
        with self.assertRaises(a.Error): self.start(fake)
        self.assertEqual(fake.calls, 0)
    def test_concurrent_snapshots_require_and_idempotent_close(self):
        f = Fake(); g = self.start(f)
        self.assertTrue(g._thread.daemon)
        def read():
            for _ in range(100):
                r = g.result; r.features["nested"]["x"] = 99
                g.require("export")
                self.assertIsNone(g.error)
        errors = []
        def capture():
            try: read()
            except BaseException as e: errors.append(e)
        threads = [threading.Thread(target=capture) for _ in range(12)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertFalse(errors)
        self.assertEqual(g.result.features["nested"]["x"], 1)
        before = f.calls; g.require("export"); self.assertEqual(f.calls, before)
        with self.assertRaises(a.Error): g.require("missing")
        g.close(); g.close()
        self.assertEqual(f.releases, 1)
        with self.assertRaises(a.Error): g.require()
        before = f.calls; time.sleep(1.1); self.assertEqual(f.calls, before)
    def test_grace_and_final_error(self):
        for status in ("grace",):
            with self.subTest(status=status):
                f = Fake(); f.status = status
                observed = threading.Event()
                g = self.start(f, on_change=lambda r, e: observed.set())
                self.assertTrue(observed.wait(2))
                self.assertFalse(g.done.is_set())
                self.assertEqual(g.result.status, status)
                f.code = "SDK_GRACE_EXPIRED" if status == "grace" else "LICENSE_REVOKED"
                self.assertTrue(g.done.wait(2))
                self.assertEqual(g.error.code, f.code)
                with self.assertRaises(a.Error): g.require()
                g.close()
    def test_close_is_bounded_when_request_does_not_cooperate(self):
        f = Fake(); f.block = threading.Event(); g = self.start(f)
        deadline = time.monotonic() + 1
        while not f.calls and time.monotonic() < deadline: time.sleep(.01)
        start = time.monotonic()
        try:
            with self.assertRaises(a.Error): g.close()
            self.assertLess(time.monotonic() - start, 5.3)
        finally: f.block.set()
        self.assertEqual(f.releases, 0)
    def test_heartbeat_uses_response_metadata_not_grant_fields(self):
        f = Fake(); f.next_check = 10; g = self.start(f)
        try:
            self.assertNotIn("heartbeat_interval", g.result.data)
            self.assertEqual(g.result.heartbeat_interval, 1)
            deadline = time.monotonic() + 2
            while not f.heartbeats and time.monotonic() < deadline: time.sleep(.01)
            self.assertGreaterEqual(f.heartbeats, 1)
            self.assertLessEqual(f.calls, 3)
        finally: g.close()

    def test_close_does_not_wait_for_require(self):
        f = Fake(); g = self.start(f); f.validate_block = threading.Event()
        observed = []
        def require():
            try: g.require()
            except a.Error as e: observed.append(e.code)
        reader = threading.Thread(target=require); reader.start()
        self.assertTrue(f.validating.wait(1))
        failsafe = threading.Timer(2, f.validate_block.set)
        failsafe.daemon = True; failsafe.start()
        start = time.monotonic()
        try:
            g.close()
            self.assertLess(time.monotonic() - start, 1)
        finally:
            failsafe.cancel(); f.validate_block.set(); reader.join(1)
        self.assertEqual(observed, ["SDK_NOT_ACTIVATED"])

    def test_release_error_is_returned_not_a_completion(self):
        f = Fake(); f.release_error = "SDK_NETWORK_ERROR"; g = self.start(f)
        with self.assertRaises(a.Error) as e: g.close()
        self.assertEqual(e.exception.code, "SDK_NETWORK_ERROR")
        self.assertFalse(g.done.is_set())
        self.assertIsNone(g.error)

    def test_license_environment_only_and_with(self):
        f = Fake()
        with patch.dict("os.environ", {"AUTHGO_LICENSE": "customer", "AUTHGO_CONFIG": "attacker"}):
            with patch("authgo.guard.Client", return_value=f) as ctor:
                with a.start_guard(config="compiled", version="1.2.3") as g:
                    g.require()
                self.assertEqual(f.key, "customer")
                self.assertEqual(ctor.call_args.args[0], "compiled")
                self.assertEqual(ctor.call_args.kwargs["version"], "1.2.3")
        self.assertEqual(a.EXIT_LICENSE, 77)

if __name__ == "__main__": unittest.main()
