# Test image ONLY. Advance the existing injected SDK clock after real outage.
import threading
import time
import authgo
from _authgo_build import CONFIG, VERSION
advance = threading.Event()
def clock(): return time.time() + (72 * 3600 + 1 if advance.is_set() else 0)
def changed(result, error):
    if result and result.status == "grace": advance.set()
    print("clock agent: " + (str(error) if error else result.status), flush=True)
try:
    guard = authgo.start_guard(config=CONFIG, version=VERSION, clock=clock, on_change=changed)
except authgo.Error as error:
    print("clock startup: " + str(error), flush=True)
    raise SystemExit(authgo.EXIT_LICENSE)
print("clock ready", flush=True)
guard.done.wait()
print("clock stopped: " + str(guard.error), flush=True)
try: guard.close()
except authgo.Error: pass
raise SystemExit(authgo.EXIT_LICENSE)
