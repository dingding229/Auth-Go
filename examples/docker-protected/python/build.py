"""Build stage only; source and build helper never enter the runtime image."""
import os
from pathlib import Path
import py_compile

source = Path("/src/example/main.py").read_text()
source = source.replace("CONFIG = None", "CONFIG = " + repr(os.environ["AUTHGO_CONFIG"]))
source = source.replace("VERSION = None", "VERSION = " + repr(os.environ["VERSION"]))
Path("/src/launcher.py").write_text(source)
py_compile.compile("/src/launcher.py", cfile="/main.pyc", doraise=True)
Path("/staging/core").mkdir(parents=True)
py_compile.compile("/src/example/core/__init__.py", cfile="/staging/core/__init__.pyc",
                   dfile="authgo-sealed://core/__init__.py", doraise=True)
