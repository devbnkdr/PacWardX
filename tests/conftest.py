"""Keep every test away from the real ~/.config and ~/.local/share."""
import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="pacwardx-tests-")
os.environ["XDG_DATA_HOME"] = os.path.join(_tmp, "data")
os.environ["XDG_CONFIG_HOME"] = os.path.join(_tmp, "config")
os.environ["XDG_RUNTIME_DIR"] = os.path.join(_tmp, "run")
