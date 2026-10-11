"""The root helper must refuse anything but one known subcommand name."""
import json
import subprocess
import sys
from pathlib import Path

HELPER = Path(__file__).resolve().parent.parent / "packaging" / "pacwardx-priv"


def run(*args):
    p = subprocess.run([sys.executable, "-I", str(HELPER), *args], capture_output=True, text=True)
    return p.returncode, json.loads(p.stdout)


def test_rejects_unknown_and_extra_arguments():
    for args in ([], ["rm"], ["sockets", "--extra"], ["../../bin/sh"], ["SOCKETS"]):
        code, out = run(*args)
        assert code == 2 and "usage" in out["error"]


def test_ping():
    assert run("ping") == (0, {"ok": True})
