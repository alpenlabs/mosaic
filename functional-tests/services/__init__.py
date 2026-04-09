import os
import subprocess
import sys

import flexitest


class ProcServiceWithEnv(flexitest.service.ProcService):
    """ProcService subclass that supports passing environment variables."""

    def __init__(self, props: dict, cmd: list[str], stdout=None, env=None):
        super().__init__(props, cmd, stdout)
        self.env = env

    def start(self):
        if self.is_started():
            raise RuntimeError("already running")

        self._reset_state()

        kwargs = {}
        if self.env is not None:
            kwargs["env"] = self.env

        if self.stdout is not None:
            if type(self.stdout) is str:
                # file handle must stay open for subprocess lifetime (no context manager)
                f = open(self.stdout, "a")  # noqa: SIM115
                f.write(f"(process started as: {self.cmd})\n")
                kwargs["stdout"] = f
                kwargs["stderr"] = f
            else:
                kwargs["stdout"] = self.stdout

        p = subprocess.Popen(self.cmd, **kwargs)
        flexitest.service._register_kill(p)
        self.proc = p
        self._update_status_msg()


def get_fdb_env():
    """Build environment dict with FDB library path for subprocesses."""
    env = os.environ.copy()
    fdb_lib_path = os.environ.get("FDB_LIBRARY_PATH", "/usr/local/lib")
    if sys.platform == "darwin":
        # macOS uses DYLD_LIBRARY_PATH
        existing = env.get("DYLD_LIBRARY_PATH", "")
        env["DYLD_LIBRARY_PATH"] = f"{fdb_lib_path}:{existing}" if existing else fdb_lib_path
    else:
        # Linux uses LD_LIBRARY_PATH
        existing = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{fdb_lib_path}:{existing}" if existing else fdb_lib_path
    return env
