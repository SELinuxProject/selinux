import ast
import errno
import os
from pathlib import Path
import sys
import tempfile
import unittest


if os.environ.get("SELINUX_TEST_BINDING"):
    import selinux
    policy_open = selinux.policy_open
else:
    # Exercise the exact helper without requiring a built Python extension.
    source = (Path(__file__).resolve().parents[1] / "src" /
              "selinuxswig_python.i").read_text()
    code = source.split("%pythoncode %{", 1)[1].split("%}", 1)[0]
    function = next(node for node in ast.parse(code).body
                    if isinstance(node, ast.FunctionDef) and
                    node.name == "policy_open")
    namespace = {"os": os, "selinux_policy_open": os.open}
    exec(compile(ast.Module(body=[function], type_ignores=[]),
                 "selinuxswig_python.i", "exec"), namespace)
    policy_open = namespace["policy_open"]


class PolicyOpenTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = os.path.join(self.directory.name, "config")
        with open(self.path, "w") as stream:
            stream.write("policy data\n")

    def test_reads(self):
        for mode, expected in [("r", "policy data\n"),
                               ("rb", b"policy data\n")]:
            with self.subTest(mode=mode):
                with policy_open(self.path, mode) as stream:
                    fd = stream.fileno()
                    self.assertFalse(os.get_inheritable(fd))
                    self.assertEqual(stream.read(), expected)
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_exceptions_and_cleanup(self):
        scenarios = [
            ("r", {"encoding": "not-a-real-codec"}),
            ("r", {"newline": "invalid"}),
            ("r", {"buffering": 0}),
            ("rb", {"encoding": "utf-8"}),
            ("bad", {}),
            ("r", {"closefd": False}),
        ]
        for mode, kwargs in scenarios:
            with self.subTest(mode=mode, kwargs=kwargs):
                before = len(os.listdir("/proc/self/fd"))
                try:
                    open(self.path, mode, **kwargs)
                except Exception as error:
                    expected = type(error)
                else:
                    self.fail("fixture did not fail")
                for _ in range(10):
                    with self.assertRaises(expected):
                        policy_open(self.path, mode, **kwargs)
                self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_open_failure(self):
        with self.assertRaises(FileNotFoundError):
            policy_open(self.path + ".missing")

    def test_late_failure_does_not_close_reused_fd(self):
        namespace = policy_open.__globals__
        original = namespace["selinux_policy_open"]
        opened = []
        replacement = []

        def track(name, flags):
            fd = original(name, flags)
            opened.append(fd)
            return fd

        def trace(frame, event, arg):
            if (frame.f_code is policy_open.__code__ and
                    event == "exception" and not replacement):
                self.assertEqual(len(opened), 1)
                with self.assertRaises(OSError) as result:
                    os.fstat(opened[0])
                self.assertEqual(result.exception.errno, errno.EBADF)
                fd = os.open(self.path, os.O_RDONLY)
                replacement.append(fd)
                self.assertEqual(fd, opened[0])
            return trace

        namespace["selinux_policy_open"] = track
        previous = sys.gettrace()
        try:
            sys.settrace(trace)
            # This check occurs after raw-stream creation in CPython.
            with self.assertRaises(ValueError):
                policy_open(self.path, buffering=0)
            sys.settrace(previous)
            self.assertEqual(len(replacement), 1)
            self.assertEqual(os.read(replacement[0], 32), b"policy data\n")
        finally:
            sys.settrace(previous)
            namespace["selinux_policy_open"] = original
            for fd in replacement:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def test_readonly_underlying_descriptor(self):
        with policy_open(self.path, "wb", buffering=0) as stream:
            with self.assertRaises(OSError) as error:
                stream.write(b"changed")
            self.assertEqual(error.exception.errno, errno.EBADF)
        with open(self.path) as stream:
            self.assertEqual(stream.read(), "policy data\n")


if __name__ == "__main__":
    unittest.main()
