import ctypes
import os
import subprocess
import sys


def analyze(api, permission="read"):
    return api.analyze("system_u:object_r:test_t:s0",
                       "system_u:object_r:test_t:s0", "file", [permission])


def child(policy, kind, nth):
    import audit2why as api
    fault = ctypes.CDLL(api.__file__)
    fault.audit_fault.argtypes = [ctypes.c_int, ctypes.c_int]
    api.finish()
    if kind:
        fault.audit_fault(kind, nth)
        try:
            api.init(policy)
        except (RuntimeError, MemoryError) as exc:
            assert not isinstance(exc, SystemError), str(exc)
        else:
            raise AssertionError("init accepted an injected failure")
        assert fault.audit_fault_hits() == 1
        assert fault.audit_live() == 0
        assert analyze(api) == (api.NOPOLICY, None)
        api.finish()
        api.finish()
    fault.audit_fault(0, 0)
    for _ in range(3):
        assert api.init(policy) == 0
        assert analyze(api) == (api.ALLOW, None)
        try:
            api.init(policy)
        except RuntimeError:
            pass
        else:
            raise AssertionError("double init accepted")
        api.finish()
        assert fault.audit_live() == 0


if len(sys.argv) == 4:
    child(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]))
else:
    cases = [(0, 0), (6, 1), (7, 1)]
    cases += [(kind, nth) for kind in (1, 2, 4, 5) for nth in (1, 2)]
    for kind, nth in cases:
        subprocess.run([sys.executable, __file__, sys.argv[1], str(kind), str(nth)],
                       check=True, timeout=30, env=os.environ)
    print("audit2why initialization: 11 cases passed")
