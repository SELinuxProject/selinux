#!/usr/bin/python3
#
# Exercise seobject.permissiveRecords against a private, throw-away policy
# store so that the Python calls into the libsemanage bindings are checked
# against their actual signatures. This needs neither root nor an SELinux
# enabled system, only the semanage bindings and seobject importable.

import os
import shutil
import tempfile
import unittest

import semanage
import seobject

BASE_CIL = b"""
(typeattribute cil_gen_require)
(roleattribute cil_gen_require)
(handleunknown allow)
(mls true)
(sid security)
(sidorder (security))
(sensitivity s0)
(sensitivityorder (s0))
(user system_u)
(userrole system_u object_r)
(userlevel system_u (s0))
(userrange system_u ((s0) (s0)))
(role object_r)
(roletype object_r test_t)
(type test_t)
(sidcontext security (system_u object_r test_t ((s0) (s0))))
(class test_class (test_perm))
(classorder (test_class))
(allow test_t self (test_class (test_perm)))
"""

STORE = "store"


class PermissiveStoreTests(unittest.TestCase):

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="semanage-permissive-test-")
        os.makedirs(os.path.join(self.root, "etc", "selinux"))
        with open(os.path.join(self.root, "etc", "selinux", "semanage.conf"), "w") as f:
            f.write("disable-genhomedircon = true\n")
        base = os.path.join(self.root, STORE, "active", "modules", "100", "base")
        os.makedirs(base)
        with open(os.path.join(base, "cil"), "wb") as f:
            f.write(BASE_CIL)
        with open(os.path.join(base, "lang_ext"), "w") as f:
            f.write("cil")

        semanage.semanage_set_root(self.root)
        self.sh = semanage.semanage_handle_create()
        self.assertIsNotNone(self.sh)
        semanage.semanage_set_create_store(self.sh, 1)
        semanage.semanage_set_reload(self.sh, 0)
        semanage.semanage_set_store_root(self.sh, "")
        semanage.semanage_select_store(self.sh, STORE, semanage.SEMANAGE_CON_DIRECT)
        self.assertGreaterEqual(semanage.semanage_connect(self.sh), 0)

        # Bypass semanageRecords.__init__(), which consults the policy
        # configuration of the running system.
        self.records = object.__new__(seobject.permissiveRecords)
        self.records.sh = self.sh
        self.records.noreload = True
        self.records.mylog = seobject.nulllogger()

    def tearDown(self):
        semanage.semanage_disconnect(self.sh)
        semanage.semanage_handle_destroy(self.sh)
        semanage.semanage_set_root("/")
        shutil.rmtree(self.root)

    def test_add_delete(self):
        self.assertEqual(self.records.get_all(), [])

        self.records.begin()
        self.records.add("test_t")
        self.assertEqual(self.records.get_all(), ["test_t"])

        self.records.begin()
        self.records.delete("test_t")
        self.assertEqual(self.records.get_all(), [])


if __name__ == "__main__":
    unittest.main()
