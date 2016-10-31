import unittest
import os
import shutil
from tempfile import mkdtemp
from subprocess import Popen, PIPE


class Audit2allowTests(unittest.TestCase):

    def assertDenied(self, err):
        self.assertTrue('Permission denied' in err,
                        '"Permission denied" not found in %r' % err)

    def assertNotFound(self, err):
        self.assertTrue('not found' in err,
                        '"not found" not found in %r' % err)

    def assertFailure(self, status):
        self.assertTrue(status != 0,
                        '"Succeeded when it should have failed')

    def assertSuccess(self, cmd, status, err):
        self.assertTrue(status == 0,
                        '"%s should have succeeded for this test %r' % (cmd, err))

    def test_sepolgen_ifgen(self):
        "Verify sepolgen-ifgen works"
        p = Popen(['sudo', 'sepolgen-ifgen'], stdout=PIPE)
        out, err = p.communicate()
        if err:
            print(out, err)
        self.assertSuccess("sepolgen-ifgen", p.returncode, err)

    def test_audit2allow(self):
        "Verify audit2allow works"
        p = Popen(['python', './audit2allow', "-i", "test.log"], stdout=PIPE)
        out, err = p.communicate()
        if err:
            print(out, err)
        self.assertSuccess("audit2allow", p.returncode, err)

    def test_audit2why(self):
        "Verify audit2why works"
        p = Popen(['python', './audit2why', "-i", "test.log"], stdout=PIPE)
        out, err = p.communicate()
        if err:
            print(out, err)
        self.assertSuccess("audit2why", p.returncode, err)

if __name__ == "__main__":
    unittest.main()
