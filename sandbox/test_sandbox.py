import unittest
import os
import shutil
import sys
from tempfile import mkdtemp
from subprocess import Popen, PIPE


class SandboxTests(unittest.TestCase):

    def assertDenied(self, err):
        self.assertTrue(b'Permission denied' in err,
                        '"Permission denied" not found in %r' % err)

    def assertNotFound(self, err):
        self.assertTrue(b'not found' in err,
                        '"not found" not found in %r' % err)

    def assertFailure(self, status):
        self.assertTrue(status != 0,
                        '"Succeeded when it should have failed')

    def assertSuccess(self, status, err):
        self.assertTrue(status == 0,
                        '"Sandbox should have succeeded for this test %r' % err)

    def test_simple_success(self):
        "Verify that we can read file descriptors handed to sandbox"
        p1 = Popen(['cat', '/etc/passwd'], stdout=PIPE)
        p2 = Popen([sys.executable, 'sandbox', 'grep', 'root'], stdin=p1.stdout, stdout=PIPE)
        p1.stdout.close()
        out, err = p2.communicate()
        self.assertTrue(b'root' in out)

    def test_cant_kill(self):
        "Verify that we cannot send kill signal in the sandbox"
        pid = os.getpid()
        p = Popen([sys.executable, 'sandbox', 'kill', '-HUP', str(pid)], stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        self.assertDenied(err)

    def test_cant_ping(self):
        "Verify that we can't ping within the sandbox"
        p = Popen([sys.executable, 'sandbox', 'ping', '-c 1 ', '127.0.0.1'], stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        self.assertDenied(err)

    def test_cant_mkdir(self):
        "Verify that we can't mkdir within the sandbox"
        p = Popen([sys.executable, 'sandbox', 'mkdir', '~/test'], stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        self.assertFailure(p.returncode)

    def test_cant_list_homedir(self):
        "Verify that we can't list homedir within the sandbox"
        p = Popen([sys.executable, 'sandbox', 'ls', '~'], stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        self.assertFailure(p.returncode)

    def test_cant_send_mail(self):
        "Verify that we can't send mail within the sandbox"
        p = Popen([sys.executable, 'sandbox', 'mail'], stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        self.assertDenied(err)

    def test_cant_sudo(self):
        "Verify that we can't run sudo within the sandbox"
        p = Popen([sys.executable, 'sandbox', 'sudo'], stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        self.assertFailure(p.returncode)

    def test_mount(self):
        "Verify that we mount a file system"
        p = Popen([sys.executable, 'sandbox', '-M', 'id'], stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_set_level(self):
        "Verify that we set level a file system"
        p = Popen([sys.executable, 'sandbox', '-l', 's0', 'id'], stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_homedir(self):
        "Verify that we set homedir a file system"
        homedir = mkdtemp(dir=".", prefix=".sandbox_test")
        p = Popen([sys.executable, 'sandbox', '-H', homedir, '-M', 'id'], stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        shutil.rmtree(homedir)
        self.assertSuccess(p.returncode, err)

    def test_tmpdir(self):
        "Verify that we set tmpdir a file system"
        tmpdir = mkdtemp(dir="/tmp", prefix=".sandbox_test")
        p = Popen([sys.executable, 'sandbox', '-T', tmpdir, '-M', 'id'], stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        shutil.rmtree(tmpdir)
        self.assertSuccess(p.returncode, err)

    def test_include_file(self):
        "Verify that sandbox can copy a file in the sandbox home and use it"
        p = Popen([sys.executable, 'sandbox', '-i' ,'test_sandbox.py' , '-M', '/bin/cat', 'test_sandbox.py'],
                  stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)


if __name__ == "__main__":
    import selinux
    if selinux.is_selinux_enabled() and selinux.security_getenforce() == 1:
        unittest.main()
    else:
        print("SELinux must be in enforcing mode for this test")
