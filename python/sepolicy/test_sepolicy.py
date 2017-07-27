import unittest
import os
import shutil
from tempfile import mkdtemp
from subprocess import Popen, PIPE


class SepolicyTests(unittest.TestCase):

    def assertDenied(self, err):
        self.assert_('Permission denied' in err,
                     '"Permission denied" not found in %r' % err)

    def assertNotFound(self, err):
        self.assert_('not found' in err,
                     '"not found" not found in %r' % err)

    def assertFailure(self, status):
        self.assertNotEqual(status, 0,
                     'Succeeded when it should have failed')

    def assertSuccess(self, status, err):
        self.assertEqual(status, 0,
                     'sepolicy should have succeeded for this test %r' % err)

    def test_man_domain(self):
        "Verify sepolicy manpage -d works"
        p = Popen(['sepolicy', 'manpage', '-d', 'httpd_t'], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_man_all(self):
        "Verify sepolicy manpage -a works"
        p = Popen(['sepolicy', 'manpage', '-a'], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_network_l(self):
        "Verify sepolicy network -l works"
        p = Popen(['sepolicy', 'network', '-l'], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_network_t(self):
        "Verify sepolicy network -t works"
        p = Popen(['sepolicy', 'network', '-t', 'http_port_t'], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_network_p(self):
        "Verify sepolicy network -p works"
        p = Popen(['sepolicy', 'network', '-p', '80'], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_network_d(self):
        "Verify sepolicy network -d works"
        p = Popen(['sepolicy', 'network', '-d', 'httpd_t'], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_transition_s(self):
        "Verify sepolicy transition -s works"
        p = Popen(['sepolicy', 'transition', '-s', 'httpd_t'], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_transition_t(self):
        "Verify sepolicy transition -t works"
        p = Popen(['sepolicy', 'transition', '-s', 'httpd_t', '-t', 'sendmail_t'], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_booleans_a(self):
        "Verify sepolicy booleans -a works"
        p = Popen(['sepolicy', 'booleans', '-a'], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_booleans_b_alias(self):
        "Verify sepolicy booleans -b works"
        p = Popen(['sepolicy', 'booleans', '-b', 'allow_ypbind'], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_booleans_b(self):
        "Verify sepolicy booleans -b works"
        p = Popen(['sepolicy', 'booleans', '-b', 'nis_enabled'], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_interface_l(self):
        "Verify sepolicy interface -l works"
        p = Popen(['sepolicy', 'interface', '-l'], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_interface_a(self):
        "Verify sepolicy interface -a works"
        p = Popen(['sepolicy', 'interface', '-a'], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_interface_p(self):
        "Verify sepolicy interface -u works"
        p = Popen(['sepolicy', 'interface', '-u'], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_interface_ci(self):
        "Verify sepolicy interface -c -i works"
        p = Popen(['sepolicy', 'interface', '-c', '-i', 'apache_admin'], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

if __name__ == "__main__":
    import selinux
    if selinux.is_selinux_enabled() and selinux.security_getenforce() == 1:
        unittest.main()
    else:
        print("SELinux must be in enforcing mode for this test")
