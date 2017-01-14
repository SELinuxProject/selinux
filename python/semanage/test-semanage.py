import unittest
import sys
from subprocess import Popen, PIPE

import argparse

object_list = ['login', 'user', 'port', 'module', 'interface', 'node', 'fcontext', 'boolean', 'permissive', "dontaudit"]


class SemanageTests(unittest.TestCase):

    def assertDenied(self, err):
        self.assertTrue('Permission denied' in err,
                        '"Permission denied" not found in %r' % err)

    def assertNotFound(self, err):
        self.assertTrue('not found' in err,
                        '"not found" not found in %r' % err)

    def assertFailure(self, status):
        self.assertTrue(status != 0,
                        '"semanage succeeded when it should have failed')

    def assertSuccess(self, status, err):
        self.assertTrue(status == 0,
                        '"semanage should have succeeded for this test %r' % err)

    def test_extract(self):
        for object in object_list:
            if object in ["dontaudit", "module", "permissive"]:
                continue
            "Verify semanage %s -E" % object
            p = Popen(['semanage', object, '-E'], stdout=PIPE)
            out, err = p.communicate()
            self.assertSuccess(p.returncode, err)

    def test_input_output(self):
        print("Verify semanage export -f /tmp/out")
        p = Popen(['semanage', "export", '-f', '/tmp/out'], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage export -S targeted -f -")
        p = Popen(["semanage", "export", "-S", "targeted", "-f", "-"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage -S targeted -o -")
        p = Popen(["semanage", "-S", "targeted", "-o", "-"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage import -f /tmp/out")
        p = Popen(['semanage', "import", '-f', '/tmp/out'], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage import -S targeted -f /tmp/out")
        p = Popen(["semanage", "import", "-S", "targeted", "-f", "/tmp/out"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage -S targeted -i /tmp/out")
        p = Popen(["semanage", "-S", "targeted", "-i", "/tmp/out"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_list(self):
        for object in object_list:
            if object in ["dontaudit"]:
                continue
            "Verify semanage %s -l" % object
            p = Popen(['semanage', object, '-l'], stdout=PIPE)
            out, err = p.communicate()
            self.assertSuccess(p.returncode, err)

    def test_list_c(self):
        for object in object_list:
            if object in ["module", "permissive", "dontaudit"]:
                continue
            print("Verify semanage %s -l" % object)
            p = Popen(['semanage', object, '-lC'], stdout=PIPE)
            out, err = p.communicate()
            self.assertSuccess(p.returncode, err)

    def test_fcontext(self):
        p = Popen(["semanage", "fcontext", "-d", "/ha-web(/.*)?"], stderr=PIPE)
        out, err = p.communicate()

        print("Verify semanage fcontext -a")
        p = Popen(["semanage", "fcontext", "-a", "-t", "httpd_sys_content_t", "/ha-web(/.*)?"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage fcontext -m")
        p = Popen(["semanage", "fcontext", "-m", "-t", "default_t", "/ha-web(/.*)?"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage fcontext -d")
        p = Popen(["semanage", "fcontext", "-d", "/ha-web(/.*)?"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_fcontext_e(self):
        p = Popen(["semanage", "fcontext", "-d", "/myhome"], stderr=PIPE)
        out, err = p.communicate()
        p = Popen(["semanage", "fcontext", "-d", "/myhome1"], stderr=PIPE)
        out, err = p.communicate()

        print("Verify semanage fcontext -a -e")
        p = Popen(["semanage", "fcontext", "-a", "-e", "/home", "/myhome"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage fcontext -m -e")
        p = Popen(["semanage", "fcontext", "-a", "-e", "/home", "/myhome1"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage fcontext -d -e")
        p = Popen(["semanage", "fcontext", "-d", "/myhome1"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_port(self):
        # Cleanup
        p = Popen(["semanage", "port", "-d", "-p", "tcp", "55"], stdout=PIPE, stderr=PIPE)
        out, err = p.communicate()

        # test
        print("Verify semanage port -a")
        p = Popen(["semanage", "port", "-a", "-t", "ssh_port_t", "-p", "tcp", "55"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage port -m")
        p = Popen(["semanage", "port", "-m", "-t", "http_port_t", "-p", "tcp", "55"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage port -d")
        p = Popen(["semanage", "port", "-d", "-p", "tcp", "55"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_login(self):
        # Cleanup
        p = Popen(["userdel", "-f", "-r", "testlogin"], stderr=PIPE, stdout=PIPE)
        out, err = p.communicate()
        p = Popen(["semanage", "user", "-d", "testuser_u"], stderr=PIPE, stdout=PIPE)
        out, err = p.communicate()
        p = Popen(["semanage", "login", "-d", "testlogin"], stderr=PIPE, stdout=PIPE)
        out, err = p.communicate()

        #test
        print("Verify semanage user -a")
        p = Popen(["semanage", "user", "-a", "-R", "staff_r", "-r", "s0-s0:c0.c1023", "testuser_u"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify useradd ")
        p = Popen(["useradd", "testlogin"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage login -a")
        p = Popen(["semanage", "login", "-a", "-s", "testuser_u", "testlogin"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage login -m -r")
        p = Popen(["semanage", "login", "-m", "-r", "s0-s0:c1", "testlogin"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage login -m -s")
        p = Popen(["semanage", "login", "-m", "-s", "staff_u", "testlogin"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage login -m -s -r")
        p = Popen(["semanage", "login", "-m", "-s", "testuser_u", "-r", "s0", "testlogin"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage login -d")
        p = Popen(["semanage", "login", "-d", "testlogin"], stdout=PIPE)
        out, err = p.communicate()
        print("Verify userdel ")
        p = Popen(["userdel", "-f", "-r", "testlogin"], stderr=PIPE, stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage user -d")
        p = Popen(["semanage", "user", "-d", "testuser_u"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_user(self):
        # Cleanup
        p = Popen(["semanage", "user", "-d", "testuser_u"], stderr=PIPE, stdout=PIPE)
        out, err = p.communicate()

        # test
        print("Verify semanage user -a")
        p = Popen(["semanage", "user", "-a", "-R", "staff_r", "-r", "s0-s0:c0.c1023", "testuser_u"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage user -m -R")
        p = Popen(["semanage", "user", "-m", "-R", "sysadm_r unconfined_r", "testuser_u"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage user -m -r")
        p = Popen(["semanage", "user", "-m", "-r", "s0-s0:c1", "testuser_u"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage user -d")
        p = Popen(["semanage", "user", "-d", "testuser_u"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)

    def test_boolean(self):
        import selinux
        boolean_status = {0: "--off", 1: "--on"}
        boolean_state = selinux.security_get_boolean_active("httpd_anon_write")
        # Test
        print("Verify semanage boolean -m %s httpd_anon_write" % boolean_status[not boolean_state])
        p = Popen(["semanage", "boolean", "-m", boolean_status[(not boolean_state)], "httpd_anon_write"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)
        print("Verify semanage boolean -m %s httpd_anon_write" % boolean_status[boolean_state])
        p = Popen(["semanage", "boolean", "-m", boolean_status[boolean_state], "httpd_anon_write"], stdout=PIPE)
        out, err = p.communicate()
        self.assertSuccess(p.returncode, err)


def semanage_suite():
    semanage_suite = unittest.TestSuite()
    semanage_suite.addTest(unittest.makeSuite(SemanageTests))

    return semanage_suite


def semanage_custom_suite(test_list):
    suiteSemanage = unittest.TestSuite()
    for t in test_list:
        suiteSemanage.addTest(SemanageTests(t))

    return suiteSemanage


def semanage_run_test(suite):
    unittest.TextTestRunner(verbosity=2).run(suite)


class CheckTest(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        newval = getattr(namespace, self.dest)
        if not newval:
            newval = []
        for v in values:
            if v not in semanage_test_list:
                raise ValueError("%s must be an unit test.\nValid tests: %s" % (v, ", ".join(semanage_test_list)))
            newval.append(v)
        setattr(namespace, self.dest, newval)


def semanage_args(args):
    if args.list:
        print("You can run the following tests:")
        for i in semanage_test_list:
            print(i)
    if args.all:
        semanage_run_test(semanage_suite())
    if args.test:
        semanage_run_test(semanage_custom_suite(args.test))


def gen_semanage_test_args(parser):
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-a', "--all", dest="all", default=False,
                       action="store_true",
                       help=("Run all semanage unit tests"))
    group.add_argument('-l', "--list", dest="list", default=False,
                       action="store_true",
                       help=("List all semanage unit tests"))
    group.add_argument('-t', "--test", dest="test", default=[],
                       action=CheckTest, nargs="*",
                       help=("Run selected semanage unit test(s)"))
    group.set_defaults(func=semanage_args)

if __name__ == "__main__":
    import selinux
    semanage_test_list = [x for x in dir(SemanageTests) if x.startswith("test_")]
    if selinux.is_selinux_enabled() and selinux.security_getenforce() == 1:
        parser = argparse.ArgumentParser(description='Semanage unit test script')
        gen_semanage_test_args(parser)
        try:
            args = parser.parse_args()
            args.func(args)
            sys.exit(0)
        except ValueError as e:
            sys.stderr.write("%s: %s\n" % (e.__class__.__name__, str(e)))
            sys.exit(1)
        except IOError as e:
            sys.stderr.write("%s: %s\n" % (e.__class__.__name__, str(e)))
            sys.exit(1)
        except KeyboardInterrupt:
            sys.exit(0)
    else:
        print("SELinux must be in enforcing mode for this test")
