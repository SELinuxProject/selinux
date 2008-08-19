# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#
# Copyright (C) 2006 Red Hat 
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; version 2 only
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import unittest
import sepolgen.audit
import sepolgen.refpolicy

# syslog message
audit1 = """Sep 12 08:26:43 dhcp83-5 kernel: audit(1158064002.046:4): avc:  denied  { read } for  pid=2 496 comm="bluez-pin" name=".gdm1K3IFT" dev=dm-0 ino=3601333 scontext=user_u:system_r:bluetooth_helper_t:s0-s0:c0 tcontext=system_u:object_r:xdm_tmp_t:s0 tclass=file"""

# audit daemon messages
audit2 = """type=AVC msg=audit(1158584779.745:708): avc:  denied  { dac_read_search } for  pid=8132 comm="sh" capability=2 scontext=user_u:system_r:vpnc_t:s0 tcontext=user_u:system_r:vpnc_t:s0 tclass=capability"""

log1 = """type=AVC msg=audit(1158584779.745:708): avc:  denied  { dac_read_search } for  pid=8132 comm="sh" capability=2 scontext=user_u:system_r:vpnc_t:s0 tcontext=user_u:system_r:vpnc_t:s0 tclass=capability
type=SYSCALL msg=audit(1158584779.745:708): arch=40000003 syscall=195 success=no exit=-13 a0=80d2437 a1=bf9132f8 a2=4c56cff4 a3=0 items=0 ppid=8131 pid=8132 auid=500 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) comm="sh" exe="/bin/bash" subj=user_u:system_r:vpnc_t:s0 key=(null)
type=AVC msg=audit(1158584779.753:709): avc:  denied  { dac_override } for  pid=8133 comm="vpnc-script" capability=1 scontext=user_u:system_r:vpnc_t:s0 tcontext=user_u:system_r:vpnc_t:s0 tclass=capability
type=AVC msg=audit(1158584779.753:709): avc:  denied  { dac_read_search } for  pid=8133 comm="vpnc-script" capability=2 scontext=user_u:system_r:vpnc_t:s0 tcontext=user_u:system_r:vpnc_t:s0 tclass=capability
type=SYSCALL msg=audit(1158584779.753:709): arch=40000003 syscall=195 success=no exit=-13 a0=80d2437 a1=bf910a48 a2=4c56cff4 a3=0 items=0 ppid=8132 pid=8133 auid=500 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) comm="vpnc-script" exe="/bin/bash" subj=user_u:system_r:vpnc_t:s0 key=(null)
type=AVC msg=audit(1158584779.825:710): avc:  denied  { dac_override } for  pid=8134 comm="vpnc-script" capability=1 scontext=user_u:system_r:vpnc_t:s0 tcontext=user_u:system_r:vpnc_t:s0 tclass=capability
type=AVC msg=audit(1158584779.825:710): avc:  denied  { dac_read_search } for  pid=8134 comm="vpnc-script" capability=2 scontext=user_u:system_r:vpnc_t:s0 tcontext=user_u:system_r:vpnc_t:s0 tclass=capability
type=SYSCALL msg=audit(1158584779.825:710): arch=40000003 syscall=195 success=no exit=-13 a0=80d2437 a1=bf910a48 a2=4c56cff4 a3=0 items=0 ppid=8132 pid=8134 auid=500 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) comm="vpnc-script" exe="/bin/bash" subj=user_u:system_r:vpnc_t:s0 key=(null)
type=AVC msg=audit(1158584780.793:711): avc:  denied  { dac_override } for  pid=8144 comm="sh" capability=1 scontext=user_u:system_r:vpnc_t:s0 tcontext=user_u:system_r:vpnc_t:s0 tclass=capability
type=AVC msg=audit(1158584780.793:711): avc:  denied  { dac_read_search } for  pid=8144 comm="sh" capability=2 scontext=user_u:system_r:vpnc_t:s0 tcontext=user_u:system_r:vpnc_t:s0 tclass=capability
type=SYSCALL msg=audit(1158584780.793:711): arch=40000003 syscall=195 success=no exit=-13 a0=80d2437 a1=bfc0ba38 a2=4c56cff4 a3=0 items=0 ppid=8131 pid=8144 auid=500 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) comm="sh" exe="/bin/bash" subj=user_u:system_r:vpnc_t:s0 key=(null)
type=AVC msg=audit(1158584780.797:712): avc:  denied  { dac_override } for  pid=8145 comm="vpnc-script" capability=1 scontext=user_u:system_r:vpnc_t:s0 tcontext=user_u:system_r:vpnc_t:s0 tclass=capability
type=AVC msg=audit(1158584780.797:712): avc:  denied  { dac_read_search } for  pid=8145 comm="vpnc-script" capability=2 scontext=user_u:system_r:vpnc_t:s0 tcontext=user_u:system_r:vpnc_t:s0 tclass=capability
type=SYSCALL msg=audit(1158584780.797:712): arch=40000003 syscall=195 success=no exit=-13 a0=80d2437 a1=bfc0b188 a2=4c56cff4 a3=0 items=0 ppid=8144 pid=8145 auid=500 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) comm="vpnc-script" exe="/bin/bash" subj=user_u:system_r:vpnc_t:s0 key=(null)
type=AVC msg=audit(1158584780.801:713): avc:  denied  { dac_override } for  pid=8146 comm="vpnc-script" capability=1 scontext=user_u:system_r:vpnc_t:s0 tcontext=user_u:system_r:vpnc_t:s0 tclass=capability
type=AVC msg=audit(1158584780.801:713): avc:  denied  { dac_read_search } for  pid=8146 comm="vpnc-script" capability=2 scontext=user_u:system_r:vpnc_t:s0 tcontext=user_u:system_r:vpnc_t:s0 tclass=capability
type=AVC_PATH msg=audit(1162850461.778:1113):  path="/etc/rc.d/init.d/innd"
"""

granted1 = """type=AVC msg=audit(1188833848.190:34): avc:  granted  { getattr } for  pid=4310 comm="ls" name="foo.pp" dev=sda5 ino=295171 scontext=user_u:system_r:unconfined_t:s0 tcontext=user_u:object_r:user_home_t:s0 tclass=file"""

path1 = """type=AVC_PATH msg=audit(1162852201.019:1225):  path="/usr/lib/sa/sa1"
"""

log2 = """type=AVC_PATH msg=audit(1162852201.019:1225):  path="/usr/lib/sa/sa1"
type=SYSCALL msg=audit(1162852201.019:1225): arch=40000003 syscall=11 success=yes exit=0 a0=87271b0 a1=8727358 a2=8727290 a3=8727008 items=0 ppid=6973 pid=6974 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) comm="sa1" exe="/bin/bash" subj=system_u:system_r:crond_t:s0-s0:c0.c1023 key=(null)
type=AVC msg=audit(1162852201.019:1225): avc:  denied  { execute_no_trans } for  pid=6974 comm="sh" name="sa1" dev=dm-0 ino=13061698 scontext=system_u:system_r:crond_t:s0-s0:c0.c1023 tcontext=system_u:object_r:lib_t:s0 tclass=file
type=AVC msg=audit(1162852201.019:1225): avc:  denied  { execute } for  pid=6974 comm="sh" name="sa1" dev=dm-0 ino=13061698 scontext=system_u:system_r:crond_t:s0-s0:c0.c1023 tcontext=system_u:object_r:lib_t:s0 tclass=file"""

class TestAVCMessage(unittest.TestCase):
    def test_defs(self):
        avc = sepolgen.audit.AVCMessage(audit1)
        sc = sepolgen.refpolicy.SecurityContext()
        self.assertEquals(avc.scontext, sc)
        self.assertEquals(avc.tcontext, sc)
        self.assertEquals(avc.tclass, "")
        self.assertEquals(avc.accesses, [])

    def test_granted(self):
        avc = sepolgen.audit.AVCMessage(granted1)
        avc.from_split_string(granted1.split())

        self.assertEquals(avc.scontext.user, "user_u")
        self.assertEquals(avc.scontext.role, "system_r")
        self.assertEquals(avc.scontext.type, "unconfined_t")
        self.assertEquals(avc.scontext.level, "s0")

        self.assertEquals(avc.tcontext.user, "user_u")
        self.assertEquals(avc.tcontext.role, "object_r")
        self.assertEquals(avc.tcontext.type, "user_home_t")
        self.assertEquals(avc.tcontext.level, "s0")
        
        self.assertEquals(avc.tclass, "file")
        self.assertEquals(avc.accesses, ["getattr"])

        self.assertEquals(avc.denial, False)


    def test_from_split_string(self):
        # syslog message
        avc = sepolgen.audit.AVCMessage(audit1)
        recs = audit1.split()
        avc.from_split_string(recs)

        self.assertEquals(avc.header, "audit(1158064002.046:4):")
        self.assertEquals(avc.scontext.user, "user_u")
        self.assertEquals(avc.scontext.role, "system_r")
        self.assertEquals(avc.scontext.type, "bluetooth_helper_t")
        self.assertEquals(avc.scontext.level, "s0-s0:c0")

        self.assertEquals(avc.tcontext.user, "system_u")
        self.assertEquals(avc.tcontext.role, "object_r")
        self.assertEquals(avc.tcontext.type, "xdm_tmp_t")
        self.assertEquals(avc.tcontext.level, "s0")

        self.assertEquals(avc.tclass, "file")
        self.assertEquals(avc.accesses, ["read"])

        self.assertEquals(avc.comm, "bluez-pin")


        self.assertEquals(avc.denial, True)

        # audit daemon message
        avc = sepolgen.audit.AVCMessage(audit2)
        recs = audit2.split()
        avc.from_split_string(recs)

        self.assertEquals(avc.header, "audit(1158584779.745:708):")
        self.assertEquals(avc.scontext.user, "user_u")
        self.assertEquals(avc.scontext.role, "system_r")
        self.assertEquals(avc.scontext.type, "vpnc_t")
        self.assertEquals(avc.scontext.level, "s0")

        self.assertEquals(avc.tcontext.user, "user_u")
        self.assertEquals(avc.tcontext.role, "system_r")
        self.assertEquals(avc.tcontext.type, "vpnc_t")
        self.assertEquals(avc.tcontext.level, "s0")

        self.assertEquals(avc.tclass, "capability")
        self.assertEquals(avc.accesses, ["dac_read_search"])

        self.assertEquals(avc.comm, "sh")

        self.assertEquals(avc.denial, True)

class TestPathMessage(unittest.TestCase):
    def test_from_split_string(self):
        path = sepolgen.audit.PathMessage(path1)
        recs = path1.split()
        path.from_split_string(recs)
        self.assertEquals(path.path, "/usr/lib/sa/sa1")

# TODO - add tests for the other message types


# TODO - these tests need a lot of expansion and more examples of
# different types of log files
class TestAuditParser(unittest.TestCase):
    def test_parse_string(self):
        a = sepolgen.audit.AuditParser()
        a.parse_string(log1)
        self.assertEquals(len(a.avc_msgs), 11)
        self.assertEquals(len(a.compute_sid_msgs), 0)
        self.assertEquals(len(a.invalid_msgs), 0)
        self.assertEquals(len(a.policy_load_msgs), 0)
        self.assertEquals(len(a.path_msgs), 1)

    def test_post_process(self):
        a = sepolgen.audit.AuditParser()
        a.parse_string(log2)
        self.assertEquals(len(a.avc_msgs), 2)
        self.assertEquals(a.avc_msgs[0].path, "/usr/lib/sa/sa1")
        self.assertEquals(a.avc_msgs[1].path, "/usr/lib/sa/sa1")

    def test_parse_file(self):
        f = open("audit.txt")
        a = sepolgen.audit.AuditParser()
        a.parse_file(f)
        self.assertEquals(len(a.avc_msgs), 21)
        self.assertEquals(len(a.compute_sid_msgs), 0)
        self.assertEquals(len(a.invalid_msgs), 0)
        self.assertEquals(len(a.policy_load_msgs), 0)

class TestGeneration(unittest.TestCase):
    def test_generation(self):
        parser = sepolgen.audit.AuditParser()
        parser.parse_string(log1)
        avs = parser.to_access()

        self.assertEqual(len(avs), 1)

    def test_genaration_granted(self):
        parser = sepolgen.audit.AuditParser()
        parser.parse_string(granted1)
        avs = parser.to_access()

        self.assertEqual(len(avs), 0)
        
        avs = parser.to_access(only_denials=False)
        
        self.assertEqual(len(avs), 1)

