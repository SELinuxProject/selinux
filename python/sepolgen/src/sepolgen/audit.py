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

import re
import sys

from . import refpolicy
from . import access
from . import util
# Convenience functions

def get_audit_boot_msgs():
    """Obtain all of the avc and policy load messages from the audit
    log. This function uses ausearch and requires that the current
    process have sufficient rights to run ausearch.

    Returns:
       string contain all of the audit messages returned by ausearch.
    """
    import subprocess
    import time
    fd=open("/proc/uptime", "r")
    off=float(fd.read().split()[0])
    fd.close
    s = time.localtime(time.time() - off)
    bootdate = time.strftime("%x", s)
    boottime = time.strftime("%X", s)
    output = subprocess.Popen(["/sbin/ausearch", "-m", "AVC,USER_AVC,MAC_POLICY_LOAD,DAEMON_START,SELINUX_ERR", "-ts", bootdate, boottime],
                              stdout=subprocess.PIPE).communicate()[0]
    if util.PY3:
        output = util.decode_input(output)
    return output

def get_audit_msgs():
    """Obtain all of the avc and policy load messages from the audit
    log. This function uses ausearch and requires that the current
    process have sufficient rights to run ausearch.

    Returns:
       string contain all of the audit messages returned by ausearch.
    """
    import subprocess
    output = subprocess.Popen(["/sbin/ausearch", "-m", "AVC,USER_AVC,MAC_POLICY_LOAD,DAEMON_START,SELINUX_ERR"],
                              stdout=subprocess.PIPE).communicate()[0]
    if util.PY3:
        output = util.decode_input(output)
    return output

def get_dmesg_msgs():
    """Obtain all of the avc and policy load messages from /bin/dmesg.

    Returns:
       string contain all of the audit messages returned by dmesg.
    """
    import subprocess
    output = subprocess.Popen(["/bin/dmesg"],
                              stdout=subprocess.PIPE).communicate()[0]
    if util.PY3:
        output = util.decode_input(output)
    return output

# Classes representing audit messages

class AuditMessage:
    """Base class for all objects representing audit messages.

    AuditMessage is a base class for all audit messages and only
    provides storage for the raw message (as a string) and a
    parsing function that does nothing.
    """
    def __init__(self, message):
        self.message = message
        self.header = ""

    def from_split_string(self, recs):
        """Parse a string that has been split into records by space into
        an audit message.

        This method should be overridden by subclasses. Error reporting
        should be done by raise ValueError exceptions.
        """
        for msg in recs:
            fields = msg.split("=")
            if len(fields) != 2:
                if msg[:6] == "audit(":
                    self.header = msg
                    return
                else:
                    continue
            
            if fields[0] == "msg":
                self.header = fields[1]
                return


class InvalidMessage(AuditMessage):
    """Class representing invalid audit messages. This is used to differentiate
    between audit messages that aren't recognized (that should return None from
    the audit message parser) and a message that is recognized but is malformed
    in some way.
    """
    def __init__(self, message):
        AuditMessage.__init__(self, message)

class PathMessage(AuditMessage):
    """Class representing a path message"""
    def __init__(self, message):
        AuditMessage.__init__(self, message)
        self.path = ""

    def from_split_string(self, recs):
        AuditMessage.from_split_string(self, recs)
        
        for msg in recs:
            fields = msg.split("=")
            if len(fields) != 2:
                continue
            if fields[0] == "path":
                self.path = fields[1][1:-1]
                return
import selinux.audit2why as audit2why

avcdict = {}

class AVCMessage(AuditMessage):
    """AVC message representing an access denial or granted message.

    This is a very basic class and does not represent all possible fields
    in an avc message. Currently the fields are:
       scontext - context for the source (process) that generated the message
       tcontext - context for the target
       tclass - object class for the target (only one)
       comm - the process name
       exe - the on-disc binary
       path - the path of the target
       access - list of accesses that were allowed or denied
       denial - boolean indicating whether this was a denial (True) or granted
          (False) message.

    An example audit message generated from the audit daemon looks like (line breaks
    added):
       'type=AVC msg=audit(1155568085.407:10877): avc:  denied  { search } for
       pid=677 comm="python" name="modules" dev=dm-0 ino=13716388
       scontext=user_u:system_r:setroubleshootd_t:s0
       tcontext=system_u:object_r:modules_object_t:s0 tclass=dir'

    An example audit message stored in syslog (not processed by the audit daemon - line
    breaks added):
       'Sep 12 08:26:43 dhcp83-5 kernel: audit(1158064002.046:4): avc:  denied  { read }
       for  pid=2 496 comm="bluez-pin" name=".gdm1K3IFT" dev=dm-0 ino=3601333
       scontext=user_u:system_r:bluetooth_helper_t:s0-s0:c0
       tcontext=system_u:object_r:xdm_tmp_t:s0 tclass=file
    """
    def __init__(self, message):
        AuditMessage.__init__(self, message)
        self.scontext = refpolicy.SecurityContext()
        self.tcontext = refpolicy.SecurityContext()
        self.tclass = ""
        self.comm = ""
        self.exe = ""
        self.path = ""
        self.name = ""
        self.accesses = []
        self.denial = True
        self.type = audit2why.TERULE

    def __parse_access(self, recs, start):
        # This is kind of sucky - the access that is in a space separated
        # list like '{ read write }'. This doesn't fit particularly well with splitting
        # the string on spaces. This function takes the list of recs and a starting
        # position one beyond the open brace. It then adds the accesses until it finds
        # the close brace or the end of the list (which is an error if reached without
        # seeing a close brace).
        found_close = False
        i = start
        if i == (len(recs) - 1):
            raise ValueError("AVC message in invalid format [%s]\n" % self.message)
        while i < len(recs):
            if recs[i] == "}":
                found_close = True
                break
            self.accesses.append(recs[i])
            i = i + 1
        if not found_close:
            raise ValueError("AVC message in invalid format [%s]\n" % self.message)
        return i + 1
        

    def from_split_string(self, recs):
        AuditMessage.from_split_string(self, recs)        
        # FUTURE - fully parse avc messages and store all possible fields
        # Required fields
        found_src = False
        found_tgt = False
        found_class = False
        found_access = False
        
        for i in range(len(recs)):
            if recs[i] == "{":
                i = self.__parse_access(recs, i + 1)
                found_access = True
                continue
            elif recs[i] == "granted":
                self.denial = False
            
            fields = recs[i].split("=")
            if len(fields) != 2:
                continue
            if fields[0] == "scontext":
                self.scontext = refpolicy.SecurityContext(fields[1])
                found_src = True
            elif fields[0] == "tcontext":
                self.tcontext = refpolicy.SecurityContext(fields[1])
                found_tgt = True
            elif fields[0] == "tclass":
                self.tclass = fields[1]
                found_class = True
            elif fields[0] == "comm":
                self.comm = fields[1][1:-1]
            elif fields[0] == "exe":
                self.exe = fields[1][1:-1]
            elif fields[0] == "name":
                self.name = fields[1][1:-1]

        if not found_src or not found_tgt or not found_class or not found_access:
            raise ValueError("AVC message in invalid format [%s]\n" % self.message)
        self.analyze()

    def analyze(self):
        tcontext = self.tcontext.to_string()
        scontext = self.scontext.to_string()
        access_tuple = tuple( self.accesses)
        self.data = []

        if (scontext, tcontext, self.tclass, access_tuple) in avcdict.keys():
            self.type, self.data = avcdict[(scontext, tcontext, self.tclass, access_tuple)]
        else:
            self.type, self.data = audit2why.analyze(scontext, tcontext, self.tclass, self.accesses);
            if self.type == audit2why.NOPOLICY:
                self.type = audit2why.TERULE
            if self.type == audit2why.BADTCON:
                raise ValueError("Invalid Target Context %s\n" % tcontext)
            if self.type == audit2why.BADSCON:
                raise ValueError("Invalid Source Context %s\n" % scontext)
            if self.type == audit2why.BADSCON:
                raise ValueError("Invalid Type Class %s\n" % self.tclass)
            if self.type == audit2why.BADPERM:
                raise ValueError("Invalid permission %s\n" % " ".join(self.accesses))
            if self.type == audit2why.BADCOMPUTE:
                raise ValueError("Error during access vector computation")

            if self.type == audit2why.CONSTRAINT:
                self.data = [ self.data ]
                if self.scontext.user != self.tcontext.user:
                    self.data.append(("user (%s)" % self.scontext.user, 'user (%s)' % self.tcontext.user))
                if self.scontext.role != self.tcontext.role and self.tcontext.role != "object_r":
                    self.data.append(("role (%s)" % self.scontext.role, 'role (%s)' % self.tcontext.role))
                if self.scontext.level != self.tcontext.level:
                    self.data.append(("level (%s)" % self.scontext.level, 'level (%s)' % self.tcontext.level))

            avcdict[(scontext, tcontext, self.tclass, access_tuple)] = (self.type, self.data)

class PolicyLoadMessage(AuditMessage):
    """Audit message indicating that the policy was reloaded."""
    def __init__(self, message):
        AuditMessage.__init__(self, message)

class DaemonStartMessage(AuditMessage):
    """Audit message indicating that a daemon was started."""
    def __init__(self, message):
        AuditMessage.__init__(self, message)
        self.auditd = False

    def from_split_string(self, recs):
        AuditMessage.from_split_string(self, recs)
        if "auditd" in recs:
            self.auditd = True
        

class ComputeSidMessage(AuditMessage):
    """Audit message indicating that a sid was not valid.

    Compute sid messages are generated on attempting to create a security
    context that is not valid. Security contexts are invalid if the role is
    not authorized for the user or the type is not authorized for the role.

    This class does not store all of the fields from the compute sid message -
    just the type and role.
    """
    def __init__(self, message):
        AuditMessage.__init__(self, message)
        self.invalid_context = refpolicy.SecurityContext()
        self.scontext = refpolicy.SecurityContext()
        self.tcontext = refpolicy.SecurityContext()
        self.tclass = ""

    def from_split_string(self, recs):
        AuditMessage.from_split_string(self, recs)
        if len(recs) < 10:
            raise ValueError("Split string does not represent a valid compute sid message")

        try:
            self.invalid_context = refpolicy.SecurityContext(recs[5])
            self.scontext = refpolicy.SecurityContext(recs[7].split("=")[1])
            self.tcontext = refpolicy.SecurityContext(recs[8].split("=")[1])
            self.tclass = recs[9].split("=")[1]
        except:
            raise ValueError("Split string does not represent a valid compute sid message")
    def output(self):
        return "role %s types %s;\n" % (self.role, self.type)
        
# Parser for audit messages

class AuditParser:
    """Parser for audit messages.

    This class parses audit messages and stores them according to their message
    type. This is not a general purpose audit message parser - it only extracts
    selinux related messages.

    Each audit messages are stored in one of four lists:
       avc_msgs - avc denial or granted messages. Messages are stored in
          AVCMessage objects.
       comput_sid_messages - invalid sid messages. Messages are stored in
          ComputSidMessage objects.
       invalid_msgs - selinux related messages that are not valid. Messages
          are stored in InvalidMessageObjects.
       policy_load_messages - policy load messages. Messages are stored in
          PolicyLoadMessage objects.

    These lists will be reset when a policy load message is seen if
    AuditParser.last_load_only is set to true. It is assumed that messages
    are fed to the parser in chronological order - time stamps are not
    parsed.
    """
    def __init__(self, last_load_only=False):
        self.__initialize()
        self.last_load_only = last_load_only

    def __initialize(self):
        self.avc_msgs = []
        self.compute_sid_msgs = []
        self.invalid_msgs = []
        self.policy_load_msgs = []
        self.path_msgs = []
        self.by_header = { }
        self.check_input_file = False
                
    # Low-level parsing function - tries to determine if this audit
    # message is an SELinux related message and then parses it into
    # the appropriate AuditMessage subclass. This function deliberately
    # does not impose policy (e.g., on policy load message) or store
    # messages to make as simple and reusable as possible.
    #
    # Return values:
    #   None - no recognized audit message found in this line
    #
    #   InvalidMessage - a recognized but invalid message was found.
    #
    #   AuditMessage (or subclass) - object representing a parsed
    #      and valid audit message.
    def __parse_line(self, line):
        rec = line.split()
        for i in rec:
            found = False
            if i == "avc:" or i == "message=avc:" or i == "msg='avc:":
                msg = AVCMessage(line)
                found = True
            elif i == "security_compute_sid:":
                msg = ComputeSidMessage(line)
                found = True
            elif i == "type=MAC_POLICY_LOAD" or i == "type=1403":
                msg = PolicyLoadMessage(line)
                found = True
            elif i == "type=AVC_PATH":
                msg = PathMessage(line)
                found = True
            elif i == "type=DAEMON_START":
                msg = DaemonStartMessage(list)
                found = True
                
            if found:
                self.check_input_file = True
                try:
                    msg.from_split_string(rec)
                except ValueError:
                    msg = InvalidMessage(line)
                return msg
        return None

    # Higher-level parse function - take a line, parse it into an
    # AuditMessage object, and store it in the appropriate list.
    # This function will optionally reset all of the lists when
    # it sees a load policy message depending on the value of
    # self.last_load_only.
    def __parse(self, line):
        msg = self.__parse_line(line)
        if msg is None:
            return

        # Append to the correct list
        if isinstance(msg, PolicyLoadMessage):
            if self.last_load_only:
                self.__initialize()
        elif isinstance(msg, DaemonStartMessage):
            # We initialize every time the auditd is started. This
            # is less than ideal, but unfortunately it is the only
            # way to catch reboots since the initial policy load
            # by init is not stored in the audit log.
            if msg.auditd and self.last_load_only:
                self.__initialize()
            self.policy_load_msgs.append(msg)
        elif isinstance(msg, AVCMessage):
            self.avc_msgs.append(msg)
        elif isinstance(msg, ComputeSidMessage):
            self.compute_sid_msgs.append(msg)
        elif isinstance(msg, InvalidMessage):
            self.invalid_msgs.append(msg)
        elif isinstance(msg, PathMessage):
            self.path_msgs.append(msg)

        # Group by audit header
        if msg.header != "":
            if msg.header in self.by_header:
                self.by_header[msg.header].append(msg)
            else:
                self.by_header[msg.header] = [msg]
            

    # Post processing will add additional information from AVC messages
    # from related messages - only works on messages generated by
    # the audit system.
    def __post_process(self):
        for value in self.by_header.values():
            avc = []
            path = None
            for msg in value:
                if isinstance(msg, PathMessage):
                    path = msg
                elif isinstance(msg, AVCMessage):
                    avc.append(msg)
            if len(avc) > 0 and path:
                for a in avc:
                    a.path = path.path

    def parse_file(self, input):
        """Parse the contents of a file object. This method can be called
        multiple times (along with parse_string)."""
        line = input.readline()
        while line:
            self.__parse(line)
            line = input.readline()
        if not self.check_input_file:
            sys.stderr.write("Nothing to do\n")
            sys.exit(0)
        self.__post_process()

    def parse_string(self, input):
        """Parse a string containing audit messages - messages should
        be separated by new lines. This method can be called multiple
        times (along with parse_file)."""
        lines = input.split('\n')
        for l in lines:
            self.__parse(l)
        self.__post_process()

    def to_role(self, role_filter=None):
        """Return RoleAllowSet statements matching the specified filter

        Filter out types that match the filer, or all roles

        Params:
           role_filter - [optional] Filter object used to filter the
              output.
        Returns:
           Access vector set representing the denied access in the
           audit logs parsed by this object.
        """
        role_types = access.RoleTypeSet()
        for cs in self.compute_sid_msgs:
            if not role_filter or role_filter.filter(cs):
                role_types.add(cs.invalid_context.role, cs.invalid_context.type)
        
        return role_types

    def to_access(self, avc_filter=None, only_denials=True):
        """Convert the audit logs access into a an access vector set.

        Convert the audit logs into an access vector set, optionally
        filtering the restults with the passed in filter object.

        Filter objects are object instances with a .filter method
        that takes and access vector and returns True if the message
        should be included in the final output and False otherwise.

        Params:
           avc_filter - [optional] Filter object used to filter the
              output.
        Returns:
           Access vector set representing the denied access in the
           audit logs parsed by this object.
        """
        av_set = access.AccessVectorSet()
        for avc in self.avc_msgs:
            if avc.denial != True and only_denials:
                continue
            if avc_filter:
                if avc_filter.filter(avc):
                    av_set.add(avc.scontext.type, avc.tcontext.type, avc.tclass,
                               avc.accesses, avc, avc_type=avc.type, data=avc.data)
            else:
                av_set.add(avc.scontext.type, avc.tcontext.type, avc.tclass,
                           avc.accesses, avc, avc_type=avc.type, data=avc.data)
        return av_set

class AVCTypeFilter:
    def __init__(self, regex):
        self.regex = re.compile(regex)

    def filter(self, avc):
        if self.regex.match(avc.scontext.type):
            return True
        if self.regex.match(avc.tcontext.type):
            return True
        return False

class ComputeSidTypeFilter:
    def __init__(self, regex):
        self.regex = re.compile(regex)

    def filter(self, avc):
        if self.regex.match(avc.invalid_context.type):
            return True
        if self.regex.match(avc.scontext.type):
            return True
        if self.regex.match(avc.tcontext.type):
            return True
        return False


