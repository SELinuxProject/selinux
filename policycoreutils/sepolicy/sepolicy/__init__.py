#!/usr/bin/python

# Author: Thomas Liu <tliu@redhat.com>
# Author: Dan Walsh <dwalsh@redhat.com>

import _policy
import selinux, glob
PROGNAME="policycoreutils"
import gettext
gettext.bindtextdomain(PROGNAME, "/usr/share/locale")
gettext.textdomain(PROGNAME)
try:
    gettext.install(PROGNAME,
                    localedir="/usr/share/locale",
                    unicode=False,
                    codeset = 'utf-8')
except IOError:
    import __builtin__
    __builtin__.__dict__['_'] = unicode

TYPE = _policy.TYPE
ROLE = _policy.ROLE
ATTRIBUTE = _policy.ATTRIBUTE
PORT = _policy.PORT
USER = _policy.USER
BOOLEAN = _policy.BOOLEAN
TCLASS =  _policy.CLASS

ALLOW = 'allow'
AUDITALLOW = 'auditallow'
NEVERALLOW = 'neverallow'
DONTAUDIT = 'dontaudit'
SOURCE = 'source'
TARGET = 'target'
PERMS = 'permlist'
CLASS = 'class'
TRANSITION = 'transition'
ROLE_ALLOW = 'role_allow'

def __get_installed_policy():
    try:
        path = selinux.selinux_binary_policy_path()
        policies = glob.glob ("%s.*" % path )
        policies.sort()
        return policies[-1]
    except:
        pass
    raise ValueError(_("No SELinux Policy installed"))
        
all_types = None
def get_all_types():
    global all_types
    if all_types == None:
        all_types = map(lambda x: x['name'], info(TYPE))
    return all_types

role_allows = None
def get_all_role_allows():
	global role_allows
	if role_allows:
		return role_allows
	role_allows = {}
	for r in search([ROLE_ALLOW]):
		if r["source"] == "system_r" or r["target"] == "system_r":
			continue
		if r["source"] in role_allows:
			role_allows[r["source"]].append(r["target"])
		else:
			role_allows[r["source"]] = [ r["target"] ]

	return role_allows

def get_all_entrypoint_domains():
    all_domains = []
    types=get_all_types()
    types.sort()
    for i in types:
        m = re.findall("(.*)%s" % "_exec_t$", i)
        if len(m) > 0:
            if len(re.findall("(.*)%s" % "_initrc$", m[0])) == 0 and m[0] not in all_domains:
                all_domains.append(m[0])
    return all_domains

all_domains = None
def get_all_domains():
	global all_domains
	if not all_domains:
		all_domains = info(ATTRIBUTE,"domain")[0]["types"]
	return all_domains

roles = None
def get_all_roles():
	global roles
	if roles:
		return roles
        roles = map(lambda x: x['name'], info(ROLE))
        roles.remove("object_r")
        roles.sort()
        return roles

users = None
def get_all_users():
    global users
    if users:
        return users
    users = map(lambda x: x['name'], info(USER))
    return users 

file_types = None
def get_all_file_types():
	global file_types
	if file_types:
		return file_types
	file_types =  info(ATTRIBUTE,"file_type")[0]["types"]
	file_types.sort()
	return file_types

port_types = None
def get_all_port_types():
	global port_types
	if port_types:
		return port_types
	port_types =  info(ATTRIBUTE,"port_type")[0]["types"]
	port_types.sort()
	return port_types

bools = None
def get_all_bools():
	global bools
	if not bools:
		bools = info(BOOLEAN)
	return bools

all_attributes = None
def get_all_attributes():
	global all_attributes
	if not all_attributes:
		all_attributes = map(lambda x: x['name'], info(ATTRIBUTE))
	return all_attributes

def policy(policy_file):
    try:
        _policy.policy(policy_file)
    except:
        raise ValueError(_("Failed to read %s policy file") % policy_file)


policy_file = selinux.selinux_current_policy_path()
if not policy_file:
    policy_file = __get_installed_policy()

try:
    policy(policy_file)
except ValueError, e:
    if selinux.is_selinux_enabled() == 1:
        raise e

def search(types, info = {} ):
    valid_types = [ALLOW, AUDITALLOW, NEVERALLOW, DONTAUDIT, TRANSITION, ROLE_ALLOW]
    for type in types:
        if type not in valid_types:
            raise ValueError("Type has to be in %s" % valid_types)
        info[type] = True

    perms = []
    if PERMS in info:
        perms = info[PERMS]
        info[PERMS] = ",".join(info[PERMS])

    dict_list = _policy.search(info)
    if dict_list and len(perms) != 0:
        dict_list = filter(lambda x: _dict_has_perms(x, perms), dict_list)
    return dict_list

def _dict_has_perms(dict, perms):
    for perm in perms:
        if perm not in dict[PERMS]:
            return False
    return True

def info(setype, name=None):
    dict_list = _policy.info(setype, name)
    return dict_list

booleans_dict = None
def gen_bool_dict(path="/usr/share/selinux/devel/policy.xml"):
        global booleans_dict
        if booleans_dict:
            return booleans_dict
	import xml.etree.ElementTree
	import re
	booleans_dict = {}
	try:
		tree = xml.etree.ElementTree.parse(path)
		for l in  tree.findall("layer"):
			for m in  l.findall("module"):
				for b in  m.findall("tunable"):
					desc = b.find("desc").find("p").text.strip("\n")
					desc = re.sub("\n", " ", desc)
					booleans_dict[b.get('name')] = (m.get("name"), b.get('dftval'), desc)
				for b in  m.findall("bool"):
					desc = b.find("desc").find("p").text.strip("\n")
					desc = re.sub("\n", " ", desc)
					booleans_dict[b.get('name')] = (m.get("name"), b.get('dftval'), desc)
			for i in  tree.findall("bool"):
				desc = i.find("desc").find("p").text.strip("\n")
				desc = re.sub("\n", " ", desc)
				booleans_dict[i.get('name')] = ("global", i.get('dftval'), desc)
		for i in  tree.findall("tunable"):
			desc = i.find("desc").find("p").text.strip("\n")
			desc = re.sub("\n", " ", desc)
			booleans_dict[i.get('name')] = ("global", i.get('dftval'), desc)
	except IOError, e:
		pass
	return booleans_dict

def boolean_category(boolean):
    booleans_dict = gen_bool_dict()
    if boolean in booleans_dict:
        return _(booleans_dict[boolean][0])
    else:
        return _("unknown")

def boolean_desc(boolean):
       booleans_dict = gen_bool_dict()
       if boolean in booleans_dict:
              return _(booleans_dict[boolean][2])
       else:
           desc = boolean.split("_")
           return "Allow %s to %s" % (desc[0], " ".join(desc[1:]))

def get_os_version():
    os_version = ""
    pkg_name = "selinux-policy"
    try:
	import commands
	rc, output = commands.getstatusoutput("rpm -q '%s'" % pkg_name)
	if rc == 0:
	    os_version = output.split(".")[-2]
    except:
	os_version = ""

    if os_version[0:2] == "fc":
	os_version = "Fedora"+os_version[2:]
    elif os_version[0:2] == "el":
	os_version = "RHEL"+os_version[2:]
    else:
	os_version = ""

    return os_version
