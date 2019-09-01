# Author: Dan Walsh <dwalsh@redhat.com>
# Author: Ryan Hallisey <rhallise@redhat.com>
# Author: Jason Zaman <perfinion@gentoo.org>

import errno
import selinux
import setools
import glob
import sepolgen.defaults as defaults
import sepolgen.interfaces as interfaces
import sys
import os
import re
import gzip

PROGNAME = "policycoreutils"
try:
    import gettext
    kwargs = {}
    if sys.version_info < (3,):
        kwargs['unicode'] = True
    gettext.install(PROGNAME,
                    localedir="/usr/share/locale",
                    codeset='utf-8',
                    **kwargs)
except:
    try:
        import builtins
        builtins.__dict__['_'] = str
    except ImportError:
        import __builtin__
        __builtin__.__dict__['_'] = unicode

TYPE = 1
ROLE = 2
ATTRIBUTE = 3
PORT = 4
USER = 5
BOOLEAN = 6
TCLASS = 7

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


# Autofill for adding files *************************
DEFAULT_DIRS = {}
DEFAULT_DIRS["/etc"] = "etc_t"
DEFAULT_DIRS["/tmp"] = "tmp_t"
DEFAULT_DIRS["/usr/lib/systemd/system"] = "unit_file_t"
DEFAULT_DIRS["/lib/systemd/system"] = "unit_file_t"
DEFAULT_DIRS["/etc/systemd/system"] = "unit_file_t"
DEFAULT_DIRS["/var/cache"] = "var_cache_t"
DEFAULT_DIRS["/var/lib"] = "var_lib_t"
DEFAULT_DIRS["/var/log"] = "log_t"
DEFAULT_DIRS["/var/run"] = "var_run_t"
DEFAULT_DIRS["/run"] = "var_run_t"
DEFAULT_DIRS["/run/lock"] = "var_lock_t"
DEFAULT_DIRS["/var/run/lock"] = "var_lock_t"
DEFAULT_DIRS["/var/spool"] = "var_spool_t"
DEFAULT_DIRS["/var/www"] = "content_t"

file_type_str = {}
file_type_str["a"] = _("all files")
file_type_str["f"] = _("regular file")
file_type_str["d"] = _("directory")
file_type_str["c"] = _("character device")
file_type_str["b"] = _("block device")
file_type_str["s"] = _("socket file")
file_type_str["l"] = _("symbolic link")
file_type_str["p"] = _("named pipe")

trans_file_type_str = {}
trans_file_type_str[""] = "a"
trans_file_type_str["--"] = "f"
trans_file_type_str["-d"] = "d"
trans_file_type_str["-c"] = "c"
trans_file_type_str["-b"] = "b"
trans_file_type_str["-s"] = "s"
trans_file_type_str["-l"] = "l"
trans_file_type_str["-p"] = "p"

# the setools policy handle
_pol = None

# cache the lookup results
file_equiv_modified = None
file_equiv = None
local_files = None
fcdict = None
methods = []
all_types = None
all_types_info = None
user_types = None
role_allows = None
portrecs = None
portrecsbynum = None
all_domains = None
roles = None
selinux_user_list = None
login_mappings = None
file_types = None
port_types = None
bools = None
all_attributes = None
booleans = None
booleans_dict = None
all_allow_rules = None
all_transitions = None


def policy_sortkey(policy_path):
    # Parse the extension of a policy path which looks like .../policy/policy.31
    extension = policy_path.rsplit('/policy.', 1)[1]
    try:
        return int(extension), policy_path
    except ValueError:
        # Fallback with sorting on the full path
        return 0, policy_path

def get_installed_policy(root="/"):
    try:
        path = root + selinux.selinux_binary_policy_path()
        policies = glob.glob("%s.*" % path)
        policies.sort(key=policy_sortkey)
        return policies[-1]
    except:
        pass
    raise ValueError(_("No SELinux Policy installed"))

def get_store_policy(store):
    """Get the path to the policy file located in the given store name"""
    policies = glob.glob("%s%s/policy/policy.*" %
                         (selinux.selinux_path(), store))
    if not policies:
        return None
    # Return the policy with the higher version number
    policies.sort(key=policy_sortkey)
    return policies[-1]

def policy(policy_file):
    global all_domains
    global all_attributes
    global bools
    global all_types
    global role_allows
    global users
    global roles
    global file_types
    global port_types
    all_domains = None
    all_attributes = None
    bools = None
    all_types = None
    role_allows = None
    users = None
    roles = None
    file_types = None
    port_types = None
    global _pol

    try:
        _pol = setools.SELinuxPolicy(policy_file)
    except:
        raise ValueError(_("Failed to read %s policy file") % policy_file)

def load_store_policy(store):
    policy_file = get_store_policy(store)
    if not policy_file:
        return None
    policy(policy_file)

try:
    policy_file = get_installed_policy()
    policy(policy_file)
except ValueError as e:
    if selinux.is_selinux_enabled() == 1:
        raise e


def info(setype, name=None):
    if setype == TYPE:
        q = setools.TypeQuery(_pol)
        q.name = name
        results = list(q.results())

        if name and len(results) < 1:
            # type not found, try alias
            q.name = None
            q.alias = name
            results = list(q.results())

        return ({
            'aliases': list(map(str, x.aliases())),
            'name': str(x),
            'permissive': bool(x.ispermissive),
            'attributes': list(map(str, x.attributes()))
        } for x in results)

    elif setype == ROLE:
        q = setools.RoleQuery(_pol)
        if name:
            q.name = name

        return ({
            'name': str(x),
            'roles': list(map(str, x.expand())),
            'types': list(map(str, x.types())),
        } for x in q.results())

    elif setype == ATTRIBUTE:
        q = setools.TypeAttributeQuery(_pol)
        if name:
            q.name = name

        return ({
            'name': str(x),
            'types': list(map(str, x.expand())),
        } for x in q.results())

    elif setype == PORT:
        q = setools.PortconQuery(_pol)
        if name:
            ports = [int(i) for i in name.split("-")]
            if len(ports) == 2:
                q.ports = ports
            elif len(ports) == 1:
                q.ports = (ports[0], ports[0])

        if _pol.mls:
            return ({
                'high': x.ports.high,
                'protocol': str(x.protocol),
                'range': str(x.context.range_),
                'type': str(x.context.type_),
                'low': x.ports.low,
            } for x in q.results())
        return ({
            'high': x.ports.high,
            'protocol': str(x.protocol),
            'type': str(x.context.type_),
            'low': x.ports.low,
        } for x in q.results())

    elif setype == USER:
        q = setools.UserQuery(_pol)
        if name:
            q.name = name

        if _pol.mls:
            return ({
                'range': str(x.mls_range),
                'name': str(x),
                'roles': list(map(str, x.roles)),
                'level': str(x.mls_level),
            } for x in q.results())
        return ({
            'name': str(x),
            'roles': list(map(str, x.roles)),
        } for x in q.results())

    elif setype == BOOLEAN:
        q = setools.BoolQuery(_pol)
        if name:
            q.name = name

        return ({
            'name': str(x),
            'state': x.state,
        } for x in q.results())

    elif setype == TCLASS:
        q = setools.ObjClassQuery(_pol)
        if name:
            q.name = name

        return ({
            'name': str(x),
            'permlist': list(x.perms),
        } for x in q.results())

    else:
        raise ValueError("Invalid type")


def _setools_rule_to_dict(rule):
    d = {
        'type': str(rule.ruletype),
        'source': str(rule.source),
        'target': str(rule.target),
        'class': str(rule.tclass),
    }

    # Evaluate boolean expression associated with given rule (if there is any)
    try:
        # Get state of all booleans in the conditional expression
        boolstate = {}
        for boolean in rule.conditional.booleans:
            boolstate[str(boolean)] = boolean.state
        # evaluate if the rule is enabled
        enabled = rule.conditional.evaluate(**boolstate) == rule.conditional_block
    except AttributeError:
        # non-conditional rules are always enabled
        enabled = True

    d['enabled'] = enabled

    try:
        d['permlist'] = list(map(str, rule.perms))
    except AttributeError:
        pass

    try:
        d['transtype'] = str(rule.default)
    except AttributeError:
        pass

    try:
        d['boolean'] = [(str(rule.conditional), enabled)]
    except AttributeError:
        pass

    try:
        d['filename'] = rule.filename
    except AttributeError:
        pass

    return d


def search(types, seinfo=None):
    if not seinfo:
        seinfo = {}
    valid_types = set([ALLOW, AUDITALLOW, NEVERALLOW, DONTAUDIT, TRANSITION, ROLE_ALLOW])
    for setype in types:
        if setype not in valid_types:
            raise ValueError("Type has to be in %s" % " ".join(valid_types))

    source = None
    if SOURCE in seinfo:
        source = str(seinfo[SOURCE])

    target = None
    if TARGET in seinfo:
        target = str(seinfo[TARGET])

    tclass = None
    if CLASS in seinfo:
        tclass = str(seinfo[CLASS]).split(',')

    toret = []

    tertypes = []
    if ALLOW in types:
        tertypes.append(ALLOW)
    if NEVERALLOW in types:
        tertypes.append(NEVERALLOW)
    if AUDITALLOW in types:
        tertypes.append(AUDITALLOW)
    if DONTAUDIT in types:
        tertypes.append(DONTAUDIT)

    if len(tertypes) > 0:
        q = setools.TERuleQuery(_pol,
                                ruletype=tertypes,
                                source=source,
                                target=target,
                                tclass=tclass)

        if PERMS in seinfo:
            q.perms = seinfo[PERMS]

        toret += [_setools_rule_to_dict(x) for x in q.results()]

    if TRANSITION in types:
        rtypes = ['type_transition', 'type_change', 'type_member']
        q = setools.TERuleQuery(_pol,
                                ruletype=rtypes,
                                source=source,
                                target=target,
                                tclass=tclass)

        if PERMS in seinfo:
            q.perms = seinfo[PERMS]

        toret += [_setools_rule_to_dict(x) for x in q.results()]

    if ROLE_ALLOW in types:
        ratypes = ['allow']
        q = setools.RBACRuleQuery(_pol,
                                  ruletype=ratypes,
                                  source=source,
                                  target=target,
                                  tclass=tclass)

        for r in q.results():
            toret.append({'source': str(r.source),
                          'target': str(r.target)})

    return toret


def get_conditionals(src, dest, tclass, perm):
    tdict = {}
    tlist = []
    src_list = [src]
    dest_list = [dest]
    # add assigned attributes
    try:
        src_list += list(filter(lambda x: x['name'] == src, get_all_types_info()))[0]['attributes']
    except:
        pass
    try:
        dest_list += list(filter(lambda x: x['name'] == dest, get_all_types_info()))[0]['attributes']
    except:
        pass
    allows = map(lambda y: y, filter(lambda x:
                x['source'] in src_list and
                x['target'] in dest_list and
                set(perm).issubset(x[PERMS]) and
                'boolean' in x,
                get_all_allow_rules()))

    try:
        for i in allows:
            tdict.update({'source': i['source'], 'boolean': i['boolean']})
            if tdict not in tlist:
                tlist.append(tdict)
                tdict = {}
    except KeyError:
        return(tlist)

    return (tlist)


def get_conditionals_format_text(cond):

    enabled = False
    for x in cond:
        if x['boolean'][0][1]:
            enabled = True
            break
    return _("-- Allowed %s [ %s ]") % (enabled, " || ".join(set(map(lambda x: "%s=%d" % (x['boolean'][0][0], x['boolean'][0][1]), cond))))


def get_types_from_attribute(attribute):
    return list(info(ATTRIBUTE, attribute))[0]["types"]


def get_file_types(setype):
    flist = []
    mpaths = {}
    for f in get_all_file_types():
        if f.startswith(gen_short_name(setype)):
            flist.append(f)
    fcdict = get_fcdict()
    for f in flist:
        try:
            mpaths[f] = (fcdict[f]["regex"], file_type_str[fcdict[f]["ftype"]])
        except KeyError:
            mpaths[f] = []
    return mpaths


def get_real_type_name(name):
    """Return the real name of a type

    * If 'name' refers to a type alias, return the corresponding type name.
    * Otherwise return the original name (even if the type does not exist).
    """
    if not name:
        return name

    try:
        return next(info(TYPE, name))["name"]
    except (RuntimeError, StopIteration):
        return name

def get_writable_files(setype):
    file_types = get_all_file_types()
    all_writes = []
    mpaths = {}
    permlist = search([ALLOW], {'source': setype, 'permlist': ['open', 'write'], 'class': 'file'})
    if permlist is None or len(permlist) == 0:
        return mpaths

    fcdict = get_fcdict()

    attributes = ["proc_type", "sysctl_type"]
    for i in permlist:
        if i['target'] in attributes:
            continue
        if "enabled" in i:
            if not i["enabled"]:
                continue
        if i['target'].endswith("_t"):
            if i['target'] not in file_types:
                continue
            if i['target'] not in all_writes:
                if i['target'] != setype:
                    all_writes.append(i['target'])
        else:
            for t in get_types_from_attribute(i['target']):
                if t not in all_writes:
                    all_writes.append(t)

    for f in all_writes:
        try:
            mpaths[f] = (fcdict[f]["regex"], file_type_str[fcdict[f]["ftype"]])
        except KeyError:
            mpaths[f] = []  # {"regex":[],"paths":[]}
    return mpaths


def find_file(reg):
    if os.path.exists(reg):
        return [reg]
    try:
        pat = re.compile(r"%s$" % reg)
    except:
        print("bad reg:", reg)
        return []
    p = reg
    if p.endswith("(/.*)?"):
        p = p[:-6] + "/"

    path = os.path.dirname(p)

    try:                       # Bug fix: when "all files on system"
        if path[-1] != "/":    # is pass in it breaks without try block
            path += "/"
    except IndexError:
        print("try failed got an IndexError")

    try:
        pat = re.compile(r"%s$" % reg)
        return [x for x in map(lambda x: path + x, os.listdir(path)) if pat.match(x)]
    except:
        return []


def find_all_files(domain, exclude_list=[]):
    executable_files = get_entrypoints(domain)
    for exe in executable_files.keys():
        if exe.endswith("_exec_t") and exe not in exclude_list:
            for path in executable_files[exe]:
                for f in find_file(path):
                    return f
    return None


def find_entrypoint_path(exe, exclude_list=[]):
    fcdict = get_fcdict()
    try:
        if exe.endswith("_exec_t") and exe not in exclude_list:
            for path in fcdict[exe]["regex"]:
                for f in find_file(path):
                    return f
    except KeyError:
        pass
    return None


def read_file_equiv(edict, fc_path, modify):
    try:
        with open(fc_path, "r") as fd:
            for e in fd:
                f = e.split()
                if f and not f[0].startswith('#'):
                    edict[f[0]] = {"equiv": f[1], "modify": modify}
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise
    return edict


def get_file_equiv_modified(fc_path=selinux.selinux_file_context_path()):
    global file_equiv_modified
    if file_equiv_modified:
        return file_equiv_modified
    file_equiv_modified = {}
    file_equiv_modified = read_file_equiv(file_equiv_modified, fc_path + ".subs", modify=True)
    return file_equiv_modified


def get_file_equiv(fc_path=selinux.selinux_file_context_path()):
    global file_equiv
    if file_equiv:
        return file_equiv
    file_equiv = get_file_equiv_modified(fc_path)
    file_equiv = read_file_equiv(file_equiv, fc_path + ".subs_dist", modify=False)
    return file_equiv


def get_local_file_paths(fc_path=selinux.selinux_file_context_path()):
    global local_files
    if local_files:
        return local_files
    local_files = []
    try:
        with open(fc_path + ".local", "r") as fd:
            fc = fd.readlines()
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise
        return []
    for i in fc:
        rec = i.split()
        if len(rec) == 0:
            continue
        try:
            if len(rec) > 2:
                ftype = trans_file_type_str[rec[1]]
            else:
                ftype = "a"

            local_files.append((rec[0], ftype))
        except KeyError:
            pass
    return local_files


def get_fcdict(fc_path=selinux.selinux_file_context_path()):
    global fcdict
    if fcdict:
        return fcdict
    fd = open(fc_path, "r")
    fc = fd.readlines()
    fd.close()
    fd = open(fc_path + ".homedirs", "r")
    fc += fd.readlines()
    fd.close()
    fcdict = {}
    try:
        with open(fc_path + ".local", "r") as fd:
            fc += fd.readlines()
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise

    for i in fc:
        rec = i.split()
        try:
            if len(rec) > 2:
                ftype = trans_file_type_str[rec[1]]
            else:
                ftype = "a"

            t = rec[-1].split(":")[2]
            if t in fcdict:
                fcdict[t]["regex"].append(rec[0])
            else:
                fcdict[t] = {"regex": [rec[0]], "ftype": ftype}
        except:
            pass

    fcdict["logfile"] = {"regex": ["all log files"]}
    fcdict["user_tmp_type"] = {"regex": ["all user tmp files"]}
    fcdict["user_home_type"] = {"regex": ["all user home files"]}
    fcdict["virt_image_type"] = {"regex": ["all virtual image files"]}
    fcdict["noxattrfs"] = {"regex": ["all files on file systems which do not support extended attributes"]}
    fcdict["sandbox_tmpfs_type"] = {"regex": ["all sandbox content in tmpfs file systems"]}
    fcdict["user_tmpfs_type"] = {"regex": ["all user content in tmpfs file systems"]}
    fcdict["file_type"] = {"regex": ["all files on the system"]}
    fcdict["samba_share_t"] = {"regex": ["use this label for random content that will be shared using samba"]}
    return fcdict


def get_transitions_into(setype):
    try:
        return [x for x in search([TRANSITION], {'class': 'process'}) if x["transtype"] == setype]
    except (TypeError, AttributeError):
        pass
    return None


def get_transitions(setype):
    try:
        return search([TRANSITION], {'source': setype, 'class': 'process'})
    except (TypeError, AttributeError):
        pass
    return None


def get_file_transitions(setype):
    try:
        return [x for x in search([TRANSITION], {'source': setype}) if x['class'] != "process"]
    except (TypeError, AttributeError):
        pass
    return None


def get_boolean_rules(setype, boolean):
    boollist = []
    permlist = search([ALLOW], {'source': setype})
    for p in permlist:
        if "boolean" in p:
            try:
                for b in p["boolean"]:
                    if boolean in b:
                        boollist.append(p)
            except:
                pass
    return boollist


def get_all_entrypoints():
    return get_types_from_attribute("entry_type")


def get_entrypoint_types(setype):
    q = setools.TERuleQuery(_pol,
                            ruletype=[ALLOW],
                            source=setype,
                            tclass=["file"],
                            perms=["entrypoint"])
    return [str(x.target) for x in q.results() if x.source == setype]


def get_init_transtype(path):
    entrypoint = selinux.getfilecon(path)[1].split(":")[2]
    try:
        entrypoints = list(filter(lambda x: x['target'] == entrypoint, search([TRANSITION], {'source': "init_t", 'class': 'process'})))
        return entrypoints[0]["transtype"]
    except (TypeError, AttributeError, IndexError):
        pass
    return None


def get_init_entrypoint(transtype):
    q = setools.TERuleQuery(_pol,
                            ruletype=["type_transition"],
                            source="init_t",
                            tclass=["process"])
    entrypoints = []
    for i in q.results():
        try:
            if i.default == transtype:
                entrypoints.append(i.target)
        except AttributeError:
            continue

    return entrypoints

def get_init_entrypoints_str():
    q = setools.TERuleQuery(_pol,
                            ruletype=["type_transition"],
                            source="init_t",
                            tclass=["process"])
    entrypoints = {}
    for i in q.results():
        try:
            transtype = str(i.default)
            if transtype in entrypoints:
                entrypoints[transtype].append(str(i.target))
            else:
                entrypoints[transtype] = [str(i.target)]
        except AttributeError:
            continue

    return entrypoints

def get_init_entrypoint_target(entrypoint):
    try:
        entrypoints = map(lambda x: x['transtype'], search([TRANSITION], {'source': "init_t", 'target': entrypoint, 'class': 'process'}))
        return list(entrypoints)[0]
    except (TypeError, IndexError):
        pass
    return None


def get_entrypoints(setype):
    fcdict = get_fcdict()
    mpaths = {}
    for f in get_entrypoint_types(setype):
        try:
            mpaths[f] = (fcdict[f]["regex"], file_type_str[fcdict[f]["ftype"]])
        except KeyError:
            mpaths[f] = []
    return mpaths


def get_methods():
    global methods
    if len(methods) > 0:
        return methods
    gen_interfaces()
    fn = defaults.interface_info()
    try:
        fd = open(fn)
    # List of per_role_template interfaces
        ifs = interfaces.InterfaceSet()
        ifs.from_file(fd)
        methods = list(ifs.interfaces.keys())
        fd.close()
    except:
        sys.stderr.write("could not open interface info [%s]\n" % fn)
        sys.exit(1)

    methods.sort()
    return methods


def get_all_types():
    global all_types
    if all_types is None:
        all_types = [x['name'] for x in info(TYPE)]
    return all_types

def get_all_types_info():
    global all_types_info
    if all_types_info is None:
        all_types_info = list(info(TYPE))
    return all_types_info

def get_user_types():
    global user_types
    if user_types is None:
        user_types = list(list(info(ATTRIBUTE, "userdomain"))[0]["types"])
    return user_types


def get_all_role_allows():
    global role_allows
    if role_allows:
        return role_allows
    role_allows = {}

    q = setools.RBACRuleQuery(_pol, ruletype=[ALLOW])
    for r in q.results():
        src = str(r.source)
        tgt = str(r.target)
        if src == "system_r" or tgt == "system_r":
            continue
        if src in role_allows:
            role_allows[src].append(tgt)
        else:
            role_allows[src] = [tgt]

    return role_allows


def get_all_entrypoint_domains():
    import re
    all_domains = []
    types = sorted(get_all_types())
    for i in types:
        m = re.findall("(.*)%s" % "_exec_t$", i)
        if len(m) > 0:
            if len(re.findall("(.*)%s" % "_initrc$", m[0])) == 0 and m[0] not in all_domains:
                all_domains.append(m[0])
    return all_domains


def gen_interfaces():
    try:
        from commands import getstatusoutput
    except ImportError:
        from subprocess import getstatusoutput
    ifile = defaults.interface_info()
    headers = defaults.headers()
    try:
        if os.stat(headers).st_mtime <= os.stat(ifile).st_mtime:
            return
    except OSError:
        pass

    if os.getuid() != 0:
        raise ValueError(_("You must regenerate interface info by running /usr/bin/sepolgen-ifgen"))
    print(getstatusoutput("/usr/bin/sepolgen-ifgen")[1])


def gen_port_dict():
    global portrecs
    global portrecsbynum
    if portrecs:
        return (portrecs, portrecsbynum)
    portrecsbynum = {}
    portrecs = {}
    for i in info(PORT):
        if i['low'] == i['high']:
            port = str(i['low'])
        else:
            port = "%s-%s" % (str(i['low']), str(i['high']))

        if (i['type'], i['protocol']) in portrecs:
            portrecs[(i['type'], i['protocol'])].append(port)
        else:
            portrecs[(i['type'], i['protocol'])] = [port]

        if 'range' in i:
            portrecsbynum[(i['low'], i['high'], i['protocol'])] = (i['type'], i['range'])
        else:
            portrecsbynum[(i['low'], i['high'], i['protocol'])] = (i['type'])

    return (portrecs, portrecsbynum)


def get_all_domains():
    global all_domains
    if not all_domains:
        all_domains = list(list(info(ATTRIBUTE, "domain"))[0]["types"])
    return all_domains


def get_all_roles():
    global roles
    if roles:
        return roles

    q = setools.RoleQuery(_pol)
    roles = [str(x) for x in q.results() if str(x) != "object_r"]
    return roles


def get_selinux_users():
    global selinux_user_list
    if not selinux_user_list:
        selinux_user_list = list(info(USER))
        if _pol.mls:
            for x in selinux_user_list:
                x['range'] = "".join(x['range'].split(" "))
    return selinux_user_list


def get_login_mappings():
    global login_mappings
    if login_mappings:
        return login_mappings

    fd = open(selinux.selinux_usersconf_path(), "r")
    buf = fd.read()
    fd.close()
    login_mappings = []
    for b in buf.split("\n"):
        b = b.strip()
        if len(b) == 0 or b.startswith("#"):
            continue
        x = b.split(":")
        login_mappings.append({"name": x[0], "seuser": x[1], "mls": ":".join(x[2:])})
    return login_mappings


def get_all_users():
    return sorted(map(lambda x: x['name'], get_selinux_users()))


def get_all_file_types():
    global file_types
    if file_types:
        return file_types
    file_types = list(sorted(info(ATTRIBUTE, "file_type"))[0]["types"])
    return file_types


def get_all_port_types():
    global port_types
    if port_types:
        return port_types
    port_types = list(sorted(info(ATTRIBUTE, "port_type"))[0]["types"])
    return port_types


def get_all_bools():
    global bools
    if not bools:
        bools = list(info(BOOLEAN))
    return bools


def prettyprint(f, trim):
    return " ".join(f[:-len(trim)].split("_"))


def markup(f):
    return f


def get_description(f, markup=markup):

    txt = "Set files with the %s type, if you want to " % markup(f)

    if f.endswith("_var_run_t"):
        return txt + "store the %s files under the /run or /var/run directory." % prettyprint(f, "_var_run_t")
    if f.endswith("_pid_t"):
        return txt + "store the %s files under the /run directory." % prettyprint(f, "_pid_t")
    if f.endswith("_var_lib_t"):
        return txt + "store the %s files under the /var/lib directory." % prettyprint(f, "_var_lib_t")
    if f.endswith("_var_t"):
        return txt + "store the %s files under the /var directory." % prettyprint(f, "_var_lib_t")
    if f.endswith("_var_spool_t"):
        return txt + "store the %s files under the /var/spool directory." % prettyprint(f, "_spool_t")
    if f.endswith("_spool_t"):
        return txt + "store the %s files under the /var/spool directory." % prettyprint(f, "_spool_t")
    if f.endswith("_cache_t") or f.endswith("_var_cache_t"):
        return txt + "store the files under the /var/cache directory."
    if f.endswith("_keytab_t"):
        return txt + "treat the files as kerberos keytab files."
    if f.endswith("_lock_t"):
        return txt + "treat the files as %s lock data, stored under the /var/lock directory" % prettyprint(f, "_lock_t")
    if f.endswith("_log_t"):
        return txt + "treat the data as %s log data, usually stored under the /var/log directory." % prettyprint(f, "_log_t")
    if f.endswith("_config_t"):
        return txt + "treat the files as %s configuration data, usually stored under the /etc directory." % prettyprint(f, "_config_t")
    if f.endswith("_conf_t"):
        return txt + "treat the files as %s configuration data, usually stored under the /etc directory." % prettyprint(f, "_conf_t")
    if f.endswith("_exec_t"):
        return txt + "transition an executable to the %s_t domain." % f[:-len("_exec_t")]
    if f.endswith("_cgi_content_t"):
        return txt + "treat the files as %s cgi content." % prettyprint(f, "_cgi_content_t")
    if f.endswith("_rw_content_t"):
        return txt + "treat the files as %s read/write content." % prettyprint(f, "_rw_content_t")
    if f.endswith("_rw_t"):
        return txt + "treat the files as %s read/write content." % prettyprint(f, "_rw_t")
    if f.endswith("_write_t"):
        return txt + "treat the files as %s read/write content." % prettyprint(f, "_write_t")
    if f.endswith("_db_t"):
        return txt + "treat the files as %s database content." % prettyprint(f, "_db_t")
    if f.endswith("_ra_content_t"):
        return txt + "treat the files as %s read/append content." % prettyprint(f, "_ra_content_t")
    if f.endswith("_cert_t"):
        return txt + "treat the files as %s certificate data." % prettyprint(f, "_cert_t")
    if f.endswith("_key_t"):
        return txt + "treat the files as %s key data." % prettyprint(f, "_key_t")

    if f.endswith("_secret_t"):
        return txt + "treat the files as %s secret data." % prettyprint(f, "_key_t")

    if f.endswith("_ra_t"):
        return txt + "treat the files as %s read/append content." % prettyprint(f, "_ra_t")

    if f.endswith("_ro_t"):
        return txt + "treat the files as %s read/only content." % prettyprint(f, "_ro_t")

    if f.endswith("_modules_t"):
        return txt + "treat the files as %s modules." % prettyprint(f, "_modules_t")

    if f.endswith("_content_t"):
        return txt + "treat the files as %s content." % prettyprint(f, "_content_t")

    if f.endswith("_state_t"):
        return txt + "treat the files as %s state data." % prettyprint(f, "_state_t")

    if f.endswith("_files_t"):
        return txt + "treat the files as %s content." % prettyprint(f, "_files_t")

    if f.endswith("_file_t"):
        return txt + "treat the files as %s content." % prettyprint(f, "_file_t")

    if f.endswith("_data_t"):
        return txt + "treat the files as %s content." % prettyprint(f, "_data_t")

    if f.endswith("_file_t"):
        return txt + "treat the data as %s content." % prettyprint(f, "_file_t")

    if f.endswith("_tmp_t"):
        return txt + "store %s temporary files in the /tmp directories." % prettyprint(f, "_tmp_t")
    if f.endswith("_etc_t"):
        return txt + "store %s files in the /etc directories." % prettyprint(f, "_tmp_t")
    if f.endswith("_home_t"):
        return txt + "store %s files in the users home directory." % prettyprint(f, "_home_t")
    if f.endswith("_tmpfs_t"):
        return txt + "store %s files on a tmpfs file system." % prettyprint(f, "_tmpfs_t")
    if f.endswith("_unit_file_t"):
        return txt + "treat files as a systemd unit file."
    if f.endswith("_htaccess_t"):
        return txt + "treat the file as a %s access file." % prettyprint(f, "_htaccess_t")

    return txt + "treat the files as %s data." % prettyprint(f, "_t")


def get_all_attributes():
    global all_attributes
    if not all_attributes:
        all_attributes = list(sorted(map(lambda x: x['name'], info(ATTRIBUTE))))
    return all_attributes


def _dict_has_perms(dict, perms):
    for perm in perms:
        if perm not in dict[PERMS]:
            return False
    return True


def gen_short_name(setype):
    all_domains = get_all_domains()
    if setype.endswith("_t"):
        # replace aliases with corresponding types
        setype = get_real_type_name(setype)
        domainname = setype[:-2]
    else:
        domainname = setype
    if domainname + "_t" not in all_domains:
        raise ValueError("domain %s_t does not exist" % domainname)
    if domainname[-1] == 'd':
        short_name = domainname[:-1] + "_"
    else:
        short_name = domainname + "_"
    return (domainname, short_name)

def get_all_allow_rules():
    global all_allow_rules
    if not all_allow_rules:
        all_allow_rules = search([ALLOW])
    return all_allow_rules

def get_all_transitions():
    global all_transitions
    if not all_transitions:
        all_transitions = list(search([TRANSITION]))
    return all_transitions

def get_bools(setype):
    bools = []
    domainbools = []
    domainname, short_name = gen_short_name(setype)
    for i in map(lambda x: x['boolean'], filter(lambda x: 'boolean' in x and x['source'] == setype, get_all_allow_rules())):
        for b in i:
            if not isinstance(b, tuple):
                continue
            try:
                enabled = selinux.security_get_boolean_active(b[0])
            except OSError:
                enabled = b[1]
            if b[0].startswith(short_name) or b[0].startswith(domainname):
                if (b[0], enabled) not in domainbools and (b[0], not enabled) not in domainbools:
                    domainbools.append((b[0], enabled))
            else:
                if (b[0], enabled) not in bools and (b[0], not enabled) not in bools:
                    bools.append((b[0], enabled))
    return (domainbools, bools)


def get_all_booleans():
    global booleans
    if not booleans:
        booleans = selinux.security_get_boolean_names()[1]
    return booleans


def policy_xml(path="/usr/share/selinux/devel/policy.xml"):
    try:
        fd = gzip.open(path)
        buf = fd.read()
        fd.close()
    except IOError:
        fd = open(path)
        buf = fd.read()
        fd.close()
    return buf


def gen_bool_dict(path="/usr/share/selinux/devel/policy.xml"):
    global booleans_dict
    if booleans_dict:
        return booleans_dict
    import xml.etree.ElementTree
    booleans_dict = {}
    try:
        tree = xml.etree.ElementTree.fromstring(policy_xml(path))
        for l in tree.findall("layer"):
            for m in l.findall("module"):
                for b in m.findall("tunable"):
                    desc = b.find("desc").find("p").text.strip("\n")
                    desc = re.sub("\n", " ", desc)
                    booleans_dict[b.get('name')] = (m.get("name"), b.get('dftval'), desc)
                for b in m.findall("bool"):
                    desc = b.find("desc").find("p").text.strip("\n")
                    desc = re.sub("\n", " ", desc)
                    booleans_dict[b.get('name')] = (m.get("name"), b.get('dftval'), desc)
            for i in tree.findall("bool"):
                desc = i.find("desc").find("p").text.strip("\n")
                desc = re.sub("\n", " ", desc)
                booleans_dict[i.get('name')] = ("global", i.get('dftval'), desc)
        for i in tree.findall("tunable"):
            desc = i.find("desc").find("p").text.strip("\n")
            desc = re.sub("\n", " ", desc)
            booleans_dict[i.get('name')] = ("global", i.get('dftval'), desc)
    except IOError:
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
        try:
            from commands import getstatusoutput
        except ImportError:
            from subprocess import getstatusoutput
        rc, output = getstatusoutput("rpm -q '%s'" % pkg_name)
        if rc == 0:
            os_version = output.split(".")[-2]
    except:
        os_version = ""

    if os_version[0:2] == "fc":
        os_version = "Fedora" + os_version[2:]
    elif os_version[0:2] == "el":
        os_version = "RHEL" + os_version[2:]
    else:
        os_version = ""

    return os_version


def reinit():
    global all_attributes
    global all_domains
    global all_types
    global booleans
    global booleans_dict
    global bools
    global fcdict
    global file_types
    global local_files
    global methods
    global methods
    global portrecs
    global portrecsbynum
    global port_types
    global role_allows
    global roles
    global login_mappings
    global selinux_user_list
    global user_types
    all_attributes = None
    all_domains = None
    all_types = None
    booleans = None
    booleans_dict = None
    bools = None
    fcdict = None
    file_types = None
    local_files = None
    methods = None
    methods = None
    portrecs = None
    portrecsbynum = None
    port_types = None
    role_allows = None
    roles = None
    user_types = None
    login_mappings = None
    selinux_user_list = None
