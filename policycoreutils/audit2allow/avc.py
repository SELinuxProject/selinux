#! /usr/bin/python -E
# Copyright (C) 2006 Red Hat 
# see file 'COPYING' for use and warranty information
#
# avc.py is a plugin modules used by audit2allow and other objects to process
# avc messages from the log files
#
# Based off original audit2allow perl script: which credits
#    newrules.pl, Copyright (C) 2001 Justin R. Smith (jsmith@mcs.drexel.edu)
#    2003 Oct 11: Add -l option by Yuichi Nakamura(ynakam@users.sourceforge.jp)
#
#    This program is free software; you can redistribute it and/or
#    modify it under the terms of the GNU General Public License as
#    published by the Free Software Foundation; either version 2 of
#    the License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA     
#                                        02111-1307  USA
#
#  
import sys, os, pwd, string, re, selinux

obj = "(\{[^\}]*\}|[^ \t:]*)"
allow_regexp = "(allow|dontaudit)[ \t]+%s[ \t]*%s[ \t]*:[ \t]*%s[ \t]*%s" % (obj, obj, obj, obj)
awk_script = '/^[[:blank:]]*interface[[:blank:]]*\(/ {\n\
        IFACEFILE=FILENAME\n\
	IFACENAME = gensub("^[[:blank:]]*interface[[:blank:]]*\\\\(\`?","","g",$0);\n\
	IFACENAME = gensub("\'?,.*$","","g",IFACENAME);\n\
}\n\
\n\
/^[[:blank:]]*(allow|dontaudit)[[:blank:]]+.*;[[:blank:]]*$/ {\n\
\n\
  if ((length(IFACENAME) > 0) && (IFACEFILE == FILENAME)){\n\
		ALLOW = gensub("^[[:blank:]]*","","g",$0)\n\
		ALLOW = gensub(";[[:blank:]]*$","","g",$0)\n\
		print FILENAME "\\t" IFACENAME "\\t" ALLOW;\n\
	}\n\
}\
'

class context:
    def __init__(self, scontext):
        self.scontext = scontext
        con=scontext.split(":")
        self.user = con[0]
        self.role = con[1]
        self.type = con[2]
        if len(con) > 3:
            self.mls = con[3]
        else:
            self.mls = "s0"
        
    def __str__(self):
        return self.scontext

class accessTrans:
    def __init__(self):
        self.dict = {}
	try:
		fd = open("/usr/share/selinux/devel/include/support/obj_perm_sets.spt")
	except IOError, error:
		raise IOError("Reference policy generation requires the policy development package selinux-policy-devel.\n%s" % error)
        records = fd.read().split("\n")
        regexp = "^define *\(`([^']*)' *, *` *\{([^}]*)}'"
        for r in records:
            m = re.match(regexp,r)
            if m != None:
                self.dict[m.groups()[0]] = m.groups()[1].split()
        fd.close()
    def get(self, var):
        l = []
        for v in var:
            if v in self.dict.keys():
                l += self.dict[v]
            else:
                if v not in ("{", "}"):
                    l.append(v)
        return l

class interfaces:
    def __init__(self):
        self.dict = {}
        trans = accessTrans()
	(input, output) = os.popen2("awk -f - /usr/share/selinux/devel/include/*/*.if 2> /dev/null")
	input.write(awk_script)
	input.close()
	records = output.read().split("\n")
	input.close()
        if len(records) > 0:
            regexp = "([^ \t]*)[ \t]+([^ \t]*)[ \t]+%s" % allow_regexp
            for r in records:
                m = re.match(regexp,r)
                if m == None:
                    continue
                val = m.groups()
                file = os.path.basename(val[0]).split(".")[0]
                iface = val[1]
                Scon = val[3].split()
                Tcon = val[4].split()
                Class = val[5].split()
                Access = trans.get(val[6].split())
                for s in Scon:
                    for t in Tcon:
                        for c in Class:
                            if (s, t, c) not in self.dict.keys():
                                self.dict[(s, t, c)] = []
                            self.dict[(s, t, c)].append((Access, file, iface))
    def out(self):
        keys = self.dict.keys()
        keys.sort()
        for k in keys:
            print k
            for i in self.dict[k]:
                print "\t", i
                
    def match(self, Scon, Tcon, Class, Access):
        keys = self.dict.keys()
        ret = []
        if (Scon, Tcon, Class) in keys:
            for i in self.dict[(Scon, Tcon, Class)]:
                if Access in i[0]:
                    if i[2].find(Access) >= 0:
                        ret.insert(0, i)
                    else:
                        ret.append(i)
            return ret
        if ("$1", Tcon, Class) in keys:
            for i in self.dict[("$1", Tcon, Class)]:
                if Access in i[0]:
                    if i[2].find(Access) >= 0:
                        ret.insert(0, i)
                    else:
                        ret.append(i)
            return ret
        if (Scon, "$1", Class) in keys:
            for i in self.dict[(Scon, "$1", Class)]:
                if Access in i[0]:
                    if i[2].find(Access) >= 0:
                        ret.insert(0, i)
                    else:
                        ret.append(i)
            return ret
        else:
            return ret

import glob, imp
pluginPath = "/usr/share/selinux/plugins" 
if not pluginPath in sys.path:
    sys.path.append(pluginPath)

class Analyze:
	def __init__(self):
            self.plugins = []
            for p in glob.glob("/usr/share/selinux/plugins/*.py"):
                plugin = os.path.basename(p)[:-3]
                self.plugins.append(imp.load_module(plugin, *imp.find_module(plugin)))
                
        def process(self, AVCS):
            ret = []
            avcs = AVCS
            for p in self.plugins:
                if avcs == None:
                    break;
                r = p.analyze(avcs)
                if len(r) == 0:
                    continue
                avcs = r[1]
                if len(r[0]) > 0:
                    ret.append(r[0])
            return ret
                
class serule:
	def __init__(self, key):
		self.type = key[0]
		self.source = key[1]
		self.target = key[2]
		self.seclass = key[3]
                self.access = []
		self.avcinfo = {}
		self.iface = None
		
	def add(self, avc):
		for a in avc[0]:
			if a not in self.avcinfo.keys():
				self.avcinfo[a] = []
                                self.access.append(a)
			self.avcinfo[a].append(avc[1:])

	def getAccess(self):
		if len(self.access) == 1:
                        return self.access[0]
		else:
                        self.access.sort()
			return "{ " + string.join(self.access) +" }"

	def getName(self):
            print self.avcinfo
                    
	def out(self, verbose = 0):
		ret = ""
		ret = ret+"%s %s %s:%s %s;" % (self.type, self.source, self.gettarget(), self.seclass, self.getAccess())
		if verbose:
			keys = self.avcinfo.keys()
			keys.sort()
			for i in keys:
				for x in self.avcinfo[i]:
					ret = ret+"\n\t#TYPE=AVC  MSG=%s  " % x[0]
					if len(x[1]):
						ret=ret+"COMM=%s  " % x[1]
					if len(x[2]):
						ret=ret+"NAME=%s  " % x[2]
					ret = ret + " : " + i 
		return ret
		
	def gen_reference_policy(self, iface):
		ret = ""
		Scon = self.source
		Tcon = self.gettarget()
		Class = self.seclass
		Access = self.getAccess()
		m = iface.match(Scon,Tcon,Class,Access)
		if len(m) == 0:
			return self.out()
		else:
			file = m[0][1]
			ret = "\n#%s\n"% self.out()
			ret += "optional_policy(`\n" 
			first = True
			for i in m:
				if file != i[1]:
					ret += "')\ngen_require(`%s', `\n" % i[1]
					file = i[1]
					first = True
				if first:
					ret += "\t%s(%s)\n" % (i[2], Scon)
					first = False
				else:
					ret += "#\t%s(%s)\n" % (i[2], Scon)
			ret += "');"
		return ret
		
	def gettarget(self):
		if self.source == self.target:
			return "self"
		else:
			return self.target

def warning(error):
    sys.stderr.write("%s: " % sys.argv[0])
    sys.stderr.write("%s\n" % error)
    sys.stderr.flush()


class TERules:
	def __init__(self, serules):
		self.VALID_CMDS = ("allow", "dontaudit", "auditallow")
                self.serules = serules

        def load(self, input):
		line = input.readline()
                while line:
                    rec = line.split()
                    if len(rec) and rec[0] in self.VALID_CMDS:
                        self.add_terule(line)
                    line = input.readline()

	def add_terule(self, rule):
		rc = rule.split(":")
		rules = rc[0].split()
		type = rules[0]
		(sources, targets) = self.rules_split(rules[1:])
		rules = rc[1].split()
		(classes, access) = self.rules_split(rules)
		for scon in sources:
			for tcon in targets:
				for seclass in classes:
					self.serules.add_rule(type, scon, tcon, seclass,access)
		
	def rules_split(self, rules):
		(idx, target ) = self.get_target(0, rules)
		(idx, subject) = self.get_target(idx, rules)
		return (target, subject)

	def get_target(self, i, rule):
		target = []
		if rule[i][0] == "{":
			for t in rule[i].split("{"):
				if len(t):
					target.append(t)
			i = i+1
			for s in rule[i:]:
				if s.find("}") >= 0:
					for s1 in s.split("}"):
						if len(s1):
							target.append(s1)
						i = i+1
						return (i, target)

				target.append(s)
				i = i+1
		else:
			if rule[i].find(";") >= 0:
				for s1 in rule[i].split(";"):
					if len(s1):
						target.append(s1)
			else:
				target.append(rule[i])

		i = i+1
		return (i, target)


ALLOW = 0
STYPE = 1
TTYPE = 2
CLASS = 3
COMM = 1
NAME = 3

class SERules:
	def __init__(self, last_reload = 0, verbose = 0):
		self.last_reload = last_reload
                self.initialize()
		self.gen_ref_policy = False
		self.verbose = verbose
                self.AVCS = []
                self.INVALID_SIDS = {}

        def initialize(self):
       		self.seRules = {}
		self.classes = {}
		self.types = []
		self.roles = []

	def load(self, input):
		dict = []
		found = 0
		line = input.readline()
                while line:
                    rec = line.split()
                    for i in rec:
                        if i == "avc:" or i == "message=avc:" or i == "msg='avc:":
                            found = 1
                        else:
                            if i == "security_compute_sid:":
                                self.security_compute_sid(rec)
                                found = 1
                            elif i == "type=MAC_POLICY_LOAD" and self.last_reload:
                                self.initialize()
                                break
                            else:
                                dict.append(i)
                                
                    if not found:
                        regexp = "audit\(\d+\.\d+:\d+\): policy loaded"
                        m = re.match(regexp, line)
                        if m !=None:
                            found =1
                            dict.append("load_policy")
                            dict.append("granted")
                        
                    if found:
                        self.translate(dict)
                        found = 0
                        dict = []
                    line = input.readline()
				

        def translate(self,dict):
                AVC = {}
		AVC["access"] = []
		if "load_policy" in dict and self.last_reload:
                        self.initialize()

		if "granted" in dict:
			return
		try:
			for i in range (0, len(dict)):
				if dict[i] == "{":
					i = i+1
					while i<len(dict) and dict[i] != "}":
						AVC["access"].append(dict[i])
						i = i+1
					continue
			
				t = dict[i].split('=')
				if len(t) < 2:
					continue
                                AVC[t[0]] = t[1]

                        for i in ("scontext", "tcontext", "tclass"):
                            if i not in AVC.keys():
                                return
                        if len(AVC["access"]) == 0:
                                return
                            
		except IndexError, e:
			warning("Bad AVC Line: %s" % avc)
			return
			
		self.add_allow(AVC)

        def security_compute_sid(self, rec):
            dict={}
            for i in rec:
                t = i.split('=')
                if len(t) < 2:
                    continue
                dict[t[0]]=t[1]
            try:
                r = context(dict["scontext"]).role
                t = context(dict["tcontext"]).type
		self.add_type(t)
		self.add_role(r)
                self.INVALID_SIDS[(r,t)]=rec
            except:
                return

        def add_avc(self, AVC):
            for a in self.AVCS:
                if a["tclass"] == AVC["tclass"] and a["access"] == AVC["access"] and a["tcontext"] == AVC["tcontext"] and a["scontext"] == AVC["scontext"] and a["comm"] == AVC["comm"] and a["name"] == AVC["name"]:
                    return
            self.AVCS.append(AVC)
                
	def add_rule(self, rule_type, scon, tcon, tclass, access, msg = "", comm = "", name = ""):
                AVC = {}
                AVC["tclass"] = tclass
                AVC["access"] = access
                AVC["tcon"] = tcon
                AVC["scon"] = scon
                AVC["comm"] = comm
                AVC["name"] = name
                self.add_avc(AVC)

		self.add_class(tclass, access)
		self.add_type(tcon)
		self.add_type(scon)
                key = (rule_type, scon, tcon, seclass)
		if key not in self.seRules.keys():
			self.seRules[key] = serule(key)
		self.seRules[key].add((access, msg, comm, name ))

	def add_allow(self, AVC):
		self.add_class(AVC["tclass"], AVC["access"])
                tcontext = context(AVC["tcontext"])
                scontext = context(AVC["scontext"])

		self.add_type(tcontext.type)
		self.add_type(scontext.type)

		self.add_role(scontext.role)

                key = ("allow", scontext.type, tcontext.type, AVC["tclass"])
		if key not in self.seRules.keys():
			self.seRules[key] = serule(key)

                avckeys = AVC.keys()
	        for i in ( "name", "comm", "msg" ):
 	               if i not in avckeys:
        	            AVC[i] = ""

                self.add_avc(AVC)
                self.seRules[key].add((AVC["access"], AVC["msg"], AVC["comm"], AVC["name"]))

        def add_class(self,seclass, access):
		if seclass not in self.classes.keys():
				self.classes[seclass] = []
		for a in access:
			if a not in self.classes[seclass]:
				self.classes[seclass].append(a)
				
	def add_role(self,role):
		if role not in self.roles:
				self.roles.append(role)

	def add_type(self,type):
		if type not in self.types:
				self.types.append(type)

	def gen_reference_policy(self):
		self.gen_ref_policy = True
		self.iface = interfaces()

	def gen_module(self, module):
            if self.gen_ref_policy:
		return "policy_module(%s, 1.0);" % module
            else:
		return "module %s 1.0;" % module

	def gen_requires(self):
		self.roles.sort()
		self.types.sort()
		keys = self.classes.keys()
		keys.sort()
		rec = "\n\nrequire {\n"
                if not self.gen_ref_policy:
                    for i in keys:
			access = self.classes[i]
			if len(access) > 1:
				access.sort()
				rec += "\tclass %s {" % i
				for a in access:
					rec += " %s" % a
				rec += " }; \n"
			else:
				rec += "\tclass %s %s;\n" % (i, access[0])
				
		for i in self.types:
			rec += "\ttype %s; \n" % i

                if not self.gen_ref_policy:
                    for i in self.roles:
			rec += "\trole %s; \n" % i

		rec += "};\n\n"
		return rec
	
	def analyze(self):
            a = Analyze()
            for i in a.process(self.AVCS):
                print i[0][0]
                print ""
                
	def out(self, require = 0, module = ""):
		rec = ""
		if len(self.seRules.keys()) == 0 and len(self.INVALID_SIDS) == 0:
		       raise(ValueError("No AVC messages found."))
		if module != "":
			rec += self.gen_module(module)
			rec += self.gen_requires()
		else:
			if require:
				rec+=self.gen_requires()

                for i in self.INVALID_SIDS.keys():
                    rec += "role %s types %s;\n" % i
                    
		keys = self.seRules.keys()
		keys.sort()
		for i in keys:
			if self.gen_ref_policy:
				rec += self.seRules[i].gen_reference_policy(self.iface)+"\n"
			else:
				rec += self.seRules[i].out(self.verbose)+"\n"
		return rec

