#!/usr/bin/python
import sys
import getopt
import semanage

usage = "\
Choose one of the following tests:\n\
-m for modules\n\
-u for users\n\
-U for add user (warning this will write!)\n\
-s for seusers\n\
-S for add seuser (warning this will write!)\n\
-p for ports\n\
-P for add port (warning this will write!)\n\
-f for file contexts \n\
-F for add file context (warning this will write!)\n\
-i for network interfaces \n\
-I for add network interface (warning this will write!)\n\
-b for booleans \n\
-B for add boolean (warning this will write!)\n\
-c for aCtive booleans\n\
-C for set aCtive boolean (warning this will write!)\n\n\
-n for network nodes\n\
-N for add node (warning this will write!)\n\n\
Other options:\n\
-h for this help\n\
-v for verbose output\
"

class Usage(Exception):
	def __init__(self, msg):
		Exception.__init__(self)
        	self.msg = msg

class Status(Exception):
	def __init__(self, msg):
		Exception.__init__(self)
		self.msg = msg

class Error(Exception):
	def __init__(self, msg):
		Exception.__init__(self)
		self.msg = msg

class Tests:
	def __init__(self):
        	self.all = False
		self.users = False
		self.writeuser = False
		self.seusers = False
		self.writeseuser = False
		self.ports = False
		self.writeport = False
		self.fcontexts = False
		self.writefcontext = False
		self.interfaces = False
		self.writeinterface = False
		self.booleans = False
		self.writeboolean = False
		self.abooleans = False
		self.writeaboolean = False
		self.nodes = False
		self.writenode = False
		self.modules = False
		self.verbose = False

	def selected(self):
		return (self.all or self.users or self.modules or self.seusers or self.ports or self.fcontexts or self.interfaces or self.booleans or self.abooleans or self.writeuser or self.writeseuser or self.writeport or self.writefcontext or self.writeinterface or self.writeboolean or self.writeaboolean or self.nodes or self.writenode)

	def run(self, handle):
		if (self.users or self.all): 
			self.test_users(handle)
			print ""
		if (self.seusers or self.all): 
			self.test_seusers(handle)
			print ""
		if (self.ports or self.all):
			self.test_ports(handle)
			print ""
		if (self.modules or self.all): 
			self.test_modules(handle)
			print ""
		if (self.fcontexts or self.all):
			self.test_fcontexts(handle)
			print ""
		if (self.interfaces or self.all):
			self.test_interfaces(handle)
			print ""
		if (self.booleans or self.all):
			self.test_booleans(handle)
			print ""
		if (self.abooleans or self.all):
			self.test_abooleans(handle)
			print ""
		if (self.nodes or self.all):
			self.test_nodes(handle)
			print ""
		if (self.writeuser or self.all): 
			self.test_writeuser(handle)
			print ""
		if (self.writeseuser or self.all): 
			self.test_writeseuser(handle)
			print ""
		if (self.writeport or self.all):
			self.test_writeport(handle)
			print ""
		if (self.writefcontext or self.all):
			self.test_writefcontext(handle)
			print ""
		if (self.writeinterface or self.all):
			self.test_writeinterface(handle)
			print ""
		if (self.writeboolean or self.all):
			self.test_writeboolean(handle)
			print ""
		if (self.writeaboolean or self.all):
			self.test_writeaboolean(handle)
			print ""
		if (self.writenode or self.all):
			self.test_writenode(handle)
			print ""

	def test_modules(self,sh):
		print "Testing modules..."

		(trans_cnt, mlist, mlist_size) = semanage.semanage_module_list(sh)

		print "Transaction number: ", trans_cnt
		print "Module list size: ", mlist_size
		if self.verbose: print "List reference: ", mlist

		if (mlist_size == 0):
			print "No modules installed!"
			print "This is not necessarily a test failure."
			return
		for idx in range(mlist_size):
			module = semanage.semanage_module_list_nth(mlist, idx)
			if self.verbose: print "Module reference: ", module
			print "Module name: ", semanage.semanage_module_get_name(module)

	def test_seusers(self,sh):
		print "Testing seusers..."

		(status, slist) = semanage.semanage_seuser_list(sh)
		if status < 0:
			raise Error("Could not list seusers")
		print "Query status (commit number): ", status

		if ( len(slist) == 0):
			print "No seusers found!"
			print "This is not necessarily a test failure."
			return
		for seuser in slist:
			if self.verbose: print "seseuser reference: ", seuser 
			print "seuser name: ", semanage.semanage_seuser_get_name(seuser)
			print "   seuser mls range: ", semanage.semanage_seuser_get_mlsrange(seuser)
			print "   seuser sename: ", semanage.semanage_seuser_get_sename(seuser)
			semanage.semanage_seuser_free(seuser)		

	def test_users(self,sh):
		print "Testing users..."

		(status, ulist) = semanage.semanage_user_list(sh)
		if status < 0:
			raise Error("Could not list users")
		print "Query status (commit number): ", status

		if ( len(ulist) == 0):
			print "No users found!"
			print "This is not necessarily a test failure."
			return
		for user in ulist:
			if self.verbose: print "User reference: ", user 
			print "User name: ", semanage.semanage_user_get_name(user)
			print "   User labeling prefix: ", semanage.semanage_user_get_prefix(user)
			print "   User mls level: ", semanage.semanage_user_get_mlslevel(user)
			print "   User mls range: ", semanage.semanage_user_get_mlsrange(user)
			print "   User number of roles: ", semanage.semanage_user_get_num_roles(user)
			print "   User roles: "
			(status, rlist) = semanage.semanage_user_get_roles(sh, user)
			if status < 0:
				raise Error("Could not get user roles")
				
			for role in rlist:
				print "      ", role

			semanage.semanage_user_free(user)

	def test_ports(self,sh):
		print "Testing ports..."

		(status, plist) = semanage.semanage_port_list(sh)
		if status < 0:
			raise Error("Could not list ports")
		print "Query status (commit number): ", status

		if ( len(plist) == 0):
			print "No ports found!"
			print "This is not necessarily a test failure."
			return
		for port in plist:
			if self.verbose: print "Port reference: ", port
			low = semanage.semanage_port_get_low(port)
			high = semanage.semanage_port_get_high(port)
			con = semanage.semanage_port_get_con(port)
			proto = semanage.semanage_port_get_proto(port)
			proto_str = semanage.semanage_port_get_proto_str(proto)
			if low == high:
				range_str = str(low)
			else:
				range_str = str(low) + "-" + str(high)
			(rc, con_str) = semanage.semanage_context_to_string(sh,con)
			if rc < 0: con_str = ""
			print "Port: ", range_str, " ", proto_str, " Context: ", con_str
			semanage.semanage_port_free(port)

	def test_fcontexts(self,sh):
		print "Testing file contexts..."

		(status, flist) = semanage.semanage_fcontext_list(sh)
		if status < 0:
			raise Error("Could not list file contexts")
		print "Query status (commit number): ", status

		if (len(flist) == 0):
			print "No file contexts found!"
			print "This is not necessarily a test failure."
			return
		for fcon in flist:
			if self.verbose: print "File Context reference: ", fcon
			expr = semanage.semanage_fcontext_get_expr(fcon)
			type = semanage.semanage_fcontext_get_type(fcon)
			type_str = semanage.semanage_fcontext_get_type_str(type)
			con = semanage.semanage_fcontext_get_con(fcon)
			if not con: 
				con_str = "<<none>>"
			else:
				(rc, con_str) = semanage.semanage_context_to_string(sh,con)
				if rc < 0: con_str = ""
			print "File Expr: ", expr, " [", type_str, "] Context: ", con_str
			semanage.semanage_fcontext_free(fcon)

	def test_interfaces(self,sh):
		print "Testing network interfaces..."

		(status, ilist) = semanage.semanage_iface_list(sh)
		if status < 0:
			raise Error("Could not list interfaces")
		print "Query status (commit number): ", status

		if (len(ilist) == 0):
			print "No network interfaces found!"
			print "This is not necessarily a test failure."
			return
		for iface in ilist:
			if self.verbose: print "Interface reference: ", iface
			name = semanage.semanage_iface_get_name(iface)
			msg_con = semanage.semanage_iface_get_msgcon(iface)
			if_con = semanage.semanage_iface_get_ifcon(iface)
			(rc, msg_con_str) = semanage.semanage_context_to_string(sh,msg_con)
			if rc < 0: msg_con_str = ""
			(rc, if_con_str) = semanage.semanage_context_to_string(sh, if_con)
			if rc < 0: if_con_str = ""
			print "Interface: ", name, " Context: ", if_con_str, " Message Context: ", msg_con_str
			semanage.semanage_iface_free(iface)

	def test_booleans(self,sh):
		print "Testing booleans..."

		(status, blist) = semanage.semanage_bool_list(sh)
		if status < 0:
			raise Error("Could not list booleans")
		print "Query status (commit number): ", status

		if (len(blist) == 0):
			print "No booleans found!"
			print "This is not necessarily a test failure."
			return
		for pbool in blist:
			if self.verbose: print "Boolean reference: ", pbool
			name = semanage.semanage_bool_get_name(pbool)
			value = semanage.semanage_bool_get_value(pbool)	
			print "Boolean: ", name, " Value: ", value
			semanage.semanage_bool_free(pbool)

	def test_abooleans(self,sh):
		print "Testing active booleans..."

		(status, ablist) = semanage.semanage_bool_list_active(sh)
		if status < 0:
			raise Error("Could not list active booleans")
		print "Query status (commit number): ", status

		if (len(ablist) == 0):
                        print "No active booleans found!"
			print "This is not necessarily a test failure."
			return
		for abool in ablist:
			if self.verbose: print "Active boolean reference: ", abool
			name = semanage.semanage_bool_get_name(abool)
			value = semanage.semanage_bool_get_value(abool)
			print "Active Boolean: ", name, " Value: ", value
			semanage.semanage_bool_free(abool)

	def test_nodes(self,sh):
		print "Testing network nodes..."

		(status, nlist) = semanage.semanage_node_list(sh)
		if status < 0:
			raise Error("Could not list network nodes")
		print "Query status (commit number): ", status

		if (len(nlist) == 0):
			print "No network nodes found!"
			print "This is not necessarily a test failure."
			return
		for node in nlist:
			if self.verbose: print "Network node reference: ", node

			(status, addr) = semanage.semanage_node_get_addr(sh, node)
			if status < 0: addr = ""

			(status, mask) = semanage.semanage_node_get_mask(sh, node)
			if status < 0: mask = ""

			proto = semanage.semanage_node_get_proto(node)
			proto_str = semanage.semanage_node_get_proto_str(proto)		
			con = semanage.semanage_node_get_con(node)

			(status, con_str) = semanage.semanage_context_to_string(sh, con)
			if status < 0: con_str = ""

			print "Network Node: ", addr, "/", mask, " (", proto_str, ")", "Context: ", con_str
			semanage.semanage_node_free(node)

	def test_writeuser(self,sh):
		print "Testing user write..."

		(status, user) = semanage.semanage_user_create(sh)
		if status < 0:
			raise Error("Could not create user object")
		if self.verbose: print "User object created"

		status = semanage.semanage_user_set_name(sh,user, "testPyUser")
		if status < 0:
			raise Error("Could not set user name")
		if self.verbose: print "User name set: ", semanage.semanage_user_get_name(user)
                
		status = semanage.semanage_user_add_role(sh, user, "user_r")	
		if status < 0:
			raise Error("Could not add role")

		status = semanage.semanage_user_set_prefix(sh,user, "user")
		if status < 0:
			raise Error("Could not set labeling prefix")
		if self.verbose: print "User prefix set: ", semanage.semanage_user_get_prefix(user)
	
		status = semanage.semanage_user_set_mlsrange(sh, user, "s0")
		if status < 0:
			raise Error("Could not set MLS range")
		if self.verbose: print "User mlsrange: ", semanage.semanage_user_get_mlsrange(user)

		status = semanage.semanage_user_set_mlslevel(sh, user, "s0")
		if status < 0:
			raise Error("Could not set MLS level")
		if self.verbose: print "User mlslevel: ", semanage.semanage_user_get_mlslevel(user)
                
		(status,key) = semanage.semanage_user_key_extract(sh,user)
		if status < 0:
			raise Error("Could not extract user key")
		if self.verbose: print "User key extracted: ", key
	
		(status,exists) = semanage.semanage_user_exists_local(sh,key)
		if status < 0:
			raise Error("Could not check if user exists")
		if self.verbose: print "Exists status (commit number): ", status

		if exists: 
			(status, old_user) = semanage.semanage_user_query_local(sh, key)
			if status < 0:
				raise Error("Could not query old user")
			if self.verbose: print "Query status (commit number): ", status

		print "Starting transaction.."
		status = semanage.semanage_begin_transaction(sh)
		if status < 0:
			raise Error("Could not start semanage transaction")

		status = semanage.semanage_user_modify_local(sh,key,user)
		if status < 0:
			raise Error("Could not modify user")

		status = semanage.semanage_commit(sh)
		if status < 0:
			raise Error("Could not commit test transaction")
		print "Commit status (transaction number): ", status

		status = semanage.semanage_begin_transaction(sh)
		if status < 0:
			raise Error("Could not start semanage transaction")
 
		if not exists:
			print "Removing user..."
			status = semanage.semanage_user_del_local(sh, key)
			if status < 0:
				raise Error("Could not delete test user")
			if self.verbose: print "User delete: ", status
		else:
			print "Resetting user..."
			status = semanage.semanage_user_modify_local(sh, key, old_user)
			if status < 0:
				raise Error("Could not reset test user")
			if self.verbose: print "User modify: ", status

		status = semanage.semanage_commit(sh)
		if status < 0:
			raise Error("Could not commit reset transaction")
		print "Commit status (transaction number): ", status

		semanage.semanage_user_key_free(key)
		semanage.semanage_user_free(user)
		if exists: semanage.semanage_user_free(old_user)

	def test_writeseuser(self,sh):
                print "Testing seuser write..."
                
		(status, seuser) = semanage.semanage_seuser_create(sh)
		if status < 0:
			raise Error("Could not create SEUser object")
		if self.verbose: print "SEUser object created."

		status = semanage.semanage_seuser_set_name(sh,seuser, "testPySEUser")
		if status < 0:
			raise Error("Could not set name")
		if self.verbose: print "SEUser name set: ", semanage.semanage_seuser_get_name(seuser)
                
		status = semanage.semanage_seuser_set_sename(sh, seuser, "root")
		if status < 0:
			raise Error("Could not set sename")
                if self.verbose: print "SEUser seuser: ", semanage.semanage_seuser_get_sename(seuser)
		
		status = semanage.semanage_seuser_set_mlsrange(sh, seuser, "s0:c0.c255")
		if status < 0:
			raise Error("Could not set MLS range")
                if self.verbose: print "SEUser mlsrange: ", semanage.semanage_seuser_get_mlsrange(seuser)
                
		(status,key) = semanage.semanage_seuser_key_extract(sh,seuser)
		if status < 0:
			raise Error("Could not extract SEUser key")
                if self.verbose: print "SEUser key extracted: ", key
	
                (status,exists) = semanage.semanage_seuser_exists_local(sh,key)
		if status < 0:
			raise Error("Could not check if SEUser exists")
		if self.verbose: print "Exists status (commit number): ", status

		if exists:
			(status, old_seuser) = semanage.semanage_seuser_query_local(sh, key)
			if status < 0:
				raise Error("Could not query old SEUser")
			if self.verbose: print "Query status (commit number): ", status

		print "Starting transaction..."
		status = semanage.semanage_begin_transaction(sh)
		if status < 0:
			raise Error("Could not start semanage transaction")

		status = semanage.semanage_seuser_modify_local(sh,key,seuser)
		if status < 0:
			raise Error("Could not modify SEUser")

		status = semanage.semanage_commit(sh)
		if status < 0:
			raise Error("Could not commit test transaction")
                print "Commit status (transaction number): ", status

		status = semanage.semanage_begin_transaction(sh)
		if status < 0:
			raise Error("Could not start semanage transaction")

		if not exists:
			print "Removing seuser..."
			status = semanage.semanage_seuser_del_local(sh, key)
			if status < 0:
				raise Error("Could not delete test SEUser")
			if self.verbose: print "Seuser delete: ", status
		else:
			print "Resetting seuser..."
			status = semanage.semanage_seuser_modify_local(sh, key, old_seuser)
			if status < 0:
				raise Error("Could not reset test SEUser")
			if self.verbose: print "Seuser modify: ", status

                status = semanage.semanage_commit(sh)
		if status < 0:
			raise Error("Could not commit reset transaction")
                print "Commit status (transaction number): ", status

		semanage.semanage_seuser_key_free(key)
		semanage.semanage_seuser_free(seuser)
		if exists: semanage.semanage_seuser_free(old_seuser)

	def test_writeport(self,sh):
		print "Testing port write..."

		(status, port) = semanage.semanage_port_create(sh)
		if status < 0:
			raise Error("Could not create SEPort object")
		if self.verbose: print "SEPort object created."

		semanage.semanage_port_set_range(port,150,200)
		low = semanage.semanage_port_get_low(port)
		high = semanage.semanage_port_get_high(port)
		if self.verbose: print "SEPort range set: ", low, "-", high
		
		semanage.semanage_port_set_proto(port, semanage.SEMANAGE_PROTO_TCP);
		if self.verbose: print "SEPort protocol set: ", \
			semanage.semanage_port_get_proto_str(semanage.SEMANAGE_PROTO_TCP)
		
		(status, con) = semanage.semanage_context_create(sh)
		if status < 0:
			raise Error("Could not create SEContext object")
		if self.verbose: print "SEContext object created (for port)."
		
		status = semanage.semanage_context_set_user(sh, con, "system_u")
		if status < 0:
			raise Error("Could not set context user")
		if self.verbose: print "SEContext user: ", semanage.semanage_context_get_user(con)
		
		status = semanage.semanage_context_set_role(sh, con, "object_r")
		if status < 0:
			raise Error("Could not set context role")
		if self.verbose: print "SEContext role: ", semanage.semanage_context_get_role(con)
		
		status = semanage.semanage_context_set_type(sh, con, "http_port_t")
		if status < 0:
			raise Error("Could not set context type")
		if self.verbose: print "SEContext type: ", semanage.semanage_context_get_type(con)

		status = semanage.semanage_context_set_mls(sh, con, "s0:c0.c255")
		if status < 0:
			raise Error("Could not set context MLS fields")
		if self.verbose: print "SEContext mls: ", semanage.semanage_context_get_mls(con)

		status = semanage.semanage_port_set_con(sh, port, con)
		if status < 0:
			raise Error("Could not set SEPort context")
		if self.verbose: print "SEPort context set: ", con

                (status,key) = semanage.semanage_port_key_extract(sh,port)
		if status < 0:
			raise Error("Could not extract SEPort key")
		if self.verbose: print "SEPort key extracted: ", key

		(status,exists) = semanage.semanage_port_exists_local(sh,key)
		if status < 0:
			raise Error("Could not check if SEPort exists")
		if self.verbose: print "Exists status (commit number): ", status

		if exists:
			(status, old_port) = semanage.semanage_port_query_local(sh, key)
			if status < 0:
				raise Error("Could not query old SEPort")
			if self.verbose: print "Query status (commit number): ", status

		print "Starting transaction..."
		status = semanage.semanage_begin_transaction(sh)
		if status < 0:
			raise Error("Could not start semanage transaction")	

		status = semanage.semanage_port_modify_local(sh,key,port)
		if status < 0:
			raise Error("Could not modify SEPort")

		status = semanage.semanage_commit(sh)
		if status < 0:
			raise Error("Could not commit test transaction")
		print "Commit status (transaction number): ", status

		status = semanage.semanage_begin_transaction(sh)
		if status < 0:
			raise Error("Could not start semanage transaction")

		if not exists:
			print "Removing port range..."
                        status = semanage.semanage_port_del_local(sh, key)
			if status < 0:
				raise Error("Could not delete test SEPort")
                        if self.verbose: print "Port range delete: ", status
                else:
			print "Resetting port range..."
			status = semanage.semanage_port_modify_local(sh, key, old_port)
			if status < 0:
				raise Error("Could not reset test SEPort")
			if self.verbose: print "Port range modify: ", status

		status = semanage.semanage_commit(sh)
		if status < 0:
			raise Error("Could not commit reset transaction")
		print "Commit status (transaction number): ", status

		semanage.semanage_context_free(con)
		semanage.semanage_port_key_free(key)
		semanage.semanage_port_free(port)
		if exists: semanage.semanage_port_free(old_port)

	def test_writefcontext(self,sh):
		print "Testing file context write..."

		(status, fcon) = semanage.semanage_fcontext_create(sh)
		if status < 0:
			raise Error("Could not create SEFcontext object")
		if self.verbose: print "SEFcontext object created."
	
		status = semanage.semanage_fcontext_set_expr(sh, fcon, "/test/fcontext(/.*)?")
		if status < 0:
			raise Error("Could not set expression")
		if self.verbose: print "SEFContext expr set: ", semanage.semanage_fcontext_get_expr(fcon)

		semanage.semanage_fcontext_set_type(fcon, semanage.SEMANAGE_FCONTEXT_REG)
		if self.verbose:
			ftype = semanage.semanage_fcontext_get_type(fcon)
			print "SEFContext type set: ", semanage.semanage_fcontext_get_type_str(ftype)

		(status, con) = semanage.semanage_context_create(sh)
		if status < 0:
			raise Error("Could not create SEContext object")
		if self.verbose: print "SEContext object created (for file context)."

		status = semanage.semanage_context_set_user(sh, con, "system_u")
		if status < 0:
			raise Error("Could not set context user")
		if self.verbose: print "SEContext user: ", semanage.semanage_context_get_user(con)

		status = semanage.semanage_context_set_role(sh, con, "object_r")
		if status < 0:
			raise Error("Could not set context role")
		if self.verbose: print "SEContext role: ", semanage.semanage_context_get_role(con)

		status = semanage.semanage_context_set_type(sh, con, "default_t")
		if status < 0:
			raise Error("Could not set context type")
		if self.verbose: print "SEContext type: ", semanage.semanage_context_get_type(con)

		status = semanage.semanage_context_set_mls(sh, con, "s0:c0.c255")
		if status < 0:
			raise Error("Could not set context MLS fields")
		if self.verbose: print "SEContext mls: ", semanage.semanage_context_get_mls(con)

		status = semanage.semanage_fcontext_set_con(sh, fcon, con)
		if status < 0:
			raise Error("Could not set SEFcontext context")
		if self.verbose: print "SEFcontext context set: ", con

		(status,key) = semanage.semanage_fcontext_key_extract(sh,fcon)
		if status < 0:
			raise Error("Could not extract SEFcontext key")
		if self.verbose: print "SEFcontext key extracted: ", key

		(status,exists) = semanage.semanage_fcontext_exists_local(sh,key)
		if status < 0:
			raise Error("Could not check if SEFcontext exists")

		if self.verbose: print "Exists status (commit number): ", status
		if exists:
			(status, old_fcontext) = semanage.semanage_fcontext_query_local(sh, key)
			if status < 0:
				raise Error("Could not query old SEFcontext")
			if self.verbose: print "Query status (commit number): ", status

		print "Starting transaction..."
		status = semanage.semanage_begin_transaction(sh)
		if status < 0:
			raise Error("Could not start semanage transaction")

		status = semanage.semanage_fcontext_modify_local(sh,key,fcon)
		if status < 0:
			raise Error("Could not modify SEFcontext")

		status = semanage.semanage_commit(sh)
		if status < 0:
			raise Error("Could not commit test transaction")
		print "Commit status (transaction number): ", status

		status = semanage.semanage_begin_transaction(sh)
		if status < 0:
			raise Error("Could not start semanage transaction")

		if not exists:
			print "Removing file context..."
			status = semanage.semanage_fcontext_del_local(sh, key)
			if status < 0:
				raise Error("Could not delete test SEFcontext")
			if self.verbose: print "File context delete: ", status
		else:
			print "Resetting file context..."
			status = semanage.semanage_fcontext_modify_local(sh, key, old_fcontext)
			if status < 0:
				raise Error("Could not reset test FContext")
			if self.verbose: print "File context modify: ", status

		status = semanage.semanage_commit(sh)
		if status < 0:
			raise Error("Could not commit reset transaction")
		print "Commit status (transaction number): ", status

		semanage.semanage_context_free(con)	
		semanage.semanage_fcontext_key_free(key)
		semanage.semanage_fcontext_free(fcon)
		if exists: semanage.semanage_fcontext_free(old_fcontext)

	def test_writeinterface(self,sh):
		print "Testing network interface write..."

		(status, iface) = semanage.semanage_iface_create(sh)
		if status < 0:
			raise Error("Could not create SEIface object")	
		if self.verbose: print "SEIface object created."

		status = semanage.semanage_iface_set_name(sh, iface, "test_iface")
		if status < 0:
			raise Error("Could not set SEIface name")
		if self.verbose: print "SEIface name set: ", semanage.semanage_iface_get_name(iface)	

		(status, con) = semanage.semanage_context_create(sh)
		if status < 0:
			raise Error("Could not create SEContext object")
		if self.verbose: print "SEContext object created (for network interface)"

		status = semanage.semanage_context_set_user(sh, con, "system_u")
		if status < 0:
			raise Error("Could not set interface context user")
		if self.verbose: print "SEContext user: ", semanage.semanage_context_get_user(con)

		status = semanage.semanage_context_set_role(sh, con, "object_r")
		if status < 0:
			raise Error("Could not set interface context role")
		if self.verbose: print "SEContext role: ", semanage.semanage_context_get_role(con)

		status = semanage.semanage_context_set_type(sh, con, "default_t")
		if status < 0:
			raise Error("Could not set interface context type")
		if self.verbose: print "SEContext type: ", semanage.semanage_context_get_type(con)

		status = semanage.semanage_context_set_mls(sh, con, "s0:c0.c255")
		if status < 0:
			raise Error("Could not set interface context MLS fields")
		if self.verbose: print "SEContext mls: ", semanage.semanage_context_get_mls(con)

		status = semanage.semanage_iface_set_ifcon(sh, iface, con)
		if status < 0:
			raise Error("Could not set SEIface interface context")
		if self.verbose: print "SEIface interface context set: ", con

		status = semanage.semanage_iface_set_msgcon(sh, iface, con)
		if status < 0:
			raise Error("Could not set SEIface message context")
		if self.verbose: print "SEIface message context set: ", con

		(status,key) = semanage.semanage_iface_key_extract(sh,iface)
		if status < 0:
			raise Error("Could not extract SEIface key")
		if self.verbose: print "SEIface key extracted: ", key

		(status,exists) = semanage.semanage_iface_exists_local(sh,key)
		if status < 0:
			raise Error("Could not check if SEIface exists")
		if self.verbose: print "Exists status (commit number): ", status

		if exists:
			(status, old_iface) = semanage.semanage_iface_query_local(sh, key)
			if status < 0:
				raise Error("Could not query old SEIface")
			if self.verbose: print "Query status (commit number): ", status

		print "Starting transaction..."
		status = semanage.semanage_begin_transaction(sh)
		if status < 0:
			raise Error("Could not begin semanage transaction")

		status = semanage.semanage_iface_modify_local(sh,key,iface)
		if status < 0:
			raise Error("Could not modify SEIface")

		status = semanage.semanage_commit(sh)
		if status < 0:
			raise Error("Could not commit test transaction")
		print "Commit status (transaction number): ", status

		status = semanage.semanage_begin_transaction(sh)
		if status < 0:
			raise Error("Could not begin semanage transaction")

		if not exists:
			print "Removing interface..."
			status = semanage.semanage_iface_del_local(sh, key)
			if status < 0:
				raise Error("Could not delete test SEIface")
			if self.verbose: print "Interface delete: ", status
		else:
			print "Resetting interface..."
			status = semanage.semanage_iface_modify_local(sh, key, old_iface)
			if status < 0:
				raise Error("Could not reset test SEIface")
			if self.verbose: print "Interface modify: ", status

		status = semanage.semanage_commit(sh)
		if status < 0:
			raise Error("Could not commit reset transaction")
		print "Commit status (transaction number): ", status

		semanage.semanage_context_free(con)
		semanage.semanage_iface_key_free(key)
		semanage.semanage_iface_free(iface)
		if exists: semanage.semanage_iface_free(old_iface)

        def test_writeboolean(self,sh):
		print "Testing boolean write..."

		(status, pbool) = semanage.semanage_bool_create(sh)
		if status < 0:
			raise Error("Could not create SEBool object")
		if self.verbose: print "SEBool object created."

		status = semanage.semanage_bool_set_name(sh, pbool, "allow_execmem")
		if status < 0:
			raise Error("Could not set name")
		if self.verbose: print "SEBool name set: ", semanage.semanage_bool_get_name(pbool)

		semanage.semanage_bool_set_value(pbool, 0)
		if self.verbose: print "SEbool value set: ", semanage.semanage_bool_get_value(pbool)

		(status,key) = semanage.semanage_bool_key_extract(sh, pbool)
		if status < 0:
			raise Error("Could not extract SEBool key")
		if self.verbose: print "SEBool key extracted: ", key

		(status,exists) = semanage.semanage_bool_exists_local(sh,key)
		if status < 0:
			raise Error("Could not check if SEBool exists")
		if self.verbose: print "Exists status (commit number): ", status

		if exists:
			(status, old_bool) = semanage.semanage_bool_query_local(sh, key)
			if status < 0:
				raise Error("Could not query old SEBool")
			if self.verbose: print "Query status (commit number): ", status

		print "Starting transaction..."
		status = semanage.semanage_begin_transaction(sh)
		if status < 0:
			raise Error("Could not start semanage transaction")

		status = semanage.semanage_bool_modify_local(sh, key, pbool)

		if status < 0:
			raise Error("Could not modify SEBool")

		status = semanage.semanage_commit(sh)
		if status < 0:
			raise Error("Could not commit test transaction")
		print "Commit status (transaction number): ", status

		status = semanage.semanage_begin_transaction(sh)
		if status < 0:
			raise Error("Could not start semanage transaction")

		if not exists:
			print "Removing boolean..."
			status = semanage.semanage_bool_del_local(sh, key)
			if status < 0:
				raise Error("Could not delete test SEBool")
			if self.verbose: print "Boolean delete: ", status
		else:
			print "Resetting boolean..."
			status = semanage.semanage_bool_modify_local(sh, key, old_bool)
			if status < 0:
				raise Error("Could not reset test SEBool")
			if self.verbose: print "Boolean modify: ", status

		status = semanage.semanage_commit(sh)
		if status < 0:
			raise Error("Could not commit reset transaction")
		print "Commit status (transaction number): ", status

		semanage.semanage_bool_key_free(key)
		semanage.semanage_bool_free(pbool)
		if exists: semanage.semanage_bool_free(old_bool)

	def test_writeaboolean(self,sh):
		print "Testing active boolean write..."

		(status, key) = semanage.semanage_bool_key_create(sh, "allow_execmem")
		if status < 0:
			raise Error("Could not create SEBool key")
		if self.verbose: print "SEBool key created: ", key

		(status, old_bool) = semanage.semanage_bool_query_active(sh, key)
		if status < 0:
			raise Error("Could not query old SEBool")
		if self.verbose: print "Query status (commit number): ", status

		(status, abool) = semanage.semanage_bool_create(sh)
		if status < 0:
			raise Error("Could not create SEBool object")
		if self.verbose: print "SEBool object created."

		status = semanage.semanage_bool_set_name(sh, abool, "allow_execmem")
		if status < 0:
			raise Error("Could not set name")
		if self.verbose: print "SEBool name set: ", semanage.semanage_bool_get_name(abool)

		semanage.semanage_bool_set_value(abool, 0)
		if self.verbose: print "SEbool value set: ", semanage.semanage_bool_get_value(abool)

		print "Starting transaction..."
		status = semanage.semanage_begin_transaction(sh)
		if status < 0:
			raise Error("Could not start semanage transaction")

		status = semanage.semanage_bool_set_active(sh,key,abool)
		if status < 0:
			raise Error("Could not modify SEBool")

		status = semanage.semanage_commit(sh)
		if status < 0:
			raise Error("Could not commit test transaction")
		print "Commit status (transaction number): ", status

		print "Resetting old active boolean..."
		status = semanage.semanage_begin_transaction(sh)
		if status < 0:
			raise Error("Could not start semanage transaction")

		status = semanage.semanage_bool_set_active(sh, key,old_bool)
		if status < 0:
			raise Error("Could not reset test SEBool")
		if self.verbose: print "SEBool active reset: ", status

		status = semanage.semanage_commit(sh)
		if status < 0:
			raise Error("Could not commit reset transaction")
		print "Commit status (transaction number): ", status

		semanage.semanage_bool_key_free(key)
		semanage.semanage_bool_free(abool)
		semanage.semanage_bool_free(old_bool)


	def test_writenode(self,sh):
		print "Testing network node write..."

		(status, node) = semanage.semanage_node_create(sh)
		if status < 0:
			raise Error("Could not create SENode object")
		if self.verbose: print "SENode object created."

		status = semanage.semanage_node_set_addr(sh, node, semanage.SEMANAGE_PROTO_IP6, "ffee:dddd::bbbb")
		if status < 0:
			raise Error("Could not set SENode address")
	
		status = semanage.semanage_node_set_mask(sh, node, semanage.SEMANAGE_PROTO_IP6, "::ffff:ffff:abcd:0000")
		if status < 0:
			raise Error("Could not set SENode netmask")

		semanage.semanage_node_set_proto(node, semanage.SEMANAGE_PROTO_IP6);
		if self.verbose: print "SENode protocol set: ", \
			semanage.semanage_node_get_proto_str(semanage.SEMANAGE_PROTO_IP6)
		
		(status, con) = semanage.semanage_context_create(sh)
		if status < 0:
			raise Error("Could not create SEContext object")
		if self.verbose: print "SEContext object created (for node)."
		
		status = semanage.semanage_context_set_user(sh, con, "system_u")
		if status < 0:
			raise Error("Could not set context user")
		if self.verbose: print "SEContext user: ", semanage.semanage_context_get_user(con)
		
		status = semanage.semanage_context_set_role(sh, con, "object_r")
		if status < 0:
			raise Error("Could not set context role")
		if self.verbose: print "SEContext role: ", semanage.semanage_context_get_role(con)
		
		status = semanage.semanage_context_set_type(sh, con, "lo_node_t")
		if status < 0:
			raise Error("Could not set context type")
		if self.verbose: print "SEContext type: ", semanage.semanage_context_get_type(con)

		status = semanage.semanage_context_set_mls(sh, con, "s0:c0.c255")
		if status < 0:
			raise Error("Could not set context MLS fields")
		if self.verbose: print "SEContext mls: ", semanage.semanage_context_get_mls(con)

		status = semanage.semanage_node_set_con(sh, node, con)
		if status < 0:
			raise Error("Could not set SENode context")
		if self.verbose: print "SENode context set: ", con

                (status,key) = semanage.semanage_node_key_extract(sh, node)
		if status < 0:
			raise Error("Could not extract SENode key")
		if self.verbose: print "SENode key extracted: ", key

		(status,exists) = semanage.semanage_node_exists_local(sh,key)
		if status < 0:
			raise Error("Could not check if SENode exists")
		if self.verbose: print "Exists status (commit number): ", status

		if exists:
			(status, old_node) = semanage.semanage_node_query_local(sh, key)
			if status < 0:
				raise Error("Could not query old SENode")
			if self.verbose: print "Query status (commit number): ", status

		print "Starting transaction..."
		status = semanage.semanage_begin_transaction(sh)
		if status < 0:
			raise Error("Could not start semanage transaction")	

		status = semanage.semanage_node_modify_local(sh,key, node)
		if status < 0:
			raise Error("Could not modify SENode")

		status = semanage.semanage_commit(sh)
		if status < 0:
			raise Error("Could not commit test transaction")
		print "Commit status (transaction number): ", status

		status = semanage.semanage_begin_transaction(sh)
		if status < 0:
			raise Error("Could not start semanage transaction")

		if not exists:
			print "Removing network node..."
                        status = semanage.semanage_node_del_local(sh, key)
			if status < 0:
				raise Error("Could not delete test SENode")
                        if self.verbose: print "Network node delete: ", status
                else:
			print "Resetting network node..."
			status = semanage.semanage_node_modify_local(sh, key, old_node)
			if status < 0:
				raise Error("Could not reset test SENode")
			if self.verbose: print "Network node modify: ", status

		status = semanage.semanage_commit(sh)
		if status < 0:
			raise Error("Could not commit reset transaction")
		print "Commit status (transaction number): ", status

		semanage.semanage_context_free(con)
		semanage.semanage_node_key_free(key)
		semanage.semanage_node_free(node)
		if exists: semanage.semanage_node_free(old_node)

def main(argv=None):
	if argv is None:
		argv = sys.argv
	try:
        	try:
			opts, args = getopt.getopt(argv[1:], "hvmuspfibcUSPFIBCanN", ["help", "verbose", "modules", "users", "seusers", "ports", "file contexts", "network interfaces", "booleans", "active booleans", "network nodes", "writeuser", "writeseuser", "writeport", "writefcontext", "writeinterface", "writeboolean", "writeaboolean", "writenode", "all"])
			tests = Tests()
			for o, a in opts:
        			if o == "-v":
            				tests.verbose = True
					print "Verbose output selected."
        			if o == "-a":
            				tests.all = True
        			if o == "-u":
            				tests.users = True
        			if o == "-U":
            				tests.writeuser = True
        			if o == "-s":
            				tests.seusers = True
        			if o == "-S":
            				tests.writeseuser = True
				if o == "-p":
					tests.ports = True
				if o == "-P":
					tests.writeport = True
				if o == "-f":
					tests.fcontexts = True
				if o == "-F":
					tests.writefcontext = True
				if o == "-i":
					tests.interfaces = True
				if o == "-I":
					tests.writeinterface = True
				if o == "-b":
					tests.booleans = True
				if o == "-B":
					tests.writeboolean = True
				if o == "-c":
					tests.abooleans = True
				if o == "-C":
					tests.writeaboolean = True
				if o == "-n":
					tests.nodes = True
				if o == "-N":
					tests.writenode = True
        			if o == "-m":
            				tests.modules = True
        			if o == "-h":
					raise Usage(usage)

			if not tests.selected():
				raise Usage("Please select a valid test.")

        	except getopt.error, msg:
             		raise Usage(msg)

		sh=semanage.semanage_handle_create()
		
		if (semanage.semanage_is_managed(sh) != 1):
			raise Status("Unmanaged!")
		
		status = semanage.semanage_connect(sh)
		if status < 0:
			raise Error("Could not establish semanage connection")

		tests.run(sh)

		status = semanage.semanage_disconnect(sh)
		if status < 0:
			raise Error("Could not disconnect")

		semanage.semanage_handle_destroy(sh)

	except Usage, err:
        	print >>sys.stderr, err.msg
	except Status, err:
        	print >>sys.stderr, err.msg
	except Error, err:
		print >>sys.stderr, err.msg

        return 2

if __name__ == "__main__":
	sys.exit(main())

