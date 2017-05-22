/* Author: Spencer Shimko <sshimko@tresys.com>
 *
 * Copyright (C) 2004-2005 Tresys Technology, LLC
 * Copyright (C) 2006 Red Hat, Inc.
 * 
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */


%module semanage

/* pull in the headers */
%include "../include/semanage/debug.h"
%include "../include/semanage/handle.h"
%include "../include/semanage/modules.h"
%include "../include/semanage/context_record.h"
%include "../include/semanage/boolean_record.h"
%include "../include/semanage/booleans_policy.h"
%include "../include/semanage/booleans_local.h"
%include "../include/semanage/booleans_active.h"
%include "../include/semanage/iface_record.h"
%include "../include/semanage/interfaces_local.h"
%include "../include/semanage/interfaces_policy.h"
%include "../include/semanage/user_record.h"
%include "../include/semanage/users_local.h"
%include "../include/semanage/users_policy.h"
%include "../include/semanage/port_record.h"
%include "../include/semanage/ports_local.h"
%include "../include/semanage/ports_policy.h"
%include "../include/semanage/ibpkey_record.h"
%include "../include/semanage/ibpkeys_local.h"
%include "../include/semanage/ibpkeys_policy.h"
%include "../include/semanage/ibendport_record.h"
%include "../include/semanage/ibendports_local.h"
%include "../include/semanage/ibendports_policy.h"
%include "../include/semanage/fcontext_record.h"
%include "../include/semanage/fcontexts_local.h"
%include "../include/semanage/fcontexts_policy.h"
%include "../include/semanage/seuser_record.h"
%include "../include/semanage/seusers_local.h"
%include "../include/semanage/seusers_policy.h"
%include "../include/semanage/node_record.h"
%include "../include/semanage/nodes_local.h"
%include "../include/semanage/nodes_policy.h"
%include "../include/semanage/semanage.h"
