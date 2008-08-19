/* Authors: Joshua Brindle  <jbrindle@tresys.com>
 *	    Jason Tang	    <jtang@tresys.com>
 *
 * Copyright (C) 2005 Tresys Technology, LLC
 * Copyright (C) 2005 Red Hat, Inc.
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

#ifndef _SEMANAGE_SEMANAGE_H_
#define _SEMANAGE_SEMANAGE_H_

#include <semanage/handle.h>
#include <semanage/modules.h>
#include <semanage/debug.h>

/* Records */
#include <semanage/boolean_record.h>
#include <semanage/user_record.h>
#include <semanage/seuser_record.h>
#include <semanage/context_record.h>
#include <semanage/iface_record.h>
#include <semanage/port_record.h>
#include <semanage/node_record.h>

/* Dbase */
#include <semanage/booleans_local.h>
#include <semanage/booleans_policy.h>
#include <semanage/booleans_active.h>
#include <semanage/users_local.h>
#include <semanage/users_policy.h>
#include <semanage/fcontexts_local.h>
#include <semanage/fcontexts_policy.h>
#include <semanage/seusers_local.h>
#include <semanage/seusers_policy.h>
#include <semanage/ports_local.h>
#include <semanage/ports_policy.h>
#include <semanage/interfaces_local.h>
#include <semanage/interfaces_policy.h>
#include <semanage/nodes_local.h>
#include <semanage/nodes_policy.h>

#endif
