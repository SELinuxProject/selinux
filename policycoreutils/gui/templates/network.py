# Copyright (C) 2007-2012 Red Hat
# see file 'COPYING' for use and warranty information
#
# policygentool is a tool for the initial generation of SELinux policy
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
########################### Type Enforcement File #############################
te_port_types="""
type TEMPLATETYPE_port_t;
corenet_port(TEMPLATETYPE_port_t)
"""

te_network="""\
sysnet_dns_name_resolve(TEMPLATETYPE_t)
corenet_all_recvfrom_unlabeled(TEMPLATETYPE_t)
"""

te_tcp="""\
allow TEMPLATETYPE_t self:tcp_socket create_stream_socket_perms;
corenet_tcp_sendrecv_generic_if(TEMPLATETYPE_t)
corenet_tcp_sendrecv_generic_node(TEMPLATETYPE_t)
corenet_tcp_sendrecv_all_ports(TEMPLATETYPE_t)
"""

te_in_tcp="""\
corenet_tcp_bind_generic_node(TEMPLATETYPE_t)
"""

te_in_need_port_tcp="""\
allow TEMPLATETYPE_t TEMPLATETYPE_port_t:tcp_socket name_bind;
"""

te_out_need_port_tcp="""\
allow TEMPLATETYPE_t TEMPLATETYPE_port_t:tcp_socket name_connect;
"""

te_udp="""\
allow TEMPLATETYPE_t self:udp_socket { create_socket_perms listen };
corenet_udp_sendrecv_generic_if(TEMPLATETYPE_t)
corenet_udp_sendrecv_generic_node(TEMPLATETYPE_t)
corenet_udp_sendrecv_all_ports(TEMPLATETYPE_t)
"""

te_in_udp="""\
corenet_udp_bind_generic_node(TEMPLATETYPE_t)
"""

te_in_need_port_udp="""\
allow TEMPLATETYPE_t TEMPLATETYPE_port_t:udp_socket name_bind;
"""

te_out_all_ports_tcp="""\
corenet_tcp_connect_all_ports(TEMPLATETYPE_t)
"""

te_out_reserved_ports_tcp="""\
corenet_tcp_connect_all_rpc_ports(TEMPLATETYPE_t)
"""

te_out_unreserved_ports_tcp="""\
corenet_tcp_connect_all_unreserved_ports(TEMPLATETYPE_t)
"""

te_in_all_ports_tcp="""\
corenet_tcp_bind_all_ports(TEMPLATETYPE_t)
"""

te_in_reserved_ports_tcp="""\
corenet_tcp_bind_all_rpc_ports(TEMPLATETYPE_t)
"""

te_in_unreserved_ports_tcp="""\
corenet_tcp_bind_all_unreserved_ports(TEMPLATETYPE_t)
"""

te_in_all_ports_udp="""\
corenet_udp_bind_all_ports(TEMPLATETYPE_t)
"""

te_in_reserved_ports_udp="""\
corenet_udp_bind_all_rpc_ports(TEMPLATETYPE_t)
"""

te_in_unreserved_ports_udp="""\
corenet_udp_bind_all_unreserved_ports(TEMPLATETYPE_t)
"""
