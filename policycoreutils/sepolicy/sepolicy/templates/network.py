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
te_types="""
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

if_rules="""\
########################################
## <summary>
##	Send and receive TCP traffic on the TEMPLATETYPE port.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <infoflow type="both" weight="10"/>
#
interface(`corenet_tcp_sendrecv_TEMPLATETYPE_port',`
	gen_require(`
		type TEMPLATETYPE_port_t;
	')

	allow $1 TEMPLATETYPE_port_t:tcp_socket { send_msg recv_msg };
')

########################################
## <summary>
##	Send UDP traffic on the TEMPLATETYPE port.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <infoflow type="write" weight="10"/>
#
interface(`corenet_udp_send_TEMPLATETYPE_port',`
	gen_require(`
		type TEMPLATETYPE_port_t;
	')

	allow $1 TEMPLATETYPE_port_t:udp_socket send_msg;
')

########################################
## <summary>
##	Do not audit attempts to send UDP traffic on the TEMPLATETYPE port.
## </summary>
## <param name="domain">
##	<summary>
##	Domain to not audit.
##	</summary>
## </param>
## <infoflow type="none"/>
#
interface(`corenet_dontaudit_udp_send_TEMPLATETYPE_port',`
	gen_require(`
		type TEMPLATETYPE_port_t;
	')

	dontaudit $1 TEMPLATETYPE_port_t:udp_socket send_msg;
')

########################################
## <summary>
##	Receive UDP traffic on the TEMPLATETYPE port.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <infoflow type="read" weight="10"/>
#
interface(`corenet_udp_receive_TEMPLATETYPE_port',`
	gen_require(`
		type TEMPLATETYPE_port_t;
	')

	allow $1 TEMPLATETYPE_port_t:udp_socket recv_msg;
')

########################################
## <summary>
##	Do not audit attempts to receive UDP traffic on the TEMPLATETYPE port.
## </summary>
## <param name="domain">
##	<summary>
##	Domain to not audit.
##	</summary>
## </param>
## <infoflow type="none"/>
#
interface(`corenet_dontaudit_udp_receive_TEMPLATETYPE_port',`
	gen_require(`
		type TEMPLATETYPE_port_t;
	')

	dontaudit $1 TEMPLATETYPE_port_t:udp_socket recv_msg;
')

########################################
## <summary>
##	Send and receive UDP traffic on the TEMPLATETYPE port.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <infoflow type="both" weight="10"/>
#
interface(`corenet_udp_sendrecv_TEMPLATETYPE_port',`
	corenet_udp_send_TEMPLATETYPE_port($1)
	corenet_udp_receive_TEMPLATETYPE_port($1)
')

########################################
## <summary>
##	Do not audit attempts to send and receive
##	UDP traffic on the TEMPLATETYPE port.
## </summary>
## <param name="domain">
##	<summary>
##	Domain to not audit.
##	</summary>
## </param>
## <infoflow type="none"/>
#
interface(`corenet_dontaudit_udp_sendrecv_TEMPLATETYPE_port',`
	corenet_dontaudit_udp_send_TEMPLATETYPE_port($1)
	corenet_dontaudit_udp_receive_TEMPLATETYPE_port($1)
')

########################################
## <summary>
##	Bind TCP sockets to the TEMPLATETYPE port.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <infoflow type="none"/>
#
interface(`corenet_tcp_bind_TEMPLATETYPE_port',`
	gen_require(`
		type TEMPLATETYPE_port_t;
	')

	allow $1 TEMPLATETYPE_port_t:tcp_socket name_bind;
	
')

########################################
## <summary>
##	Bind UDP sockets to the TEMPLATETYPE port.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <infoflow type="none"/>
#
interface(`corenet_udp_bind_TEMPLATETYPE_port',`
	gen_require(`
		type TEMPLATETYPE_port_t;
	')

	allow $1 TEMPLATETYPE_port_t:udp_socket name_bind;
	
')

########################################
## <summary>
##	Do not audit attempts to sbind to TEMPLATETYPE port.
## </summary>
## <param name="domain">
##	<summary>
##	Domain to not audit.
##	</summary>
## </param>
## <infoflow type="none"/>
#
interface(`corenet_dontaudit_udp_bind_TEMPLATETYPE_port',`
	gen_require(`
		type TEMPLATETYPE_port_t;
	')

	dontaudit $1 TEMPLATETYPE_port_t:udp_socket name_bind;
	
')

########################################
## <summary>
##	Make a TCP connection to the TEMPLATETYPE port.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`corenet_tcp_connect_TEMPLATETYPE_port',`
	gen_require(`
		type TEMPLATETYPE_port_t;
	')

	allow $1 TEMPLATETYPE_port_t:tcp_socket name_connect;
')
########################################
## <summary>
##	Do not audit attempts to make a TCP connection to TEMPLATETYPE port.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`corenet_dontaudit_tcp_connect_TEMPLATETYPE_port',`
	gen_require(`
		type TEMPLATETYPE_port_t;
	')

	dontaudit $1 TEMPLATETYPE_port_t:tcp_socket name_connect;
')


########################################
## <summary>
##	Send TEMPLATETYPE_client packets.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <infoflow type="write" weight="10"/>
#
interface(`corenet_send_TEMPLATETYPE_client_packets',`
	gen_require(`
		type TEMPLATETYPE_client_packet_t;
	')

	allow $1 TEMPLATETYPE_client_packet_t:packet send;
')

########################################
## <summary>
##	Do not audit attempts to send TEMPLATETYPE_client packets.
## </summary>
## <param name="domain">
##	<summary>
##	Domain to not audit.
##	</summary>
## </param>
## <infoflow type="none"/>
#
interface(`corenet_dontaudit_send_TEMPLATETYPE_client_packets',`
	gen_require(`
		type TEMPLATETYPE_client_packet_t;
	')

	dontaudit $1 TEMPLATETYPE_client_packet_t:packet send;
')

########################################
## <summary>
##	Receive TEMPLATETYPE_client packets.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <infoflow type="read" weight="10"/>
#
interface(`corenet_receive_TEMPLATETYPE_client_packets',`
	gen_require(`
		type TEMPLATETYPE_client_packet_t;
	')

	allow $1 TEMPLATETYPE_client_packet_t:packet recv;
')

########################################
## <summary>
##	Do not audit attempts to receive TEMPLATETYPE_client packets.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <infoflow type="none"/>
#
interface(`corenet_dontaudit_receive_TEMPLATETYPE_client_packets',`
	gen_require(`
		type TEMPLATETYPE_client_packet_t;
	')

	dontaudit $1 TEMPLATETYPE_client_packet_t:packet recv;
')

########################################
## <summary>
##	Send and receive TEMPLATETYPE_client packets.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <infoflow type="both" weight="10"/>
#
interface(`corenet_sendrecv_TEMPLATETYPE_client_packets',`
	corenet_send_TEMPLATETYPE_client_packets($1)
	corenet_receive_TEMPLATETYPE_client_packets($1)
')

########################################
## <summary>
##	Do not audit attempts to send and receive TEMPLATETYPE_client packets.
## </summary>
## <param name="domain">
##	<summary>
##	Domain to not audit.
##	</summary>
## </param>
## <infoflow type="none"/>
#
interface(`corenet_dontaudit_sendrecv_TEMPLATETYPE_client_packets',`
	corenet_dontaudit_send_TEMPLATETYPE_client_packets($1)
	corenet_dontaudit_receive_TEMPLATETYPE_client_packets($1)
')

########################################
## <summary>
##	Relabel packets to TEMPLATETYPE_client the packet type.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`corenet_relabelto_TEMPLATETYPE_client_packets',`
	gen_require(`
		type TEMPLATETYPE_client_packet_t;
	')

	allow $1 TEMPLATETYPE_client_packet_t:packet relabelto;
')


########################################
## <summary>
##	Send TEMPLATETYPE_server packets.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <infoflow type="write" weight="10"/>
#
interface(`corenet_send_TEMPLATETYPE_server_packets',`
	gen_require(`
		type TEMPLATETYPE_server_packet_t;
	')

	allow $1 TEMPLATETYPE_server_packet_t:packet send;
')

########################################
## <summary>
##	Do not audit attempts to send TEMPLATETYPE_server packets.
## </summary>
## <param name="domain">
##	<summary>
##	Domain to not audit.
##	</summary>
## </param>
## <infoflow type="none"/>
#
interface(`corenet_dontaudit_send_TEMPLATETYPE_server_packets',`
	gen_require(`
		type TEMPLATETYPE_server_packet_t;
	')

	dontaudit $1 TEMPLATETYPE_server_packet_t:packet send;
')

########################################
## <summary>
##	Receive TEMPLATETYPE_server packets.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <infoflow type="read" weight="10"/>
#
interface(`corenet_receive_TEMPLATETYPE_server_packets',`
	gen_require(`
		type TEMPLATETYPE_server_packet_t;
	')

	allow $1 TEMPLATETYPE_server_packet_t:packet recv;
')

########################################
## <summary>
##	Do not audit attempts to receive TEMPLATETYPE_server packets.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <infoflow type="none"/>
#
interface(`corenet_dontaudit_receive_TEMPLATETYPE_server_packets',`
	gen_require(`
		type TEMPLATETYPE_server_packet_t;
	')

	dontaudit $1 TEMPLATETYPE_server_packet_t:packet recv;
')

########################################
## <summary>
##	Send and receive TEMPLATETYPE_server packets.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
## <infoflow type="both" weight="10"/>
#
interface(`corenet_sendrecv_TEMPLATETYPE_server_packets',`
	corenet_send_TEMPLATETYPE_server_packets($1)
	corenet_receive_TEMPLATETYPE_server_packets($1)
')

########################################
## <summary>
##	Do not audit attempts to send and receive TEMPLATETYPE_server packets.
## </summary>
## <param name="domain">
##	<summary>
##	Domain to not audit.
##	</summary>
## </param>
## <infoflow type="none"/>
#
interface(`corenet_dontaudit_sendrecv_TEMPLATETYPE_server_packets',`
	corenet_dontaudit_send_TEMPLATETYPE_server_packets($1)
	corenet_dontaudit_receive_TEMPLATETYPE_server_packets($1)
')

########################################
## <summary>
##	Relabel packets to TEMPLATETYPE_server the packet type.
## </summary>
## <param name="domain">
##	<summary>
##	Domain allowed access.
##	</summary>
## </param>
#
interface(`corenet_relabelto_TEMPLATETYPE_server_packets',`
	gen_require(`
		type TEMPLATETYPE_server_packet_t;
	')

	allow $1 TEMPLATETYPE_server_packet_t:packet relabelto;
')
"""

te_rules="""
"""
