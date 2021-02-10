Network Labeling Statements
===========================

ipaddr
------

Declares a named IP address in IPv4 or IPv6 format that may be referenced by other CIL statements (i.e. [`netifcon`](cil_network_labeling_statements.md#netifcon)).

Notes:

-   CIL statements utilising an IP address may reference a named IP address or use an anonymous address, the examples will show each option.

-   IP Addresses may be declared without a previous declaration by enclosing within parentheses e.g. `(127.0.0.1)` or `(::1)`.

**Statement definition:**

```secil
    (ipaddr ipaddr_id ip_address)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>ipaddr</code></p></td>
<td align="left"><p>The <code>ipaddr</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>ipaddr_id</code></p></td>
<td align="left"><p>The IP address identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>ip_address</code></p></td>
<td align="left"><p>A correctly formatted IP address in IPv4 or IPv6 format.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example declares a named IP address and also passes an 'explicit anonymously declared' IP address to a macro:

```secil
    (ipaddr netmask_1 255.255.255.0)
    (context netlabel_1 (system.user object_r unconfined.object low_low))

    (call build_nodecon ((192.168.1.64) netmask_1))

    (macro build_nodecon ((ipaddr ARG1) (ipaddr ARG2))
        (nodecon ARG1 ARG2  netlabel_1))
```

netifcon
--------

Label network interface objects (e.g. `eth0`).

**Statement definition:**

```secil
    (netifcon netif_name netif_context_id packet_context_id)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>netifcon</code></p></td>
<td align="left"><p>The <code>netifcon</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>netif_name</code></p></td>
<td align="left"><p>The network interface name (e.g. <code>wlan0</code>).</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>netif_context_id</code></p></td>
<td align="left"><p>The security context to be allocated to the network interface.</p>
<p>A previously declared <code>context</code> identifier or an anonymous security context (<code>user role type levelrange</code>), the range MUST be defined whether the policy is MLS/MCS enabled or not.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>packet_context_id</code></p></td>
<td align="left"><p>The security context to be allocated to packets. Note that these are defined but currently unused as the <strong><code>iptables</code></strong><code>(8)</code> SECMARK services should be used to label packets.</p>
<p>A previously declared <code>context</code> identifier or an anonymous security context (<code>user role type levelrange</code>), the range MUST be defined whether the policy is MLS/MCS enabled or not.</p></td>
</tr>
</tbody>
</table>

**Examples:**

These examples show named and anonymous [`netifcon`](cil_network_labeling_statements.md#netifcon) statements:

```secil
    (context context_1 (unconfined.user object_r unconfined.object low_low))
    (context context_2 (unconfined.user object_r unconfined.object (systemlow level_2)))

    (netifcon eth0 context_1 (unconfined.user object_r unconfined.object levelrange_1))
    (netifcon eth1 context_1 (unconfined.user object_r unconfined.object ((s0) level_1)))
    (netifcon eth3 context_1 context_2)
```

nodecon
-------

Label network address objects that represent IPv4 or IPv6 IP addresses and network masks.

IP Addresses may be declared without a previous declaration by enclosing within parentheses e.g. `(127.0.0.1)` or `(::1)`.

**Statement definition:**

```secil
    (nodecon subnet_id netmask_id context_id)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>nodecon</code></p></td>
<td align="left"><p>The <code>nodecon</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>subnet_id</code></p></td>
<td align="left"><p>A previously declared <code>ipaddr</code> identifier, or an anonymous IPv4 or IPv6 formatted address.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>netmask_id</code></p></td>
<td align="left"><p>A previously declared <code>ipaddr</code> identifier, or an anonymous IPv4 or IPv6 formatted address.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>context_id</code></p></td>
<td align="left"><p>A previously declared <code>context</code> identifier or an anonymous security context (<code>user role type levelrange</code>), the range MUST be defined whether the policy is MLS/MCS enabled or not.</p></td>
</tr>
</tbody>
</table>

**Examples:**

These examples show named and anonymous [`nodecon`](cil_network_labeling_statements.md#nodecon) statements:

```secil
    (context context_1 (unconfined.user object_r unconfined.object low_low))
    (context context_2 (unconfined.user object_r unconfined.object (systemlow level_2)))

    (ipaddr netmask_1 255.255.255.255)
    (ipaddr ipv4_1 192.0.2.64)

    (nodecon ipv4_1 netmask_1 context_2)
    (nodecon (192.0.2.64) (255.255.255.255) context_1)
    (nodecon (192.0.2.64) netmask_1 (unconfined.user object_r unconfined.object ((s0) (s0 (c0)))))

    (context context_3 (sys.id sys.role my48prefix.node ((s0)(s0))))

    (ipaddr netmask_2 ffff:ffff:ffff:0:0:0:0:0)
    (ipaddr ipv6_2  2001:db8:1:0:0:0:0:0)

    (nodecon ipv6_2 netmask_2 context_3)
    (nodecon (2001:db8:1:0:0:0:0:0) (ffff:ffff:ffff:0:0:0:0:0) context_3)
    (nodecon (2001:db8:1:0:0:0:0:0) netmask_2 (sys.id sys.role my48prefix.node ((s0)(s0))))
```

portcon
-------

Label a udp, tcp, dccp or sctp port.

**Statement definition:**

```secil
    (portcon protocol port|(port_low port_high) context_id)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>portcon</code></p></td>
<td align="left"><p>The <code>portcon</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>protocol</code></p></td>
<td align="left"><p>The protocol keyword <code>tcp</code>, <code>udp</code>, <code>dccp</code> or <code>sctp</code>.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>port |</code></p>
<p><code>(port_low port_high)</code></p></td>
<td align="left"><p>A single port to apply the context, or a range of ports.</p>
<p>The entries must consist of numerics <code>[0-9]</code>.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>context_id</code></p></td>
<td align="left"><p>A previously declared <code>context</code> identifier or an anonymous security context (<code>user role type levelrange</code>), the range MUST be defined whether the policy is MLS/MCS enabled or not.</p></td>
</tr>
</tbody>
</table>

**Examples:**

These examples show named and anonymous [`portcon`](cil_network_labeling_statements.md#portcon) statements:

```secil
    (portcon tcp 1111 (unconfined.user object_r unconfined.object ((s0) (s0 (c0)))))
    (portcon tcp 2222 (unconfined.user object_r unconfined.object levelrange_2))
    (portcon tcp 3333 (unconfined.user object_r unconfined.object levelrange_1))
    (portcon udp 4444 (unconfined.user object_r unconfined.object ((s0) level_2)))
    (portcon tcp (2000 20000) (unconfined.user object_r unconfined.object (systemlow level_3)))
    (portcon dccp (6840 6880) (unconfined.user object_r unconfined.object ((s0) level_2)))
    (portcon sctp (1024 1035) (unconfined.user object_r unconfined.object ((s0) level_2)))
```
