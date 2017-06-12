Infiniband Statements
=====================

To support access control for InfiniBand (IB) partitions and subnet management, security contexts are provided for: Partition Keys (Pkey) that are 16 bit numbers assigned to subnets and their IB end ports. An overview of the SELinux IB implementation can be found at: [http://marc.info/?l=selinux&m=149519833917911&w=2](http://marc.info/?l=selinux&m=149519833917911&w=2).

ibpkeycon
---------

Label IB partition keys. This may be a single key or a range.

**Statement definition:**

    (ibpkeycon subnet pkey|(pkey_low pkey_high)  context_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>ibpkeycon</code></p></td>
<td align="left"><p>The <code>ibpkeycon</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>subnet</code></p>
<td align="left"><p>IP address in IPv6 format.</p>
</tr>
<tr class="odd">
<td align="left"><p><code>pkey | (pkey_low pkey_high)</code></p>
<td align="left"><p>A single partition key or a range of partition keys.</p>
</tr>
<tr class="even">
<td align="left"><p><code>context_id</code></p></td>
<td align="left"><p>A previously declared <code>context</code> identifier or an anonymous security context (<code>user role type levelrange</code>), the range MUST be defined whether the policy is MLS/MCS enabled or not.</p></td>
</tr>
</tbody>
</table>

**Example:**

An anonymous context for a partition key range of `0x0-0x10` assigned to an IPv6 subnet:

    (ibpkeycon fe80:: (0 0x10) (system_u system_r kernel_t (low (s3 (cats01 cats02)))))


ibendportcon
------------

Label IB end ports.

**Statement definition:**

    (ibendportcon device_id port context_id)

**Where:**

<table>
<colgroup>
<col width="27%" />
<col width="72%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>ibendportcon</code></p></td>
<td align="left"><p>The <code>ibendportcon</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>device_id</code></p>
<td align="left"><p>A single device identifier.</p>
</tr>
<tr class="odd">
<td align="left"><p><code>port</code></p>
<td align="left"><p>A single port number.</p>
</tr>
<tr class="even">
<td align="left"><p><code>context_id</code></p></td>
<td align="left"><p>A previously declared <code>context</code> identifier or an anonymous security context (<code>user role type levelrange</code>), the range MUST be defined whether the policy is MLS/MCS enabled or not.</p></td>
</tr>
</tbody>
</table>

**Example:**

A named context for device `mlx5_0` on port `1`:

    (ibendportcon mlx5_0 1 system_u_bin_t_l2h)
