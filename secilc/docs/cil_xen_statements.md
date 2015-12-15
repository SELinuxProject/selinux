Xen Statements
==============

Policy version 30 introduced the [`devicetreecon`](cil_xen_statements.md#devicetreecon) statement and also expanded the existing I/O memory range to 64 bits in order to support hardware with more than 44 bits of physical address space (32-bit count of 4K pages).

See the ["XSM/FLASK Configuration"](http://xenbits.xen.org/docs/4.2-testing/misc/xsm-flask.txt) document for further information ([](http://xenbits.xen.org/docs/4.2-testing/misc/xsm-flask.txt))

iomemcon
--------

Label i/o memory. This may be a single memory location or a range.

**Statement definition:**

    (iomemcon mem_addr|(mem_low mem_high) context_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>iomemcon</code></p></td>
<td align="left"><p>The <code>iomemcon</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>mem_addr |</code></p>
<p><code>(mem_low mem_high)</code></p></td>
<td align="left"><p>A single memory address to apply the context, or a range of addresses.</p>
<p>The entries must consist of numerics <code>[0-9]</code>.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>context_id</code></p></td>
<td align="left"><p>A previously declared <code>context</code> identifier or an anonymous security context (<code>user role type levelrange</code>), the range MUST be defined whether the policy is MLS/MCS enabled or not.</p></td>
</tr>
</tbody>
</table>

**Example:**

An anonymous context for a memory address range of `0xfebe0-0xfebff`:

    (iomemcon (1043424 1043455) (unconfined.user object_r unconfined.object low_low))

ioportcon
---------

Label i/o ports. This may be a single port or a range.

**Statement definition:**

    (ioportcon port|(port_low port_high) context_id)

**Where:**

<table>
<colgroup>
<col width="27%" />
<col width="72%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>ioportcon</code></p></td>
<td align="left"><p>The <code>ioportcon</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>port |</code></p>
<p><code>(port_low port_high)</code></p></td>
<td align="left"><p>A single port to apply the context, or a range of ports.</p>
<p>The entries must consist of numerics <code>[0-9]</code>.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>context_id</code></p></td>
<td align="left"><p>A previously declared <code>context</code> identifier or an anonymous security context (<code>user role type levelrange</code>), the range MUST be defined whether the policy is MLS/MCS enabled or not.</p></td>
</tr>
</tbody>
</table>

**Example:**

An anonymous context for a single port of :`0xecc0`:

    (ioportcon 60608 (unconfined.user object_r unconfined.object low_low))

pcidevicecon
------------

Label a PCI device.

**Statement definition:**

    (pcidevicecon device context_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>pcidevicecon</code></p></td>
<td align="left"><p>The <code>pcidevicecon</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>device</code></p></td>
<td align="left"><p>The device number.The entries must consist of numerics <code>[0-9]</code>.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>context_id</code></p></td>
<td align="left"><p>A previously declared <code>context</code> identifier or an anonymous security context (<code>user role type levelrange</code>), the range MUST be defined whether the policy is MLS/MCS enabled or not.</p></td>
</tr>
</tbody>
</table>

**Example:**

An anonymous context for a pci device address of `0xc800`:

    (pcidevicecon 51200 (unconfined.user object_r unconfined.object low_low))

pirqcon
-------

Label an interrupt level.

**Statement definition:**

    (pirqcon irq_level context_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>pirqcon</code></p></td>
<td align="left"><p>The <code>pirqcon</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>irq_level</code></p></td>
<td align="left"><p>The interrupt request number. The entries must consist of numerics <code>[0-9]</code>.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>context_id</code></p></td>
<td align="left"><p>A previously declared <code>context</code> identifier or an anonymous security context (<code>user role type levelrange</code>), the range MUST be defined whether the policy is MLS/MCS enabled or not.</p></td>
</tr>
</tbody>
</table>

**Example:**

An anonymous context for IRQ 33:

    (pirqcon 33 (unconfined.user object_r unconfined.object low_low))

devicetreecon
-------------

Label device tree nodes.

**Statement definition:**

    (devicetreecon path context_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>devicetreecon</code></p></td>
<td align="left"><p>The <code>devicetreecon</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>path</code></p></td>
<td align="left"><p>The device tree path. If this contains spaces enclose within <code>&quot;&quot;</code>.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>context_id</code></p></td>
<td align="left"><p>A previously declared <code>context</code> identifier or an anonymous security context (<code>user role type levelrange</code>), the range MUST be defined whether the policy is MLS/MCS enabled or not.</p></td>
</tr>
</tbody>
</table>

**Example:**

An anonymous context for the specified path:

    (devicetreecon "/this is/a/path" (unconfined.user object_r unconfined.object low_low))
