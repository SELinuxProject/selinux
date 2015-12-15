SID Statements
==============

sid
---

Declares a new SID identifier in the current namespace.

**Statement definition:**

    (sid sid_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>sid</code></p></td>
<td align="left"><p>The <code>sid</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>sid_id</code></p></td>
<td align="left"><p>The <code>sid</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Examples:**

These examples show three [`sid`](cil_sid_statements.md#sid) declarations:

    (sid kernel)
    (sid security)
    (sid igmp_packet)

sidorder
--------

Defines the order of [sid](#sid)'s. This is a mandatory statement when SIDs are defined. Multiple [`sidorder`](cil_sid_statements.md#sidorder) statements declared in the policy will form an ordered list.

**Statement definition:**

    (sidorder (sid_id ...))

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>sidorder</code></p></td>
<td align="left"><p>The <code>sidorder</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>sid_id</code></p></td>
<td align="left"><p>One or more <code>sid</code> identifiers.</p></td>
</tr>
</tbody>
</table>

**Example:**

This will produce an ordered list of "`kernel security unlabeled`"

    (sid kernel)
    (sid security)
    (sid unlabeled)
    (sidorder (kernel security))
    (sidorder (security unlabeled))

sidcontext
----------

Associates an SELinux security [context](#context) to a previously declared [`sid`](cil_sid_statements.md#sid) identifier.

**Statement definition:**

    (sidcontext sid_id context_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>sidcontext</code></p></td>
<td align="left"><p>The <code>sidcontext</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>sid_id</code></p></td>
<td align="left"><p>A single previously declared <code>sid</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>context_id</code></p></td>
<td align="left"><p>A previously declared <code>context</code> identifier or an anonymous security context (<code>user role type levelrange</code>), the range MUST be defined whether the policy is MLS/MCS enabled or not.</p></td>
</tr>
</tbody>
</table>

**Examples:**

This shows two named security context examples plus an anonymous context:

    ; Two named context:
    (sid kernel)
    (context kernel_context (u r process low_low))
    (sidcontext kernel kernel_context)

    (sid security)
    (context security_context (u object_r process low_low))
    (sidcontext security security_context)

    ; An anonymous context:
    (sid unlabeled)
    (sidcontext unlabeled (u object_r ((s0) (s0))))
