Context Statement
=================

Contexts are formed using previously declared parameters and may be named or anonymous where:

-   Named - The context is declared with a context identifer that is used as a reference.

-   Anonymous - They are defined within the CIL labeling statement using user, role etc. identifiers.

Each type is shown in the examples.

context
-------

Declare an SELinux security context identifier for labeling. The range (or current and clearance levels) MUST be defined whether the policy is MLS/MCS enabled or not.

**Statement definition:**

    (context context_id (user_id role_id type_id levelrange_id)))

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>context</code></p></td>
<td align="left"><p>The <code>context</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>context_id</code></p></td>
<td align="left"><p>The <code>context</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>user_id</code></p></td>
<td align="left"><p>A single previously declared <code>user</code> identifier.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>role_id</code></p></td>
<td align="left"><p>A single previously declared <code>role</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>type_id</code></p></td>
<td align="left"><p>A single previously declared <code>type</code> or <code>typealias</code> identifier.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>levelrange_id</code></p></td>
<td align="left"><p>A single previously declared <code>levelrange</code> identifier. This entry may also be defined by anonymous or named <code>level</code>, <code>sensitivity</code>, <code>sensitivityalias</code>, <code>category</code>, <code>categoryalias</code> or <code>categoryset</code> as discussed in the <a href="#mls_labeling_statements">Multi-Level Security Labeling Statements</a> section and shown in the examples.</p></td>
</tr>
</tbody>
</table>

**Examples:**

This example uses a named context definition:

    (context runas_exec_context (u object_r exec low_low))

    (filecon "/system/bin/run-as" file runas_exec_context)

to resolve/build a `file_contexts` entry of (assuming MLS enabled policy):

    /system/bin/run-as  -- u:object_r:runas.exec:s0-s0

This example uses an anonymous context where the previously declared `user role type levelrange` identifiers are used to specifiy two [`portcon`](cil_network_labeling_statements.md#portcon) statements:

    (portcon udp 1024 (test.user object_r test.process ((s0) (s1))))
    (portcon tcp 1024 (test.user object_r test.process (system_low system_high)))

This example uses an anonymous context for the first and named context for the second in a [`netifcon`](cil_network_labeling_statements.md#netifcon) statement:

    (context netif_context (test.user object_r test.process ((s0 (c0)) (s1 (c0)))))

    (netifcon eth04 (test.user object_r test.process ((s0 (c0)) (s1 (c0)))) netif_context)
