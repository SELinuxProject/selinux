Policy Configuration Statements
===============================

mls
---

Defines whether the policy is built as an MLS or non-MLS policy by the CIL compiler. There MUST only be one [`mls`](cil_policy_config_statements.md#mls) entry in the policy otherwise the compiler will exit with an error.

Note that this can be over-ridden by the CIL compiler command line parameter `-M true|false` or `--mls true|false` flags.

**Statement definition:**

    (mls boolean)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>mls</code></p></td>
<td align="left"><p>The <code>mls</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>boolean</code></p></td>
<td align="left"><p>Set to either <code>true</code> or <code>false</code>.</p></td>
</tr>
</tbody>
</table>

**Example:**

    (mls true)

handleunknown
-------------

Defines how the kernel will handle unknown object classes and permissions when loading the policy. There MUST only be one [`handleunknown`](cil_policy_config_statements.md#handleunknown) entry in the policy otherwise the compiler will exit with an error.

Note that this can be over-ridden by the CIL compiler command line parameter `-U` or `--handle-unknown` flags.

**Statement definition:**

    (handleunknown action)

**Where:**

<table>
<colgroup>
<col width="20%" />
<col width="80%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>handleunknown</code></p></td>
<td align="left"><p>The <code>handleunknown</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>action</code></p></td>
<td align="left"><p>A keyword of either <code>allow</code>, <code>deny</code> or <code>reject</code>. The kernel will handle these keywords as follows:</p>
<p><code>    allow</code> unknown class / permissions. This will set the returned AV with all 1's.</p>
<p><code>    deny</code> unknown class / permissions (the default). This will set the returned AV with all 0's.</p>
<p><code>    reject</code> loading the policy if it does not contain all the object classes / permissions.</p></td>
</tr>
</tbody>
</table>

**Example:**

This will allow unknown classes / permissions to be present in the policy:

    (handleunknown allow)

policycap
---------

Allow policy capabilities to be enabled via policy. These should be declared in the global namespace and be valid policy capabilities as they are checked against those known in libsepol by the CIL compiler.

**Statement definition:**

    (policycap policycap_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>policycap</code></p></td>
<td align="left"><p>The <code>policycap</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>policycap_id</code></p></td>
<td align="left"><p>The <code>policycap</code> identifier (e.g. <code>open_perms</code>).</p></td>
</tr>
</tbody>
</table>

**Example:**

These set two valid policy capabilities:

    ; Enable networking controls.
    (policycap network_peer_controls)

    ; Enable open permission check.
    (policycap open_perms)
