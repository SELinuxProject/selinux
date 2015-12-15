Type Statements
===============

type
----

Declares a type identifier in the current namespace.

**Statement definition:**

    (type type_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>type</code></p></td>
<td align="left"><p>The <code>type</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>type_id</code></p></td>
<td align="left"><p>The <code>type</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example declares a type identifier `bluetooth.process`:

    (block bluetooth
        (type process)
    )

typealias
---------

Declares a type alias in the current namespace.

**Statement definition:**

    (typealias typealias_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>typealias</code></p></td>
<td align="left"><p>The <code>typealias</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>typealias_id</code></p></td>
<td align="left"><p>The <code>typealias</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

See the [`typealiasactual`](cil_type_statements.md#typealiasactual) statement for an example that associates the [`typealias`](cil_type_statements.md#typealias) identifier.

typealiasactual
---------------

Associates a previously declared [`typealias`](cil_type_statements.md#typealias) identifier to a previously declared [`type`](cil_type_statements.md#type) identifier.

**Statement definition:**

    (typealiasactual typealias_id type_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>typealiasactual</code></p></td>
<td align="left"><p>The <code>typealiasactual</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>typealias_id</code></p></td>
<td align="left"><p>A single previously declared <code>typealias</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>type_id</code></p></td>
<td align="left"><p>A single previously declared <code>type</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will alias `unconfined.process` as `unconfined_t` in the global namespace:

    (typealias unconfined_t)
    (typealiasactual unconfined_t unconfined.process)

    (block unconfined
        (type process)
    )

typeattribute
-------------

Declares a type attribute identifier in the current namespace. The identifier may have zero or more [`type`](cil_type_statements.md#type), [`typealias`](cil_type_statements.md#typealias) and [`typeattribute`](cil_type_statements.md#typeattribute) identifiers associated to it via the [`typeattributeset`](cil_type_statements.md#typeattributeset) statement.

**Statement definition:**

    (typeattribute typeattribute_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>typeattribute</code></p></td>
<td align="left"><p>The <code>typeattribute</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>typeattribute_id</code></p></td>
<td align="left"><p>The <code>typeattribute</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example declares a type attribute `domain` in global namespace that will have an empty set:

    (typeattribute domain)

typeattributeset
----------------

Allows the association of one or more previously declared [`type`](cil_type_statements.md#type), [`typealias`](cil_type_statements.md#typealias) or [`typeattribute`](cil_type_statements.md#typeattribute) identifiers to a [`typeattribute`](cil_type_statements.md#typeattribute) identifier. Expressions may be used to refine the associations as shown in the examples.

**Statement definition:**

    (typeattributeset typeattribute_id (type_id ... | expr ...))

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>typeattributeset</code></p></td>
<td align="left"><p>The <code>typeattributeset</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>typeattribute_id</code></p></td>
<td align="left"><p>A single previously declared <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>type_id</code></p></td>
<td align="left"><p>Zero or more previously declared <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifiers.</p>
<p>Note that there must be at least one <code>type_id</code> or <code>expr</code> parameter declared.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>expr</code></p></td>
<td align="left"><p>Zero or more <code>expr</code>'s, the valid operators and syntax are:</p>
<p><code>    (and (type_id ...) (type_id ...))</code></p>
<p><code>    (or  (type_id ...) (type_id ...))</code></p>
<p><code>    (xor (type_id ...) (type_id ...))</code></p>
<p><code>    (not (type_id ...))</code></p>
<p><code>    (all)</code></p></td>
</tr>
</tbody>
</table>

**Examples:**

This example will take all the policy types and exclude those in `appdomain`. It is equivalent to `~appdomain` in the kernel policy language.

    (typeattribute not_in_appdomain)

    (typeattributeset not_in_appdomain (not (appdomain)))

This example is equivalent to `{ domain -kernel.process -ueventd.process -init.process }` in the kernel policy language:

    (typeattribute na_kernel_or_ueventd_or_init_in_domain)

    (typeattributeset na_kernel_or_ueventd_or_init_in_domain
        (and
            (and
                (and
                    (domain)
                    (not (kernel.process))
                )
                (not (ueventd.process))
            )
            (not (init.process))
        )
    )

typebounds
----------

This defines a hierarchical relationship between domains where the bounded domain cannot have more permissions than its bounding domain (the parent).

Requires kernel 2.6.28 and above to control the security context associated to threads in multi-threaded applications. Note that an [`allow`](cil_access_vector_rules.md#allow) rule must be used to authorise the bounding.

**Statement definition:**

    (typebounds parent_type_id child_type_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>typebounds</code></p></td>
<td align="left"><p>The <code>typebounds</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>parent_type_id</code></p></td>
<td align="left"><p>A single previously declared <code>type</code> or <code>typealias</code> identifier that is the parent domain.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>child_type_id</code></p></td>
<td align="left"><p>A single previously declared <code>type</code> or <code>typealias</code> identifier that is the bound (child) domain.</p></td>
</tr>
</tbody>
</table>

**Example:**

In this example the `httpd.child.process` cannot have `file (write)` due to lack of permissions on `httpd.process` which is the parent. It means the child domain will always have equal or less privileges than the parent:

    (class file (getattr read write))

    (block httpd
        (type process)
        (type object)

        (typebounds process child.process)
        ; The parent is allowed file 'getattr' and 'read':
        (allow process object (file (getattr read)))

        (block child
            (type process)
            (type object)

            ; However the child process has been given 'write' access that will be denied.
            (allow process httpd.object (file (read write)))
        )
    )

typechange
----------

The type change rule is used to define a different label of an object for userspace SELinux-aware applications. These applications would use **`security_compute_relabel`**`(3)` and [`typechange`](cil_type_statements.md#typechange) rules in the policy to determine the new context to be applied. Note that an [`allow`](cil_access_vector_rules.md#allow) rule must be used to authorise the change.

**Statement definition:**

    (typechange source_type_id target_type_id class_id change_type_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>typechange</code></p></td>
<td align="left"><p>The <code>typechange</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>source_type_id</code></p></td>
<td align="left"><p>A single previously declared <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>target_type_id</code></p></td>
<td align="left"><p>A single previously declared <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>class_id</code></p></td>
<td align="left"><p>A single previously declared <code>class</code> or <code>classmap</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>change_type_id</code></p></td>
<td align="left"><p>A single previously declared <code>type</code> or <code>typealias</code> identifier that will become the new type.</p></td>
</tr>
</tbody>
</table>

**Example:**

Whenever **`security_compute_relabel`**`(3)` is called with the following parameters:

`    scon=unconfined.object tcon=unconfined.object class=file`

the function will return a context of:

`    unconfined.object:object_r:unconfined.change_label:s0`

    (class file (getattr read write))

    (block unconfined
        (type process)
        (type object)
        (type change_label)

        (typechange object object file change_label)
    )

typemember
----------

The type member rule is used to define a new polyinstantiated label of an object for SELinux-aware applications. These applications would use **`avc_compute_member`**`(3)` or **`security_compute_member`**`(3)` with the [`typemember`](cil_type_statements.md#typemember) rules in the policy to determine the context to be applied. The application would then manage any required polyinstantiation. Note that an [`allow`](cil_access_vector_rules.md#allow) rule must be used to authorise the membership.

**Statement definition:**

    (typemember source_type_id target_type_id class_id member_type_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>typemember</code></p></td>
<td align="left"><p>The <code>typemember</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>source_type_id</code></p></td>
<td align="left"><p>A single previously declared <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>target_type_id</code></p></td>
<td align="left"><p>A single previously declared <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>class_id</code></p></td>
<td align="left"><p>A single previously declared <code>class</code> or <code>classmap</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>member_type_id</code></p></td>
<td align="left"><p>A single previously declared <code>type</code> or <code>typealias</code> identifier that will become the new member type.</p></td>
</tr>
</tbody>
</table>

**Example:**

Whenever **`avc_compute_member`**`(3)` or **`security_compute_member`**`(3)` is called with the following parameters:

`    scon=unconfined.object tcon=unconfined.object class=file`

the function will return a context of:

`    unconfined.object:object_r:unconfined.member_label:s0`

    (class file (getattr read write))

    (block unconfined
        (type process)
        (type object)
        (type change_label)

        (typemember object object file member_label)
    )

typetransition
--------------

The type transition rule specifies the labeling and object creation allowed between the `source_type` and `target`\_type when a domain transition is requested. Kernels from 2.6.39 with policy versions from 25 and above also support a 'name transition' rule, however this is not allowed inside conditionals and currently only supports the file classes. Note that an [`allow`](cil_access_vector_rules.md#allow) rule must be used to authorise the transition.

**Statement definition:**

    (typetransition source_type_id target_type_id class_id [object_name] default_type_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>typetransition</code></p></td>
<td align="left"><p>The <code>typetransition</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>source_type_id</code></p></td>
<td align="left"><p>A single previously declared <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>target_type_id</code></p></td>
<td align="left"><p>A single previously declared <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>class_id</code></p></td>
<td align="left"><p>A single previously declared <code>class</code> or <code>classmap</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>object_name</code></p></td>
<td align="left"><p>A optional string within double quotes representing an object name for the 'name transition' rule. This string will be matched against the objects name (if a path then the last component of that path). If the string matches exactly, the <code>default_type_id</code> will then become the new type.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>default_type_id</code></p></td>
<td align="left"><p>A single previously declared <code>type</code> or <code>typealias</code> identifier that will become the new type.</p></td>
</tr>
</tbody>
</table>

**Examples:**

This example shows a process transition rule with its supporting [`allow`](cil_access_vector_rules.md#allow) rule:

    (macro domain_auto_trans ((type ARG1) (type ARG2) (type ARG3))
        ; Allow the necessary permissions.
        (call domain_trans (ARG1 ARG2 ARG3))
        ; Make the transition occur by default.
        (typetransition ARG1 ARG2 process ARG3)
    )

This example shows a file object transition rule with its supporting [`allow`](cil_access_vector_rules.md#allow) rule:

    (macro tmpfs_domain ((type ARG1))
        (type tmpfs)
        (typeattributeset file_type (tmpfs))
        (typetransition ARG1 file.tmpfs file tmpfs)
        (allow ARG1 tmpfs (file (read write execute execmod)))
    )

This example shows the 'name transition' rule with its supporting [`allow`](cil_access_vector_rules.md#allow) rule:

    (macro write_klog ((type ARG1))
        (typetransition ARG1 device.device chr_file "__kmsg__" device.klog_device)
        (allow ARG1 device.klog_device (chr_file (create open write unlink)))
        (allow ARG1 device.device (dir (write add_name remove_name)))
    )

typepermissive
--------------

Policy database version 23 introduced the permissive statement to allow the named domain to run in permissive mode instead of running all SELinux domains in permissive mode (that was the only option prior to version 23). Note that the permissive statement only tests the source context for any policy denial.

**Statement definition:**

    (typepermissive source_type_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>typepermissive</code></p></td>
<td align="left"><p>The <code>typepermissive</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>source_type_id</code></p></td>
<td align="left"><p>A single previously declared <code>type</code> or <code>typealias</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will allow SELinux to run the `healthd.process` domain in permissive mode even when enforcing is enabled:

    (block healthd
        (type process)
        (typepermissive process)

        (allow ...)
    )
