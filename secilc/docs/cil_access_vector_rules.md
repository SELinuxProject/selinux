Access Vector Rules
===================

allow
-----

Specifies the access allowed between a source and target type. Note that access may be refined by constraint rules based on the source, target and class ([`validatetrans`](cil_constraint_statements.md#validatetrans) or [`mlsvalidatetrans`](cil_constraint_statements.md#mlsvalidatetrans)) or source, target class and permissions ([`constrain`](cil_constraint_statements.md#constrain) or [`mlsconstrain`](cil_constraint_statements.md#mlsconstrain) statements).

**Rule definition:**

    (allow source_id target_id|self classpermissionset_id ...)

**Where:**

<table>
<colgroup>
<col width="27%" />
<col width="72%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>allow</code></p></td>
<td align="left"><p>The <code>allow</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>source_id</code></p></td>
<td align="left"><p>A single previously defined source <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>target_id</code></p></td>
<td align="left"><p>A single previously defined target <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p>
<p>The <code>self</code> keyword may be used instead to signify that source and target are the same.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>classpermissionset_id</code></p></td>
<td align="left"><p>A single named or anonymous <code>classpermissionset</code> or a single set of <code>classmap</code>/<code>classmapping</code> identifiers.</p></td>
</tr>
</tbody>
</table>

**Examples:**

These examples show a selection of possible permutations of [`allow`](cil_access_vector_rules.md#allow) rules:

    (class binder (impersonate call set_context_mgr transfer receive))
    (class property_service (set))
    (class zygote (specifyids specifyrlimits specifycapabilities specifyinvokewith specifyseinfo))

    (classpermission cps_zygote)
    (classpermissionset cps_zygote (zygote (not (specifyids))))

    (classmap android_classes (set_1 set_2 set_3))

    (classmapping android_classes set_1 (binder (all)))
    (classmapping android_classes set_1 (property_service (set)))
    (classmapping android_classes set_1 (zygote (not (specifycapabilities))))

    (classmapping android_classes set_2 (binder (impersonate call set_context_mgr transfer)))
    (classmapping android_classes set_2 (zygote (specifyids specifyrlimits specifycapabilities specifyinvokewith)))

    (classmapping android_classes set_3 cps_zygote)
    (classmapping android_classes set_3 (binder (impersonate call set_context_mgr)))

    (block av_rules
        (type type_1)
        (type type_2)
        (type type_3)
        (type type_4)
        (type type_5)

        (typeattribute all_types)
        (typeattributeset all_types (all))

    ; These examples have named and anonymous classpermissionset's and
    ; classmap/classmapping statements
        (allow type_1 self (property_service (set)))          ; anonymous
        (allow type_2 self (zygote (specifyids)))             ; anonymous
        (allow type_3 self cps_zygote)                        ; named
        (allow type_4 self (android_classes (set_3)))         ; classmap/classmapping
        (allow all_types all_types (android_classes (set_2))) ; classmap/classmapping

    ;; This rule will cause the build to fail unless --disable-neverallow
    ;    (neverallow type_5 all_types (property_service (set)))
        (allow type_5 type_5 (property_service (set)))
        (allow type_1 all_types (property_service (set)))
    )

auditallow
----------

Audit the access rights defined if there is a valid allow rule. Note: It does NOT allow access, it only audits the event.

**Rule definition:**

    (auditallow source_id target_id|self classpermissionset_id ...)

**Where:**

<table>
<colgroup>
<col width="29%" />
<col width="70%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>auditallow</code></p></td>
<td align="left"><p>The <code>auditallow</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>source_id</code></p></td>
<td align="left"><p>A single previously defined source <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>target_id</code></p></td>
<td align="left"><p>A single previously defined target <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p>
<p>The <code>self</code> keyword may be used instead to signify that source and target are the same.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>classpermissionset_id</code></p></td>
<td align="left"><p>A single named or anonymous <code>classpermissionset</code> or a single set of <code>classmap</code>/<code>classmapping</code> identifiers.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will log an audit event whenever the corresponding [`allow`](cil_access_vector_rules.md#allow) rule grants access to the specified permissions:

    (allow release_app.process secmark_demo.browser_packet (packet (send recv append bind)))

    (auditallow release_app.process secmark_demo.browser_packet (packet (send recv)))


dontaudit
---------

Do not audit the access rights defined when access denied. This stops excessive log entries for known events.

Note that these rules can be omitted by the CIL compiler command line parameter `-D` or `--disable-dontaudit` flags.

**Rule definition:**

    (dontaudit source_id target_id|self classpermissionset_id ...)

**Where:**

<table>
<colgroup>
<col width="27%" />
<col width="72%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>dontaudit</code></p></td>
<td align="left"><p>The <code>dontaudit</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>source_id</code></p></td>
<td align="left"><p>A single previously defined source <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>target_id</code></p></td>
<td align="left"><p>A single previously defined target <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p>
<p>The <code>self</code> keyword may be used instead to signify that source and target are the same.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>classpermissionset_id</code></p></td>
<td align="left"><p>A single named or anonymous <code>classpermissionset</code> or a single set of <code>classmap</code>/<code>classmapping</code> identifiers.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will not audit the denied access:

    (dontaudit zygote.process self (capability (fsetid)))

neverallow
----------

Never allow access rights defined. This is a compiler enforced action that will stop compilation until the offending rules are modified.

Note that these rules can be over-ridden by the CIL compiler command line parameter `-N` or `--disable-neverallow` flags.

**Rule definition:**

    (neverallow source_id target_id|self classpermissionset_id ...)

**Where:**

<table>
<colgroup>
<col width="27%" />
<col width="72%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>neverallow</code></p></td>
<td align="left"><p>The <code>neverallow</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>source_id</code></p></td>
<td align="left"><p>A single previously defined source <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>target_id</code></p></td>
<td align="left"><p>A single previously defined target <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p>
<p>The <code>self</code> keyword may be used instead to signify that source and target are the same.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>classpermissionset_id</code></p></td>
<td align="left"><p>A single named or anonymous <code>classpermissionset</code> or a single set of <code>classmap</code>/<code>classmapping</code> identifiers.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will not compile as `type_3` is not allowed to be a source type for the [`allow`](cil_access_vector_rules.md#allow) rule:

    (class property_service (set))

    (block av_rules
        (type type_1)
        (type type_2)
        (type type_3)
        (typeattribute all_types)
        (typeattributeset all_types ((all)))

        (neverallow type_3 all_types (property_service (set)))
        ; This rule will fail compilation:
        (allow type_3 self (property_service (set)))
    )

allowx
------

Specifies the access allowed between a source and target type using extended permissions. Unlike the [`allow`](cil_access_vector_rules.md#allow) statement, the statements [`validatetrans`](cil_constraint_statements.md#validatetrans), [`mlsvalidatetrans`](cil_constraint_statements.md#mlsvalidatetrans), [`constrain`](cil_constraint_statements.md#constrain), and [`mlsconstrain`](cil_constraint_statements.md#mlsconstrain) do not limit accesses granted by [`allowx`](cil_access_vector_rules.md#allowx).

**Rule definition:**

    (allowx source_id target_id|self permissionx_id)

**Where:**

<table>
<colgroup>
<col width="27%" />
<col width="72%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>allowx</code></p></td>
<td align="left"><p>The <code>allowx</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>source_id</code></p></td>
<td align="left"><p>A single previously defined source <code>type</code>, <code>typealias</code>, or <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>target_id</code></p></td>
<td align="left"><p>A single previously defined target <code>type</code>, <code>typealias</code>, or <code>typeattribute</code> identifier.</p>
<p>The <code>self</code> keyword may be used instead to signify that source and target are the same.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>permissionx_id</code></p></td>
<td align="left"><p>A single named or anonymous <code>permissionx</code>.</p></td>
</tr>
</tbody>
</table>

**Examples:**

These examples show a selection of possible permutations of [`allowx`](cil_access_vector_rules.md#allowx) rules:

    (allowx type_1 type_2 (ioctl tcp_socket (range 0x2000 0x20FF)))

    (permissionx ioctl_nodebug (ioctl udp_socket (not (range 0x4000 0x4010))))
    (allowx type_3 type_4 ioctl_nodebug)



auditallowx
-----------

Audit the access rights defined if there is a valid [`allowx`](cil_access_vector_rules.md#allowx) rule. It does NOT allow access, it only audits the event.

**Rule definition:**

    (auditallowx source_id target_id|self permissionx_id)

**Where:**

<table>
<colgroup>
<col width="27%" />
<col width="72%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>auditallowx</code></p></td>
<td align="left"><p>The <code>auditallowx</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>source_id</code></p></td>
<td align="left"><p>A single previously defined source <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>target_id</code></p></td>
<td align="left"><p>A single previously defined target <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p>
<p>The <code>self</code> keyword may be used instead to signify that source and target are the same.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>permissionx_id</code></p></td>
<td align="left"><p>A single named or anonymous <code>permissionx</code>.</p></td>
</tr>
</tbody>
</table>

**Examples:**

This example will log an audit event whenever the corresponding [`allowx`](cil_access_vector_rules.md#allowx) rule grants access to the specified extended permissions:

    (allowx type_1 type_2 (ioctl tcp_socket (range 0x2000 0x20FF)))

    (auditallowx type_1 type_2 (ioctl tcp_socket (range 0x2005 0x2010)))


dontauditx
----------

Do not audit the access rights defined when access denied. This stops excessive log entries for known events.

Note that these rules can be omitted by the CIL compiler command line parameter `-D` or `--disable-dontaudit` flags.

**Rule definition:**

    (dontauditx source_id target_id|self permissionx_id)

**Where:**

<table>
<colgroup>
<col width="27%" />
<col width="72%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>dontauditx</code></p></td>
<td align="left"><p>The <code>dontauditx</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>source_id</code></p></td>
<td align="left"><p>A single previously defined source <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>target_id</code></p></td>
<td align="left"><p>A single previously defined target <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p>
<p>The <code>self</code> keyword may be used instead to signify that source and target are the same.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>permissionx_id</code></p></td>
<td align="left"><p>A single named or anonymous <code>permissionx</code>.</p></td>
</tr>
</tbody>
</table>

**Examples:**

This example will not audit the denied access:

    (dontauditx type_1 type_2 (ioctl tcp_socket (range 0x3000 0x30FF)))


neverallowx
----------
Never allow access rights defined for extended permissions. This is a compiler enforced action that will stop compilation until the offending rules are modified.

Note that these rules can be over-ridden by the CIL compiler command line parameter `-N` or `--disable-neverallow` flags.

**Rule definition:**

    (neverallowx source_id target_id|self permissionx_id)

**Where:**

<table>
<colgroup>
<col width="27%" />
<col width="72%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>neverallows</code></p></td>
<td align="left"><p>The <code>neverallowx</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>source_id</code></p></td>
<td align="left"><p>A single previously defined source <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>target_id</code></p></td>
<td align="left"><p>A single previously defined target <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p>
<p>The <code>self</code> keyword may be used instead to signify that source and target are the same.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>permissionx_id</code></p></td>
<td align="left"><p>A single named or anonymous <code>permissionx</code>.</p></td>
</tr>
</tbody>
</table>

**Examples:**

This example will not compile as `type_3` is not allowed to be a source type and ioctl range for the [`allowx`](cil_access_vector_rules.md#allowx) rule:

	(class property_service (ioctl))
	(block av_rules
		(type type_1)
		(type type_2)
		(type type_3)
		(typeattribute all_types)
		(typeattributeset all_types ((all)))
		(neverallowx type_3 all_types (ioctl property_service (range 0x2000 0x20FF)))
		; This rule will fail compilation:
		(allowx type_3 self (ioctl property_service (0x20A0)))
	)
