Access Vector Rules
===================

Rules involving a source type, a target type, and class permissions or extended permissions.

**Rule definition:**

```secil
    (av_flavor source_id target_id|self|notself|other classpermission_id|permissionx_id)
```

**Where:**

<table>
<colgroup>
<col width="27%" />
<col width="72%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>av_flavor</code></p></td>
<td align="left"><p>The flavor of access vector rule. Possible flavors are <code>allow</code>, <code>auditallow</code>, <code>dontaudit</code>, <code>neverallow</code>, <code>deny</code>, <code>allowx</code>, <code>auditallowx</code>, <code>dontauditx</code>, and <code>neverallowx</code>.</p></td>
<tr class="even">
<td align="left"><p><code>source_id</code></p></td>
<td align="left"><p>A single previously defined source <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>target_id</code></p></td>
<td align="left"><p>A single previously defined target <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p>
<p> Instead it can be one of the special keywords <code>self</code>, <code>notself</code> or <code>other</code>.</p>
<p>The <code>self</code> keyword may be used to signify that source and target are the same. If the source is an attribute, each type of the source will be paired with itself as the target. The <code>notself</code> keyword may be used to signify that the target is all types except for the types of the source. The <code>other</code> keyword may be used as a short-hand way of writing a rule for each type of the source where it is paired with all of the other types of the source as the target.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>classpermission_id</code></p></td>
<td align="left"><p>A single named or anonymous <code>classpermissionset</code> or a single set of <code>classmap</code>/<code>classmapping</code> identifiers. Used for <code>allow</code>, <code>auditallow</code>, <code>dontaudit</code>, <code>neverallow</code> rules.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>permissionx_id</code></p></td>
<td align="left"><p>A single named or anonymous <code>permissionx</code>. Used for <code>allowx</code>, <code>auditallowx</code>, <code>dontauditx</code>, <code>neverallowx</code> rules.</p></td>
</tr>
</tbody>
</table>

allow
-----

Specifies the access allowed between a source and target type. Note that access may be refined by constraint rules based on the source, target and class ([`validatetrans`](cil_constraint_statements.md#validatetrans) or [`mlsvalidatetrans`](cil_constraint_statements.md#mlsvalidatetrans)) or source, target class and permissions ([`constrain`](cil_constraint_statements.md#constrain) or [`mlsconstrain`](cil_constraint_statements.md#mlsconstrain) statements).

**Rule definition:**

```secil
    (allow source_id target_id|self|notself|other classpermissionset_id ...)
```

**Examples:**

These examples show a selection of possible permutations of [`allow`](cil_access_vector_rules.md#allow) rules:

```secil
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
```

auditallow
----------

Audit the access rights defined if there is a valid allow rule. Note: It does NOT allow access, it only audits the event.

**Rule definition:**

```secil
    (auditallow source_id target_id|self|notself|other classpermissionset_id)
```

**Example:**

This example will log an audit event whenever the corresponding [`allow`](cil_access_vector_rules.md#allow) rule grants access to the specified permissions:

```secil
    (allow release_app.process secmark_demo.browser_packet (packet (send recv append bind)))

    (auditallow release_app.process secmark_demo.browser_packet (packet (send recv)))
```

dontaudit
---------

Do not audit the access rights defined when access denied. This stops excessive log entries for known events.

Note that these rules can be omitted by the CIL compiler command line parameter `-D` or `--disable-dontaudit` flags.

**Rule definition:**

```secil
    (dontaudit source_id target_id|self|notself|other classpermissionset_id ...)
```

**Example:**

This example will not audit the denied access:

```secil
    (dontaudit zygote.process self (capability (fsetid)))
```

neverallow
----------

Never allow access rights defined. This is a compiler enforced action that will stop compilation until the offending rules are modified.

Note that these rules can be over-ridden by the CIL compiler command line parameter `-N` or `--disable-neverallow` flags.

**Rule definition:**

```secil
    (neverallow source_id target_id|self|notself|other classpermissionset_id ...)
```

**Example:**

This example will not compile as `type_3` is not allowed to be a source type for the [`allow`](cil_access_vector_rules.md#allow) rule:

```secil
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
```
deny
----------

Remove the access rights defined from any matching allow rules. These rules are processed before [`neverallow`](cil_access_vector_rules.md#neverallow) checking.

**Rule definition:**

```secil
    (deny source_id target_id|self classpermissionset_id ...)
```

**Example:**

```secil
    (class class1 (perm1 perm2))

    (type type1)
    (type type2)
    (allow type1 type2 (class1 (perm1))) ; Allow-1
    (deny type1 type2 (class1 (perm1)))  ; Deny-1
    ; Allow-1 will be complete removed by Deny-1.

    (type type3)
    (type type4)
    (allow type3 type4 (class1 (perm1 perm2))) ; Allow-2
    (deny type3 type4 (class1 (perm1)))        ; Deny-2
    ; Allow-2 will be removed and replaced with the following when Deny-2 is evaluated
    ; (allow type3 type4 (class1 (perm2)))

    (type type5)
    (type type6)
    (typeattribute attr1)
    (typeattributeset attr1 (type5 type6))
    (allow attr1 attr1 (class1 (perm1))) ; Allow-3
    (deny type5 type6 (class1 (perm1)))  ; Deny-3
    ; Allow-3 will be removed and replaced with the following when Deny-3 is evaluated
    ; (allow type6 attr1 (class1 (perm1)))
    ; (allow type5 type5 (class1 (perm1)))
```

allowx
------

Specifies the access allowed between a source and target type using extended permissions. Unlike the [`allow`](cil_access_vector_rules.md#allow) statement, the statements [`validatetrans`](cil_constraint_statements.md#validatetrans), [`mlsvalidatetrans`](cil_constraint_statements.md#mlsvalidatetrans), [`constrain`](cil_constraint_statements.md#constrain), and [`mlsconstrain`](cil_constraint_statements.md#mlsconstrain) do not limit accesses granted by [`allowx`](cil_access_vector_rules.md#allowx).

Note that for this to work there must *also* be valid equivalent [`allow`](cil_access_vector_rules.md#allow) rules present.

**Rule definition:**

```secil
    (allowx source_id target_id|self|notself|other permissionx_id)
```

**Examples:**

These examples show a selection of possible permutations of [`allowx`](cil_access_vector_rules.md#allowx) rules:

```secil
    (allow type_1 type_2 (tcp_socket (ioctl))) ;; pre-requisite
    (allowx type_1 type_2 (ioctl tcp_socket (range 0x2000 0x20FF)))

    (permissionx ioctl_nodebug (ioctl udp_socket (not (range 0x4000 0x4010))))
    (allow type_3 type_4 (udp_socket (ioctl))) ;; pre-requisite
    (allowx type_3 type_4 ioctl_nodebug)
```


auditallowx
-----------

Audit the access rights defined if there is a valid [`allowx`](cil_access_vector_rules.md#allowx) rule. It does NOT allow access, it only audits the event.

Note that for this to work there must *also* be valid equivalent [`auditallow`](cil_access_vector_rules.md#auditallow) rules present.

**Rule definition:**

```secil
    (auditallowx source_id target_id|self|notself|other permissionx_id)
```

**Examples:**

This example will log an audit event whenever the corresponding [`allowx`](cil_access_vector_rules.md#allowx) rule grants access to the specified extended permissions:

```secil
    (allowx type_1 type_2 (ioctl tcp_socket (range 0x2000 0x20FF)))

    (auditallow type_1 type_2 (tcp_socket (ioctl))) ;; pre-requisite
    (auditallowx type_1 type_2 (ioctl tcp_socket (range 0x2005 0x2010)))
```

dontauditx
----------

Do not audit the access rights defined when access denied. This stops excessive log entries for known events.

Note that for this to work there must *also* be at least one [`allowx`](cil_access_vector_rules.md#allowx) rule associated with the target type.

Note that these rules can be omitted by the CIL compiler command line parameter `-D` or `--disable-dontaudit` flags.

**Rule definition:**

```secil
    (dontauditx source_id target_id|self|notself|other permissionx_id)
```

**Examples:**

This example will not audit the denied access:

```secil
    (allowx type_1 type_2 (ioctl tcp_socket (0x1))) ;; pre-requisite, just some irrelevant random ioctl
    (dontauditx type_1 type_2 (ioctl tcp_socket (range 0x3000 0x30FF)))
```

neverallowx
----------
Never allow access rights defined for extended permissions. This is a compiler enforced action that will stop compilation until the offending rules are modified.

Note that these rules can be over-ridden by the CIL compiler command line parameter `-N` or `--disable-neverallow` flags.

**Rule definition:**

```secil
    (neverallowx source_id target_id|self|notself|other permissionx_id)
```

**Examples:**

This example will not compile as `type_3` is not allowed to be a source type and ioctl range for the [`allowx`](cil_access_vector_rules.md#allowx) rule:

```secil
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
```
