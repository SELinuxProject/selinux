Class and Permission Statements
===============================

common
------

Declares a common identifier in the current namespace with a set of common permissions that can be used by one or more [`class`](cil_class_and_permission_statements.md#class) identifiers. The [`classcommon`](cil_class_and_permission_statements.md#classcommon) statement is used to associate a [`common`](cil_class_and_permission_statements.md#common) identifier to a specific [`class`](cil_class_and_permission_statements.md#class) identifier.

**Statement definition:**

```secil
    (common common_id (permission_id ...))
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>common</code></p></td>
<td align="left"><p>The <code>common</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>common_id</code></p></td>
<td align="left"><p>The <code>common</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>permission_id</code></p></td>
<td align="left"><p>One or more permissions.</p></td>
</tr>
</tbody>
</table>

**Example:**

This common statement will associate the [`common`](cil_class_and_permission_statements.md#common) identifier '`file`' with the list of permissions:

```secil
    (common file (ioctl read write create getattr setattr lock relabelfrom relabelto append unlink link rename execute swapon quotaon mounton))
```

classcommon
-----------

Associate a [`class`](cil_class_and_permission_statements.md#class) identifier to a one or more permissions declared by a [`common`](cil_class_and_permission_statements.md#common) identifier.

**Statement definition:**

```secil
    (classcommon class_id common_id)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>classcommon</code></p></td>
<td align="left"><p>The <code>classcommon</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>class_id</code></p></td>
<td align="left"><p>A single previously declared <code>class</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>common_id</code></p></td>
<td align="left"><p>A single previously declared <code>common</code> identifier that defines the common permissions for that class.</p></td>
</tr>
</tbody>
</table>

**Example:**

This associates the `dir` class with the list of permissions declared by the `file common` identifier:

```secil
    (common file (ioctl read write create getattr setattr lock relabelfrom relabelto append unlink link rename execute swapon quotaon mounton))

    (classcommon dir file)
```

class
-----

Declares a class and zero or more permissions in the current namespace.

**Statement definition:**

```secil
    (class class_id (permission_id ...))
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>class</code></p></td>
<td align="left"><p>The <code>class</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>class_id</code></p></td>
<td align="left"><p>The <code>class</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>permission_id</code></p></td>
<td align="left"><p>Zero or more permissions declared for the class. Note that if zero permissions, an empty list is required as shown in the example.</p></td>
</tr>
</tbody>
</table>

**Examples:**

This example defines a set of permissions for the `binder` class identifier:

```secil
    (class binder (impersonate call set_context_mgr transfer receive))
```

This example defines a common set of permissions to be used by the `sem` class, the `(class sem ())` does not define any other permissions (i.e. an empty list):

```secil
    (common ipc (create destroy getattr setattr read write associate unix_read unix_write))

    (classcommon sem ipc)
    (class sem ())
```

and will produce the following set of permissions for the `sem` class identifier of:

```secil
    (class sem (create destroy getattr setattr read write associate unix_read unix_write))
```

This example, with the following combination of the [`common`](cil_class_and_permission_statements.md#common), [`classcommon`](cil_class_and_permission_statements.md#classcommon) and [`class`](cil_class_and_permission_statements.md#class) statements:

```secil
    (common file (ioctl read write create getattr setattr lock relabelfrom relabelto append unlink link rename execute swapon quotaon mounton))

    (classcommon dir file)
    (class dir (add_name remove_name reparent search rmdir open audit_access execmod))
```

will produce a set of permissions for the `dir` class identifier of:

```secil
    (class dir (add_name remove_name reparent search rmdir open audit_access execmod ioctl read write create getattr setattr lock relabelfrom relabelto append unlink link rename execute swapon quotaon mounton))
```

classorder
----------

Defines the order of [class](#class)'s. This is a mandatory statement. Multiple [`classorder`](cil_class_and_permission_statements.md#classorder) statements declared in the policy will form an ordered list.

**Statement definition:**

```secil
    (classorder (class_id ...))
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>classorder</code></p></td>
<td align="left"><p>The <code>classorder</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>class_id</code></p></td>
<td align="left"><p>One or more <code>class</code> identifiers.</p></td>
</tr>
</tbody>
</table>

**Example:**

This will produce an ordered list of "`file dir process`"

```secil
    (class process)
    (class file)
    (class dir)
    (classorder (file dir))
    (classorder (dir process))
```

**Unordered Classorder Statement:**

If users do not have knowledge of the existing [`classorder`](#classorder), the `unordered` keyword may be used in a [`classorder`](#classorder) statement. The [classes](#class) in an unordered statement are appended to the existing [`classorder`](#classorder). A class in an ordered statement always supersedes the class redeclaration in an unordered statement. The `unordered` keyword must be the first item in the [`classorder`](#classorder) listing.

**Example:**

This will produce an unordered list of "`file dir foo a bar baz`"

```secil
	(class file)
	(class dir)
	(class foo)
	(class bar)
	(class baz)
	(class a)
	(classorder (file dir))
	(classorder (dir foo))
	(classorder (unordered a))
	(classorder (unordered bar foo baz))
```

classpermission
---------------

Declares a class permission set identifier in the current namespace that can be used by one or more [`classpermissionset`](cil_class_and_permission_statements.md#classpermissionset)s to associate one or more classes and permissions to form a named set.

**Statement definition:**

```secil
    (classpermission classpermissionset_id)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>classpermission</code></p></td>
<td align="left"><p>The <code>classpermission</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>classpermissionset_id</code></p></td>
<td align="left"><p>The <code>classpermissionset</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

See the [`classpermissionset`](cil_class_and_permission_statements.md#classpermissionset) statement for examples.

classpermissionset
------------------

Defines a class permission set identifier in the current namespace that associates a class and one or more permissions to form a named set. Nested expressions may be used to determine the required permissions as shown in the examples. Anonymous [`classpermissionset`](cil_class_and_permission_statements.md#classpermissionset)s may be used in av rules and constraints.

**Statement definition:**

```secil
    (classpermissionset classpermissionset_id (class_id (permission_id | expr ...)))
```

**Where:**

<table>
<colgroup>
<col width="27%" />
<col width="72%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>classpermissionset</code></p></td>
<td align="left"><p>The <code>classpermissionset</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>classpermissionset_id</code></p></td>
<td align="left"><p>The <code>classpermissionset</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>class_id</code></p></td>
<td align="left"><p>A single previously declared <code>class</code> identifier.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>permission_id</code></p></td>
<td align="left"><p>Zero or more permissions required by the class.</p>
<p>Note that there must be at least one <code>permission</code> identifier or <code>expr</code> declared).</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>expr</code></p></td>
<td align="left"><p>Zero or more <code>expr</code>'s, the valid operators and syntax are:</p>
<p><code>    (and (permission_id ...) (permission_id ...))</code></p>
<p><code>    (or  (permission_id ...) (permission_id ...))</code></p>
<p><code>    (xor (permission_id ...) (permission_id ...))</code></p>
<p><code>    (not (permission_id ...))</code></p>
<p><code>    (all)</code></p></td>
</tr>
</tbody>
</table>

**Examples:**

These class permission set statements will resolve to the permission sets shown in the kernel policy language [`allow`](cil_access_vector_rules.md#allow) rules:

```secil
    (class zygote (specifyids specifyrlimits specifycapabilities specifyinvokewith specifyseinfo))

    (type test_1)
    (type test_2)
    (type test_3)
    (type test_4)
    (type test_5)

    ; NOT
    (classpermission zygote_1)
    (classpermissionset zygote_1 (zygote
        (not
            (specifyinvokewith specifyseinfo)
        )
    ))
    (allow unconfined.process test_1 zygote_1)
    ;; allow unconfined.process test_1 : zygote { specifyids specifyrlimits specifycapabilities } ;

    ; AND - ALL - NOT - Equiv to test_1
    (classpermission zygote_2)
    (classpermissionset zygote_2 (zygote
        (and
            (all)
            (not (specifyinvokewith specifyseinfo))
        )
    ))
    (allow unconfined.process test_2 zygote_2)
    ;; allow unconfined.process test_2 : zygote { specifyids specifyrlimits specifycapabilities  } ;

    ; OR
    (classpermission zygote_3)
    (classpermissionset zygote_3 (zygote ((or (specifyinvokewith) (specifyseinfo)))))
    (allow unconfined.process test_3 zygote_3)
    ;; allow unconfined.process test_3 : zygote { specifyinvokewith specifyseinfo } ;

    ; XOR - This will not produce an allow rule as the XOR will remove all the permissions:
    (classpermission zygote_4)
    (classpermissionset zygote_4 (zygote (xor (specifyids specifyrlimits specifycapabilities specifyinvokewith specifyseinfo) (specifyids specifyrlimits specifycapabilities specifyinvokewith specifyseinfo))))

    ; ALL
    (classpermission zygote_all_perms)
    (classpermissionset zygote_all_perms (zygote (all)))
    (allow unconfined.process test_5 zygote_all_perms)
    ;; allow unconfined.process test_5 : zygote { specifyids specifyrlimits specifycapabilities specifyinvokewith specifyseinfo } ;
```

classmap
--------

Declares a class map identifier in the current namespace and one or more class mapping identifiers. This will allow:

1.  Multiple [`classpermissionset`](cil_class_and_permission_statements.md#classpermissionset)s to be linked to a pair of [`classmap`](cil_class_and_permission_statements.md#classmap) / [`classmapping`](cil_class_and_permission_statements.md#classmapping) identifiers.

2.  Multiple [`class`](cil_class_and_permission_statements.md#class)s to be associated to statements and rules that support a list of classes:

    typetransition
    typechange
    typemember
    rangetransition
    roletransition
    defaultuser
    defaultrole
    defaulttype
    defaultrange
    validatetrans
    mlsvalidatetrans

**Statement definition:**

```secil
    (classmap classmap_id (classmapping_id ...))
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>classmap</code></p></td>
<td align="left"><p>The <code>classmap</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>classmap_id</code></p></td>
<td align="left"><p>The <code>classmap</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>classmapping_id</code></p></td>
<td align="left"><p>One or more <code>classmapping</code> identifiers.</p></td>
</tr>
</tbody>
</table>

**Example:**

See the [`classmapping`](cil_class_and_permission_statements.md#classmapping) statement for examples.

classmapping
------------

Define sets of [`classpermissionset`](cil_class_and_permission_statements.md#classpermissionset)s (named or anonymous) to form a consolidated [`classmapping`](cil_class_and_permission_statements.md#classmapping) set. Generally there are multiple [`classmapping`](cil_class_and_permission_statements.md#classmapping) statements with the same [`classmap`](cil_class_and_permission_statements.md#classmap) and [`classmapping`](cil_class_and_permission_statements.md#classmapping) identifiers that form a set of different [`classpermissionset`](cil_class_and_permission_statements.md#classpermissionset)'s. This is useful when multiple class / permissions are required in rules such as the [`allow`](cil_access_vector_rules.md#allow) rules (as shown in the examples).

**Statement definition:**

```secil
    (classmapping classmap_id classmapping_id classpermissionset_id)
```

**Where:**

<table>
<colgroup>
<col width="27%" />
<col width="72%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>classmapping</code></p></td>
<td align="left"><p>The <code>classmapping</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>classmap_id</code></p></td>
<td align="left"><p>A single previously declared <code>classmap</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>classmapping_id</code></p></td>
<td align="left"><p>The <code>classmapping</code> identifier.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>classpermissionset_id</code></p></td>
<td align="left"><p>A single named <code>classpermissionset</code> identifier or a single anonymous <code>classpermissionset</code> using <code>expr</code>'s as required (see the <code>classpermissionset</code> statement).</p></td>
</tr>
</tbody>
</table>

**Examples:**

These class mapping statements will resolve to the permission sets shown in the kernel policy language [`allow`](cil_access_vector_rules.md#allow) rules:

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

    (block map_example
        (type type_1)
        (type type_2)
        (type type_3)

        (allow type_1 self (android_classes (set_1)))
        (allow type_2 self (android_classes (set_2)))
        (allow type_3 self (android_classes (set_3)))
    )

    ; The above will resolve to the following AV rules:
    ;; allow map_example.type_1 map_example.type_1 : binder { impersonate call set_context_mgr transfer receive } ;
    ;; allow map_example.type_1 map_example.type_1 : property_service set ;
    ;; allow map_example.type_1 map_example.type_1 : zygote { specifyids specifyrlimits specifyinvokewith specifyseinfo } ;

    ;; allow map_example.type_2 map_example.type_2 : binder { impersonate call set_context_mgr transfer } ;
    ;; allow map_example.type_2 map_example.type_2 : zygote { specifyids specifyrlimits specifycapabilities specifyinvokewith } ;

    ;; allow map_example.type_3 map_example.type_3 : binder { impersonate call set_context_mgr } ;
    ;; allow map_example.type_3 map_example.type_3 : zygote { specifyrlimits specifycapabilities specifyinvokewith specifyseinfo } ;
```

permissionx
-----------

Defines a named extended permission, which can be used in the [`allowx`](cil_access_vector_rules.md#allowx), [`auditallowx`](cil_access_vector_rules.md#auditallowx), [`dontauditx`](cil_access_vector_rules.md#dontauditx), and  [`neverallowx`](cil_access_vector_rules.md#neverallowx) statements.

**Statement definition:**

```secil
    (permissionx permissionx_id (kind class_id (permission ... | expr ...)))
```

**Where:**

<table>
<colgroup>
<col width="27%" />
<col width="72%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>permissionx</code></p></td>
<td align="left"><p>The <code>permissionx</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>kind</code></p></td>
<td align="left"><p>A keyword specifying how to interpret the extended permission values. Must be one of:</p>
<table>
<thead>
<tr class="header">
<th align="left"><p><strong>kind</strong></p></th>
<th align="left"><p><strong>description</strong></p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td align="left"><p>ioctl</p></td>
<td align="left"><p>Permissions define a whitelist of ioctl values. Permission values must range from <code>0x0000</code> to <code>0xFFFF</code>, inclusive.</p></td>
</tr>
</tbody>
</table></td>
</tr>
<tr class="odd">
<td align="left"><p><code>class_id</code></p></td>
<td align="left"><p>A single previously declared <code>class</code> or <code>classmap</code> identifier.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>permission</code></p></td>
<td align="left"><p>One or more numeric values, specified in decimal, or hexadecimal if prefixed with 0x, or octal if prefixed with 0. Values are interpreted based on the value of <code>kind</code>.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>expr</code></p></td>
<td align="left"><p>An expression, with valid operators and syntax:</p>
<p><code>    (range (permission ...) (permission ...))</code></p>
<p><code>    (and (permission ...) (permission ...))</code></p>
<p><code>    (or  (permission ...) (permission ...))</code></p>
<p><code>    (xor (permission ...) (permission ...))</code></p>
<p><code>    (not (permission ...))</code></p>
<p><code>    (all)</code></p></td>
</tr>
</tbody>
</table>

**Examples:**

```secil
    (permissionx ioctl_1 (ioctl tcp_socket (0x2000 0x3000 0x4000)))
    (permissionx ioctl_2 (ioctl tcp_socket (range 0x6000 0x60FF)))
    (permissionx ioctl_3 (ioctl tcp_socket (and (range 0x8000 0x90FF) (not (range 0x8100 0x82FF)))))
```
