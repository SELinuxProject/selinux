Default Object Statements
=========================

These rules allow a default user, role, type and/or range to be used when computing a context for a new object. These require policy version 27 or 28 with kernels 3.5 or greater.

defaultuser
-----------

Allows the default user to be taken from the source or target context when computing a new context for the object [`class`](cil_class_and_permission_statements.md#class) identifier. Requires policy version 27.

**Statement definition:**

```secil
    (defaultuser class_id default)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>defaultuser</code></p></td>
<td align="left"><p>The <code>defaultuser</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>class_id</code></p></td>
<td align="left"><p>A single previously declared <code>class</code> or <code>classmap</code> identifier, or a list of previously declared <code>class</code> or <code>classmap</code> identifiers enclosed within parentheses.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>default</code></p></td>
<td align="left"><p>A keyword of either <code>source</code> or <code>target</code>.</p></td>
</tr>
</tbody>
</table>

**Example:**

When creating new `binder`, `property_service`, `zygote` or `memprotect` objects the [`user`](cil_user_statements.md#user) component of the new security context will be taken from the `source` context:

```secil
    (class binder (impersonate call set_context_mgr transfer receive))
    (class property_service (set))
    (class zygote (specifyids specifyrlimits specifycapabilities specifyinvokewith specifyseinfo))
    (class memprotect (mmap_zero))

    (classmap android_classes (android))
    (classmapping android_classes android (binder (all)))
    (classmapping android_classes android (property_service (set)))
    (classmapping android_classes android (zygote (not (specifycapabilities))))

    (defaultuser (android_classes memprotect) source)

    ; Will produce the following in the binary policy file:
    ;; default_user binder source;
    ;; default_user zygote source;
    ;; default_user property_service source;
    ;; default_user memprotect source;
```

defaultrole
-----------

Allows the default role to be taken from the source or target context when computing a new context for the object [`class`](cil_class_and_permission_statements.md#class) identifier. Requires policy version 27.

```secil
    (defaultrole class_id default)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>defaultrole</code></p></td>
<td align="left"><p>The <code>defaultrole</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>class_id</code></p></td>
<td align="left"><p>A single previously declared <code>class</code> or <code>classmap</code> identifier, or a list of previously declared <code>class</code> or <code>classmap</code> identifiers enclosed within parentheses.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>default</code></p></td>
<td align="left"><p>A keyword of either <code>source</code> or <code>target</code>.</p></td>
</tr>
</tbody>
</table>

**Example:**

When creating new `binder`, `property_service` or `zygote` objects the [`role`](cil_role_statements.md#role) component of the new security context will be taken from the `target` context:

```secil
    (class binder (impersonate call set_context_mgr transfer receive))
    (class property_service (set))
    (class zygote (specifyids specifyrlimits specifycapabilities specifyinvokewith specifyseinfo))

    (defaultrole (binder property_service zygote) target)

    ; Will produce the following in the binary policy file:
    ;; default_role binder target;
    ;; default_role zygote target;
    ;; default_role property_service target;
```

defaulttype
-----------

Allows the default type to be taken from the source or target context when computing a new context for the object [`class`](cil_class_and_permission_statements.md#class) identifier. Requires policy version 28.

**Statement definition:**

```secil
    (defaulttype class_id default)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>defaulttype</code></p></td>
<td align="left"><p>The <code>defaulttype</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>class_id</code></p></td>
<td align="left"><p>A single previously declared <code>class</code> or <code>classmap</code> identifier, or a list of previously declared <code>class</code> or <code>classmap</code> identifiers enclosed within parentheses.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>default</code></p></td>
<td align="left"><p>A keyword of either <code>source</code> or <code>target</code>.</p></td>
</tr>
</tbody>
</table>

**Example:**

When creating a new `socket` object, the [`type`](cil_type_statements.md#type) component of the new security context will be taken from the `source` context:

```secil
    (defaulttype socket source)
```

defaultrange
------------

Allows the default level or range to be taken from the source, target, or both contexts when computing a new context for the object [`class`](cil_class_and_permission_statements.md#class) identifier. Requires policy version 27. glblub as the default requires policy version 32.

**Statement definition:**

```secil
    (defaultrange class_id default <range>)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>defaultrange</code></p></td>
<td align="left"><p>The <code>defaultrange</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>class_id</code></p></td>
<td align="left"><p>A single previously declared <code>class</code> or <code>classmap</code> identifier, or a list of previously declared <code>class</code> or <code>classmap</code> identifiers enclosed within parentheses.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>default</code></p></td>
<td align="left"><p>A keyword of either <code>source</code>, <code>target</code>, or <code>glblub</code>.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>range</code></p></td>
<td align="left"><p>A keyword of either <code>low</code>, <code>high</code>, or <code>low-high</code>.</p></td>
</tr>
</tbody>
</table>

**Example:**

When creating a new `file` object, the appropriate `range` component of the new security context will be taken from the `target` context:

```secil
    (defaultrange file target low_high)
```

MLS userspace object managers may need to compute the common parts of a range such that the object is created with the range common to the subject and containing object:

```secil
    (defaultrange db_table glblub)
```
