User Statements
===============

user
----

Declares an SELinux user identifier in the current namespace.

**Statement definition:**

```secil
    (user user_id)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>user</code></p></td>
<td align="left"><p>The <code>user</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>user_id</code></p></td>
<td align="left"><p>The SELinux <code>user</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

This will declare an SELinux user as `unconfined.user`:

```secil
    (block unconfined
        (user user)
    )
```

userrole
--------

Associates a previously declared [`user`](cil_user_statements.md#user) identifier with a previously declared [`role`](cil_role_statements.md#role) identifier.

**Statement definition:**

```secil
    (userrole user_id role_id)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>userrole</code></p></td>
<td align="left"><p>The <code>userrole</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>user_id</code></p></td>
<td align="left"><p>A previously declared SELinux <code>user</code> or <code>userattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>role_id</code></p></td>
<td align="left"><p>A previously declared <code>role</code> or <code>roleattribute</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will associate `unconfined.user` to `unconfined.role`:

```secil
    (block unconfined
        (user user)
        (role role)
        (userrole user role)
    )
```

userattribute
-------------

Declares a user attribute identifier in the current namespace. The identifier may have zero or more [`user`](cil_user_statements.md#user) and [`userattribute`](cil_user_statements.md#userattribute) identifiers associated to it via the [`userattributeset`](cil_user_statements.md#userattributeset) statement.

**Statement definition:**

```secil
    (userattribute userattribute_id)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>userattribute</code></p></td>
<td align="left"><p>The <code>userattribute</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>userattribute_id</code></p></td>
<td align="left"><p>The <code>userattribute</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will declare a user attribute `users.user_holder` that will have an empty set:

```secil
    (block users
        (userattribute user_holder)
    )
```

userattributeset
----------------

Allows the association of one or more previously declared [`user`](cil_user_statements.md#user) or [`userattribute`](cil_user_statements.md#userattribute) identifiers to a [`userattribute`](cil_user_statements.md#userattribute) identifier. Expressions may be used to refine the associations as shown in the examples.

**Statement definition:**

```secil
    (userattributeset userattribute_id (user_id ... | expr ...))
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>userattributeset</code></p></td>
<td align="left"><p>The <code>userattributeset</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>userattribute_id</code></p></td>
<td align="left"><p>A single previously declared <code>userattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>user_id</code></p></td>
<td align="left"><p>Zero or more previously declared <code>user</code> or <code>userattribute</code> identifiers.</p>
<p>Note that there must be at least one <code>user_id</code> or <code>expr</code> parameter declared.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>expr</code></p></td>
<td align="left"><p>Zero or more <code>expr</code>'s, the valid operators and syntax are:</p>
<p><code>    (and (user_id ...) (user_id ...))</code></p>
<p><code>    (or  (user_id ...) (user_id ...))</code></p>
<p><code>    (xor (user_id ...) (user_id ...))</code></p>
<p><code>    (not (user_id ...))</code></p>
<p><code>    (all)</code></p></td>
</tr>
</tbody>
</table>

**Example:**

This example will declare three users and two user attributes, then associate all the users to them as shown:

```secil
    (block users
        (user user_1)
        (user user_2)
        (user user_3)

        (userattribute user_holder)
        (userattributeset user_holder (user_1 user_2 user_3))

        (userattribute user_holder_all)
        (userattributeset user_holder_all (all))
    )
```

userlevel
---------

Associates a previously declared [`user`](cil_user_statements.md#user) identifier with a previously declared [`level`](cil_mls_labeling_statements.md#level) identifier. The [`level`](cil_mls_labeling_statements.md#level) may be named or anonymous.

**Statement definition:**

```secil
    (userlevel user_id level_id)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>userlevel</code></p></td>
<td align="left"><p>The <code>userlevel</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>user_id</code></p></td>
<td align="left"><p>A previously declared SELinux <code>user</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>level_id</code></p></td>
<td align="left"><p>A previously declared <code>level</code> identifier. This may consist of a single <code>sensitivity</code> with zero or more mixed named and anonymous <code>category</code>'s as discussed in the <code>level</code> statement.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will associate `unconfined.user` with a named [`level`](cil_mls_labeling_statements.md#level) of `systemlow`:

```secil
    (sensitivity s0)
    (level systemlow (s0))

    (block unconfined
        (user user)
         (userlevel user systemlow)
        ; An anonymous example:
        ;(userlevel user (s0))
    )
```

userrange
---------

Associates a previously declared [`user`](cil_user_statements.md#user) identifier with a previously declared [`levelrange`](cil_mls_labeling_statements.md#levelrange) identifier. The [`levelrange`](cil_mls_labeling_statements.md#levelrange) may be named or anonymous.

**Statement definition:**

```secil
    (userrange user_id levelrange_id)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>userrange</code></p></td>
<td align="left"><p>The <code>userrange</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>user_id</code></p></td>
<td align="left"><p>A previously declared SELinux <code>user</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>levelrange_id</code></p></td>
<td align="left"><p>A previously declared <code>levelrange</code> identifier. This may be formed by named or anonymous components as discussed in the <code>levelrange</code> statement and shown in the examples.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will associate `unconfined.user` with a named [`levelrange`](cil_mls_labeling_statements.md#levelrange) of `low_high`, other anonymous examples are also shown:

```secil
    (category c0)
    (category c1)
    (categoryorder (c0 c1))
    (sensitivity s0)
    (sensitivity s1)
    (sensitivityorder (s0 s1))
    (sensitivitycategory s0 (c0 c1))
    (level systemLow (s0))
    (level systemHigh (s0 (c0 c1)))
    (levelrange low_high (systemLow systemHigh))

    (block unconfined
        (user user)
        (role role)
        (userrole user role)
        ; Named example:
        (userrange user low_high)
        ; Anonymous examples:
        ;(userrange user (systemLow systemHigh))
        ;(userrange user (systemLow (s0 (c0 c1))))
        ;(userrange user ((s0) (s0 (c0 c1))))
    )
```

userbounds
----------

Defines a hierarchical relationship between users where the child user cannot have more privileges than the parent.

Notes:

-   It is not possible to bind the parent to more than one child.

-   While this is added to the binary policy, it is not enforced by the SELinux kernel services.

**Statement definition:**

```secil
    (userbounds parent_user_id child_user_id)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>userbounds</code></p></td>
<td align="left"><p>The <code>userbounds</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>parent_user_id</code></p></td>
<td align="left"><p>A previously declared SELinux <code>user</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>child_user_id</code></p></td>
<td align="left"><p>A previously declared SELinux <code>user</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

The user `test` cannot have greater privileges than `unconfined.user`:

```secil
    (user test)

    (unconfined
        (user user)
        (userbounds user .test)
    )
```

userprefix
----------

Declare a user prefix that will be replaced by the file labeling utilities described at [https://github.com/SELinuxProject/selinux-notebook/blob/main/src/policy_store_config_files.md](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/policy_store_config_files.md#building-the-file-labeling-support-files) that details the `file_contexts` entries.

**Statement definition:**

```secil
    (userprefix user_id prefix)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>userprefix</code></p></td>
<td align="left"><p>The <code>userprefix</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>user_id</code></p></td>
<td align="left"><p>A previously declared SELinux <code>user</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>prefix</code></p></td>
<td align="left"><p>The string to be used by the file labeling utilities.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will associate `unconfined.admin` user with a prefix of "[`user`](cil_user_statements.md#user)":

```secil
    (block unconfined
        (user admin)
        (userprefix admin user)
    )
```

selinuxuser
-----------

Associates a GNU/Linux user to a previously declared [`user`](cil_user_statements.md#user) identifier with a previously declared MLS [`userrange`](cil_user_statements.md#userrange). Note that the [`userrange`](cil_user_statements.md#userrange) is required even if the policy is non-MCS/MLS.

**Statement definition:**

```secil
    (selinuxuser user_name user_id userrange_id)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>selinuxuser</code></p></td>
<td align="left"><p>The <code>selinuxuser</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>user_name</code></p></td>
<td align="left"><p>A string representing the GNU/Linux user name</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>user_id</code></p></td>
<td align="left"><p>A previously declared SELinux <code>user</code> identifier.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>userrange_id</code></p></td>
<td align="left"><p>A previously declared <code>userrange</code> identifier that has been associated to the <code>user</code> identifier. This may be formed by named or anonymous components as discussed in the <code>userrange</code> statement and shown in the examples.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will associate `unconfined.admin` user with a GNU / Linux user "`admin_1`":

```secil
    (block unconfined
        (user admin)
        (selinuxuser admin_1 admin low_low)
    )
```

selinuxuserdefault
------------------

Declares the default SELinux user. Only one [`selinuxuserdefault`](cil_user_statements.md#selinuxuserdefault) statement is allowed in the policy. Note that the [`userrange`](cil_user_statements.md#userrange) identifier is required even if the policy is non-MCS/MLS.

**Statement definition:**

```secil
    (selinuxuserdefault user_id userrange_id)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>selinuxuserdefault</code></p></td>
<td align="left"><p>The <code>selinuxuserdefault</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>user_id</code></p></td>
<td align="left"><p>A previously declared SELinux <code>user</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>userrange_id</code></p></td>
<td align="left"><p>A previously declared <code>userrange</code> identifier that has been associated to the <code>user</code> identifier. This may be formed by named or anonymous components as discussed in the <code>userrange</code> statement and shown in the examples.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will define the `unconfined.user` as the default SELinux user:

```secil
    (block unconfined
        (user user)
        (selinuxuserdefault user low_low)
    )
```
