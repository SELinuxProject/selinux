Role Statements
===============

role
----

Declares a role identifier in the current namespace.

**Statement definition:**

    (role role_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>role</code></p></td>
<td align="left"><p>The <code>role</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>role_id</code></p></td>
<td align="left"><p>The <code>role</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example declares two roles: `object_r` in the global namespace and `unconfined.role`:

    (role object_r)

    (block unconfined
        (role role)
    )

roletype
--------

Authorises a [`role`](cil_role_statements.md#role) to access a [`type`](cil_type_statements.md#type) identifier.

**Statement definition:**

    (role role_id type_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>roletype</code></p></td>
<td align="left"><p>The <code>roletype</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>role_id</code></p></td>
<td align="left"><p>A single previously declared <code>role</code> or <code>roleattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>type_id</code></p></td>
<td align="left"><p>A single previously declared <code>type</code>, <code>typealias</code> or <code>typeattribute</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will declare [`role`](cil_role_statements.md#role) and [`type`](cil_type_statements.md#type) identifiers, then associate them:

    (block unconfined
        (role role)
        (type process)
        (roletype role process)
    )

roleattribute
-------------

Declares a role attribute identifier in the current namespace. The identifier may have zero or more [`role`](cil_role_statements.md#role) and [`roleattribute`](cil_role_statements.md#roleattribute) identifiers associated to it via the [`typeattributeset`](cil_type_statements.md#typeattributeset) statement.

**Statement definition:**

    (roleattribute roleattribute_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>roleattribute</code></p></td>
<td align="left"><p>The <code>roleattribute</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>roleattribute_id</code></p></td>
<td align="left"><p>The <code>roleattribute</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will declare a role attribute `roles.role_holder` that will have an empty set:

    (block roles
        (roleattribute role_holder)
    )

roleattributeset
----------------

Allows the association of one or more previously declared [`role`](cil_role_statements.md#role) identifiers to a [`roleattribute`](cil_role_statements.md#roleattribute) identifier. Expressions may be used to refine the associations as shown in the examples.

**Statement definition:**

    (roleattributeset roleattribute_id (role_id ... | expr ...))

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>roleattributeset</code></p></td>
<td align="left"><p>The <code>roleattributeset</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>roleattribute_id</code></p></td>
<td align="left"><p>A single previously declared <code>roleattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>role_id</code></p></td>
<td align="left"><p>Zero or more previously declared <code>role</code> or <code>roleattribute</code> identifiers.</p>
<p>Note that there must be at least one <code>role_id</code> or <code>expr</code> parameter declared.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>expr</code></p></td>
<td align="left"><p>Zero or more <code>expr</code>'s, the valid operators and syntax are:</p>
<p><code>    (and (role_id ...) (role_id ...))</code></p>
<p><code>    (or  (role_id ...) (role_id ...))</code></p>
<p><code>    (xor (role_id ...) (role_id ...))</code></p>
<p><code>    (not (role_id ...))</code></p>
<p><code>    (all)</code></p></td>
</tr>
</tbody>
</table>

**Example:**

This example will declare three roles and two role attributes, then associate all the roles to them as shown:

    (block roles
        (role role_1)
        (role role_2)
        (role role_3)

        (roleattribute role_holder)
        (roleattributeset role_holder (role_1 role_2 role_3))

        (roleattribute role_holder_all)
        (roleattributeset role_holder_all (all))
    )

roleallow
---------

Authorise the current role to assume a new role.

Notes:

-   May require a [`roletransition`](cil_role_statements.md#roletransition) rule to ensure transition to the new role.

-   This rule is not allowed in [`booleanif`](cil_conditional_statements.md#booleanif) statements.

**Statement definition:**

    (roleallow current_role_id new_role_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>roleallow</code></p></td>
<td align="left"><p>The <code>roleallow</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>current_role_id</code></p></td>
<td align="left"><p>A single previously declared <code>role</code> or <code>roleattribute</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>new_role_id</code></p></td>
<td align="left"><p>A single previously declared <code>role</code> or <code>roleattribute</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

See the [`roletransition`](cil_role_statements.md#roletransition) statement for an example.

roletransition
--------------

Specify a role transition from the current role to a new role when computing a context for the target type. The [`class`](cil_class_and_permission_statements.md#class) identifier would normally be `process`, however for kernel versions 2.6.39 with policy version \>= 25 and above, any valid class may be used. Note that a [`roleallow`](cil_role_statements.md#roleallow) rule must be used to authorise the transition.

**Statement definition:**

    (roletransition current_role_id target_type_id class_id new_role_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>roletransition</code></p></td>
<td align="left"><p>The <code>roletransition</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>current_role_id</code></p></td>
<td align="left"><p>A single previously declared <code>role</code> or <code>roleattribute</code> identifier.</p></td>
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
<td align="left"><p><code>new_role_id</code></p></td>
<td align="left"><p>A single previously declared <code>role</code> identifier to be set on transition.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will authorise the `unconfined.role` to assume the `msg_filter.role` role, and then transition to that role:

    (block ext_gateway
        (type process)
        (type exec)

        (roletype msg_filter.role process)
        (roleallow unconfined.role msg_filter.role)
        (roletransition unconfined.role exec process msg_filter.role)
    )

rolebounds
----------

Defines a hierarchical relationship between roles where the child role cannot have more privileges than the parent.

Notes:

-   It is not possible to bind the parent role to more than one child role.

-   While this is added to the binary policy, it is not enforced by the SELinux kernel services.

**Statement definition:**

    (rolebounds parent_role_id child_role_id)

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>rolebounds</code></p></td>
<td align="left"><p>The <code>rolebounds</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>parent_role_id</code></p></td>
<td align="left"><p>A single previously declared <code>role</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>child_role_id</code></p></td>
<td align="left"><p>A single previously declared <code>role</code> identifier.</p></td>
</tr>
</tbody>
</table>

**Example:**

In this example the role `test` cannot have greater priviledges than `unconfined.role`:

    (role test)

    (unconfined
        (role role)
        (rolebounds role .test)
    )
