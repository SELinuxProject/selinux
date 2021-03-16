Constraint Statements
=====================

constrain
---------

Enable constraints to be placed on the specified permissions of the object class based on the source and target security context components.

**Statement definition:**

```secil
    (constrain classpermissionset_id ... expression | expr ...)
```

**Where:**

<table>
<colgroup>
<col width="27%" />
<col width="72%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>constrain</code></p></td>
<td align="left"><p>The <code>constrain</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>classpermissionset_id</code></p></td>
<td align="left"><p>A single named or anonymous <code>classpermissionset</code> or a single set of <code>classmap</code>/<code>classmapping</code> identifiers.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>expression</code></p></td>
<td align="left"><p>There must be one constraint <code>expression</code> or one or more <code>expr</code>'s. The expression consists of an operator and two operands as follows:</p>
<p><code>    (op u1 u2)</code></p>
<p><code>    (role_op r1 r2)</code></p>
<p><code>    (op t1 t2)</code></p>
<p><code>    (op u1 user_id | (user_id ...))</code></p>
<p><code>    (op u2 user_id | (user_id ...))</code></p>
<p><code>    (op r1 role_id | (role_id ...))</code></p>
<p><code>    (op r2 role_id | (role_id ...))</code></p>
<p><code>    (op t1 type_id | (type_id ...))</code></p>
<p><code>    (op t2 type_id | (type_id ...))</code></p>
<p>where:</p>
<p><code>  u1, r1, t1 = Source context: user, role or type</code></p>
<p><code>  u2, r2, t2 = Target context: user, role or type</code></p>
<p>and:</p>
<p><code>  op      : eq neq</code></p>
<p><code>  role_op : eq neq dom domby incomp</code></p>
<p><code>  user_id : A single user or userattribute identifier.</code></p>
<p><code>  role_id : A single role or roleattribute identifier.</code></p>
<p><code>  type_id : A single type, typealias or typeattribute identifier.</code></p></td>
</tr>
<tr class="even">
<td align="left"><p><code>expr</code></p></td>
<td align="left"><p>Zero or more <code>expr</code>'s, the valid operators and syntax are:</p>
<p><code>    (and expression expression)</code></p>
<p><code>    (or  expression expression)</code></p>
<p><code>    (not expression)</code></p></td>
</tr>
</tbody>
</table>

**Examples:**

Two constrain statements are shown with their equivalent kernel policy language statements:

```secil
    ;; constrain { file } { write }
    ;;    (( t1 == unconfined.process  ) and ( t2 == unconfined.object  ) or ( r1 eq r2 ));
    (constrain (file (write))
        (or
            (and
                (eq t1 unconfined.process)
                (eq t2 unconfined.object)
            )
            (eq r1 r2)
        )
    )

    ;; constrain { file } { read }
    ;;    (not( t1 == unconfined.process  ) and ( t2 == unconfined.object  ) or ( r1 eq r2 ));
    (constrain (file (read))
        (not
            (or
                (and
                    (eq t1 unconfined.process)
                    (eq t2 unconfined.object)
                )
                (eq r1 r2)
            )
        )
    )
```

validatetrans
-------------

The [`validatetrans`](cil_constraint_statements.md#validatetrans) statement is only used for `file` related object classes where it is used to control the ability to change the objects security context based on old, new and the current process security context.

**Statement definition:**

```secil
    (validatetrans class_id expression | expr ...)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>validatetrans</code></p></td>
<td align="left"><p>The <code>validatetrans</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>class_id</code></p></td>
<td align="left"><p>A single previously declared <code>class</code> or <code>classmap</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>expression</code></p></td>
<td align="left"><p>There must be one constraint <code>expression</code> or one or more <code>expr</code>'s. The expression consists of an operator and two operands as follows:</p>
<p><code>    (op u1 u2)</code></p>
<p><code>    (role_op r1 r2)</code></p>
<p><code>    (op t1 t2)</code></p>
<p><code>    (op u1 user_id)</code></p>
<p><code>    (op u2 user_id)</code></p>
<p><code>    (op u3 user_id)</code></p>
<p><code>    (op r1 role_id)</code></p>
<p><code>    (op r2 role_id)</code></p>
<p><code>    (op r3 role_id)</code></p>
<p><code>    (op t1 type_id)</code></p>
<p><code>    (op t2 type_id)</code></p>
<p><code>    (op t3 type_id)</code></p>
<p>where:</p>
<p><code>  u1, r1, t1 = Old context: user, role or type</code></p>
<p><code>  u2, r2, t2 = New context: user, role or type</code></p>
<p><code>  u3, r3, t3 = Process context: user, role or type</code></p>
<p>and:</p>
<p><code>  op      : eq neq</code></p>
<p><code>  role_op : eq neq dom domby incomp</code></p>
<p><code>  user_id : A single user or userattribute identifier.</code></p>
<p><code>  role_id : A single role or roleattribute identifier.</code></p>
<p><code>  type_id : A single type, typealias or typeattribute identifier.</code></p></td>
</tr>
<tr class="even">
<td align="left"><p><code>expr</code></p></td>
<td align="left"><p>Zero or more <code>expr</code>'s, the valid operators and syntax are:</p>
<p><code>    (and expression expression)</code></p>
<p><code>    (or  expression expression)</code></p>
<p><code>    (not expression)</code></p></td>
</tr>
</tbody>
</table>

**Example:**

A validate transition statement with the equivalent kernel policy language statement:

```secil
    ; validatetrans { file } ( t1 == unconfined.process  );

    (validatetrans file (eq t1 unconfined.process))
```

mlsconstrain
------------

Enable MLS constraints to be placed on the specified permissions of the object class based on the source and target security context components.

**Statement definition:**

```secil
    (mlsconstrain classpermissionset_id ... expression | expr ...)
```

**Where:**

<table>
<colgroup>
<col width="27%" />
<col width="72%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>mlsconstrain</code></p></td>
<td align="left"><p>The <code>mlsconstrain</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>classpermissionset_id</code></p></td>
<td align="left"><p>A single named or anonymous <code>classpermissionset</code> or a single set of <code>classmap</code>/<code>classmapping</code> identifiers.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>expression</code></p></td>
<td align="left"><p>There must be one constraint <code>expression</code> or one or more <code>expr</code>'s. The expression consists of an operator and two operands as follows:</p>
<p><code>    (op u1 u2)</code></p>
<p><code>    (mls_role_op r1 r2)</code></p>
<p><code>    (op t1 t2)</code></p>
<p><code>    (mls_role_op l1 l2)</code></p>
<p><code>    (mls_role_op l1 h2)</code></p>
<p><code>    (mls_role_op h1 l2)</code></p>
<p><code>    (mls_role_op h1 h2)</code></p>
<p><code>    (mls_role_op l1 h1)</code></p>
<p><code>    (mls_role_op l2 h2)</code></p>
<p><code>    (op u1 user_id)</code></p>
<p><code>    (op u2 user_id)</code></p>
<p><code>    (op r1 role_id)</code></p>
<p><code>    (op r2 role_id)</code></p>
<p><code>    (op t1 type_id)</code></p>
<p><code>    (op t2 type_id)</code></p>
<p>where:</p>
<p><code>  u1, r1, t1, l1, h1 = Source context: user, role, type, low level or high level</code></p>
<p><code>  u2, r2, t2, l2, h2 = Target context: user, role, type, low level or high level</code></p>
<p>and:</p>
<p><code>  op          : eq neq</code></p>
<p><code>  mls_role_op : eq neq dom domby incomp</code></p>
<p><code>  user_id     : A single user or userattribute identifier.</code></p>
<p><code>  role_id     : A single role or roleattribute identifier.</code></p>
<p><code>  type_id     : A single type, typealias or typeattribute identifier.</code></p></td>
</tr>
<tr class="even">
<td align="left"><p><code>expr</code></p></td>
<td align="left"><p>Zero or more <code>expr</code>'s, the valid operators and syntax are:</p>
<p><code>    (and expression expression)</code></p>
<p><code>    (or  expression expression)</code></p>
<p><code>    (not expression)</code></p></td>
</tr>
</tbody>
</table>

**Example:**

An MLS constrain statement with the equivalent kernel policy language statement:

```secil
    ;; mlsconstrain { file } { open }
    ;;     (( l1 eq l2 ) and ( u1 == u2 ) or ( r1 != r2 ));

    (mlsconstrain (file (open))
        (or
            (and
                (eq l1 l2)
                (eq u1 u2)
            )
            (neq r1 r2)
        )
    )
```

mlsvalidatetrans
----------------

The [`mlsvalidatetrans`](cil_constraint_statements.md#mlsvalidatetrans) statement is only used for `file` related object classes where it is used to control the ability to change the objects security context based on old, new and the current process security context.

**Statement definition:**

```secil
    (mlsvalidatetrans class_id expression | expr ...)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>mlsvalidatetrans</code></p></td>
<td align="left"><p>The <code>mlsvalidatetrans</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>class_id</code></p></td>
<td align="left"><p>A single previously declared <code>class</code> or <code>classmap</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>expression</code></p></td>
<td align="left"><p>There must be one constraint <code>expression</code> or one or more <code>expr</code>'s. The expression consists of an operator and two operands as follows:</p>
<p><code>    (op u1 u2)</code></p>
<p><code>    (mls_role_op r1 r2)</code></p>
<p><code>    (op t1 t2)</code></p>
<p><code>    (mls_role_op l1 l2)</code></p>
<p><code>    (mls_role_op l1 h2)</code></p>
<p><code>    (mls_role_op h1 l2)</code></p>
<p><code>    (mls_role_op h1 h2)</code></p>
<p><code>    (mls_role_op l1 h1)</code></p>
<p><code>    (mls_role_op l2 h2)</code></p>
<p><code>    (op u1 user_id)</code></p>
<p><code>    (op u2 user_id)</code></p>
<p><code>    (op u3 user_id)</code></p>
<p><code>    (op r1 role_id)</code></p>
<p><code>    (op r2 role_id)</code></p>
<p><code>    (op r3 role_id)</code></p>
<p><code>    (op t1 type_id)</code></p>
<p><code>    (op t2 type_id)</code></p>
<p><code>    (op t3 type_id)</code></p>
<p>where:</p>
<p><code>  u1, r1, t1, l1, h1 = Source context: user, role, type, low level or high level</code></p>
<p><code>  u2, r2, t2, l2, h2 = Target context: user, role, type, low level or high level</code></p>
<p><code>  u3, r3, t3         = Process context: user, role or type</code></p>
<p>and:</p>
<p><code>  op          : eq neq</code></p>
<p><code>  mls_role_op : eq neq dom domby incomp</code></p>
<p><code>  user_id     : A single user or userattribute identifier.</code></p>
<p><code>  role_id     : A single role or roleattribute identifier.</code></p>
<p><code>  type_id     : A single type, typealias or typeattribute identifier.</code></p></td>
</tr>
<tr class="even">
<td align="left"><p><code>expr</code></p></td>
<td align="left"><p>Zero or more <code>expr</code>'s, the valid operators and syntax are:</p>
<p><code>    (and expression expression)</code></p>
<p><code>    (or  expression expression)</code></p>
<p><code>    (not expression)</code></p></td>
</tr>
</tbody>
</table>

**Example:**

An MLS validate transition statement with the equivalent kernel policy language statement:

```secil
    ;; mlsvalidatetrans { file } ( l1 domby h2 );

    (mlsvalidatetrans file (domby l1 h2))
```
