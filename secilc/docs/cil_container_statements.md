Container Statements
====================

block
-----

Start a new namespace where any CIL statement is valid.

**Statement definition:**

    (block block_id
        cil_statement
        ...
    )

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>block</code></p></td>
<td align="left"><p>The <code>block</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>block_id</code></p></td>
<td align="left"><p>The namespace identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>cil_statement</code></p></td>
<td align="left"><p>Zero or more valid CIL statements.</p></td>
</tr>
</tbody>
</table>

**Example:**

See the [`blockinherit`](cil_container_statements.md#blockinherit) statement for an example.

blockabstract
-------------

Declares the namespace as a 'template' and does not generate code until instantiated by another namespace that has a [`blockinherit`](cil_container_statements.md#blockinherit) statement.

**Statement definition:**

    (block block_id
        (blockabstract template_id)
        cil_statement
        ...
    )

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>block</code></p></td>
<td align="left"><p>The <code>block</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>block_id</code></p></td>
<td align="left"><p>The namespace identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>blockabstract</code></p></td>
<td align="left"><p>The <code>blockabstract</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>template_id</code></p></td>
<td align="left"><p>The abstract namespace identifier. This must match the <code>block_id</code> entry.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>cil_statement</code></p></td>
<td align="left"><p>Zero or more valid CIL statements forming the abstract block.</p></td>
</tr>
</tbody>
</table>

**Example:**

See the [`blockinherit`](cil_container_statements.md#blockinherit) statement for an example.

blockinherit
------------

Used to add common policy rules to the current namespace via a template that has been defined with the [`blockabstract`](cil_container_statements.md#blockabstract) statement. All [`blockinherit`](cil_container_statements.md#blockinherit) statements are resolved first and then the contents of the block are copied. This is so that inherited blocks will not be inherited. For a concrete example, please see the examples section.

**Statement definition:**

    (block block_id
        (blockinherit template_id)
        cil_statement
        ...
    )

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>block</code></p></td>
<td align="left"><p>The <code>block</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>block_id</code></p></td>
<td align="left"><p>The namespace identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>blockinherit</code></p></td>
<td align="left"><p>The <code>blockinherit</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>template_id</code></p></td>
<td align="left"><p>The inherited namespace identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>cil_statement</code></p></td>
<td align="left"><p>Zero or more valid CIL statements.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example contains a template `client_server` that is instantiated in two blocks (`netserver_app` and `netclient_app`):

    ; This is the template block:
    (block client_server
        (blockabstract client_server)

        ; Log file labeling
        (type log_file)
        (typeattributeset file_type (log_file))
        (typeattributeset data_file_type (log_file))
        (allow process log_file (dir (write search create setattr add_name)))
        (allow process log_file (file (create open append getattr setattr)))
        (roletype object_r log_file)
        (context log_file_context (u object_r log_file low_low))

        ; Process labeling
        (type process)
        (typeattributeset domain (process))
        (call app_domain (process))
        (call net_domain (process))
    )

    ; This is a policy block that will inherit the abstract block above:
    (block netclient_app
        ; Add common policy rules to namespace:
        (blockinherit client_server)
        ; Label the log files
        (filecon "/data/data/com.se4android.netclient/.*" file log_file_context)
    )

    ; This is another policy block that will inherit the abstract block above:
    (block netserver_app
       ; Add common policy rules to namespace:
        (blockinherit client_server)

        ; Label the log files
        (filecon "/data/data/com.se4android.netserver/.*" file log_file_context)
    )

    ; This is an example of how blockinherits resolve inherits before copying
    (block a
        (type one))

    (block b
        ; Notice that block a is declared here as well
        (block a
            (type two)))

    ; This will first copy the contents of block b, which results in type b.a.two being copied.
    ; Next, the contents of block a will be copied which will result in type a.one.
    (block ab
        (blockinherit b)
        (blockinherit a))

optional
--------

Declare an [`optional`](cil_container_statements.md#optional) namespace. All CIL statements in the optional block must be satisfied before instantiation in the binary policy. [`tunableif`](cil_conditional_statements.md#tunableif) and [`macro`](cil_call_macro_statements.md#macro) statements are not allowed in optional containers. The same restrictions apply to CIL policy statements within [`optional`](cil_container_statements.md#optional)'s that apply to kernel policy statements, i.e. only the policy statements shown in the following table are valid:

|                     |                |                    |                    |
| ------------------- | -------------- | ------------------ | ------------------ |
| [`allow`](cil_access_vector_rules.md#allow)             | [`allowx`](cil_access_vector_rules.md#allowx)       | [`auditallow`](cil_access_vector_rules.md#auditallow)       | [`auditallowx`](cil_access_vector_rules.md#auditallowx)      |
| [`booleanif`](cil_conditional_statements.md#booleanif)         | [`dontaudit`](cil_access_vector_rules.md#dontaudit)    | [`dontauditx`](cil_access_vector_rules.md#dontauditx)       | [`typepermissive`](cil_type_statements.md#typepermissive)   |
| [`rangetransition`](cil_mls_labeling_statements.md#rangetransition)   | [`role`](cil_role_statements.md#role)         | [`roleallow`](cil_role_statements.md#roleallow)        | [`roleattribute`](cil_role_statements.md#roleattribute)    |
| [`roletransition`](cil_role_statements.md#roletransition)    | [`type`](cil_type_statements.md#type)         | [`typealias`](cil_type_statements.md#typealias)        | [`typeattribute`](cil_type_statements.md#typeattribute)    |
| [`typechange`](cil_type_statements.md#typechange)        | [`typemember`](cil_type_statements.md#typemember)   | [`typetransition`](cil_type_statements.md#typetransition)   |                    |

**Statement definition:**

    (optional optional_id
        cil_statement
        ...
    )

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>optional</code></p></td>
<td align="left"><p>The <code>optional</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>optional_id</code></p></td>
<td align="left"><p>The <code>optional</code> namespace identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>cil_statement</code></p></td>
<td align="left"><p>Zero or more valid CIL statements.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will instantiate the optional block `ext_gateway.move_file` into policy providing all optional CIL statements can be resolved:

    (block ext_gateway
        ......
        (optional move_file
            (typetransition process msg_filter.move_file.in_queue file msg_filter.move_file.in_file)
            (allow process msg_filter.move_file.in_queue (dir (read getattr write search add_name)))
            (allow process msg_filter.move_file.in_file (file (write create getattr)))
            (allow msg_filter.move_file.in_file unconfined.object (filesystem (associate)))
            (typetransition msg_filter.int_gateway.process msg_filter.move_file.out_queue file
                msg_filter.move_file.out_file)
            (allow msg_filter.int_gateway.process msg_filter.move_file.out_queue (dir (read write search)))
            (allow msg_filter.int_gateway.process msg_filter.move_file.out_file (file (read getattr unlink)))
        ) ; End optional block

        .....
    ) ; End block

in
--

Allows the insertion of CIL statements into a named container ([`block`](cil_container_statements.md#block), [`optional`](cil_container_statements.md#optional) or [`macro`](cil_call_macro_statements.md#macro)). This statement is not allowed in [`booleanif`](cil_conditional_statements.md#booleanif) or [`tunableif`](cil_conditional_statements.md#tunableif) statements. This only works for containers that aren't inherited using [`blockinherit`](cil_conditional_statements.md#blockinherit).

**Statement definition:**

    (in container_id
        cil_statement
        ...
    )

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>in</code></p></td>
<td align="left"><p>The <code>in</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>container_id</code></p></td>
<td align="left"><p>A valid <code>block</code>, <code>optional</code> or <code>macro</code> namespace identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>cil_statement</code></p></td>
<td align="left"><p>Zero or more valid CIL statements.</p></td>
</tr>
</tbody>
</table>

**Example:**

This will add rules to the container named `system_server`:

    (in system_server
        (dontaudit process secmark_demo.dns_packet (packet (send recv)))
        (allow process secmark_demo.dns_packet (packet (send recv)))
    )
