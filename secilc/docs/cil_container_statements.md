Container Statements
====================

block
-----

Start a new namespace.

Not allowed in [`macro`](cil_call_macro_statements.md#macro) and [`optional`](cil_container_statements.md#optional) blocks.

[`sensitivity`](cil_mls_labeling_statements.md#sensitivity) and [`category`](cil_mls_labeling_statements.md#category) statements are not allowed in [`block`](cil_container_statements.md#block) blocks.

Duplicate declarations of a [`block`](cil_container_statements.md#block) in the same namespace will normally cause an error, but inheriting a block into a namespace (with [`blockinherit`](cil_container_statements.md#blockinherit)) that already has a block with the same name will only result in a warning message and not cause an error. The policy from both blocks will end up in the binary policy. This behavior was used in the past to allow a block to be declared so that an [`in-statement`](cil_container_statements.md#in) could be used on it, but now an [`in-statement`](cil_container_statements.md#in) can be specified to occur after inheritance, so this behavior is not necessary (but is still allowed).

**Statement definition:**

```secil
    (block block_id
        cil_statement
        ...
    )
```

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

Not allowed in [`macro`](cil_call_macro_statements.md#macro) and [`optional`](cil_container_statements.md#optional) blocks.

**Statement definition:**

```secil
    (block block_id
        (blockabstract template_id)
        cil_statement
        ...
    )
```

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

Inherited rules are resolved by searching namespaces in the following order:

-  The parent namespaces (if any) where the [`blockinherit`](cil_container_statements.md#blockinherit) rule is located with the exception of the global namespace.

-  The parent namespaces of the block being inherited (but not that block's namespace) with the exception of the global namespace.

-  The global namespace.

Not allowed in [`macro`](cil_call_macro_statements.md#macro) blocks.

**Statement definition:**

```secil
    (block block_id
        (blockinherit template_id)
        cil_statement
        ...
    )
```

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

```secil
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
```

optional
--------

Declare an [`optional`](cil_container_statements.md#optional) namespace. All CIL statements in the optional block must be satisfied before instantiation in the binary policy.

Not allowed in [`booleanif`](cil_conditional_statements.md#booleanif) blocks.

[`tunable`](cil_conditional_statements.md#tunable), [`in`](cil_container_statements.md#in), [`block`](cil_container_statements.md#block), [`blockabstract`](cil_container_statements.md#blockabstract), and [`macro`](cil_call_macro_statements.md#macro) statements are not allowed in [`optional`](cil_container_statements.md#optional) blocks.

**Statement definition:**

```secil
    (optional optional_id
        cil_statement
        ...
    )
```

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

```secil
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
```

in
--

Allows the insertion of CIL statements into a named container ([`block`](cil_container_statements.md#block), [`optional`](cil_container_statements.md#optional) or [`macro`](cil_call_macro_statements.md#macro)). This insertion can be specified to occur either before or after block inheritance has been resolved.

Not allowed in [`macro`](cil_call_macro_statements.md#macro), [`booleanif`](cil_conditional_statements.md#booleanif), and other [`in`](cil_container_statements.md#in) blocks.

[`tunable`](cil_conditional_statements.md#tunable) and [`in`](cil_container_statements.md#in) statements are not allowed in [`in`](cil_container_statements.md#in) blocks.

**Statement definition:**

```secil
    (in [before|after] container_id
        cil_statement
        ...
    )
```

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
<td align="left"><p><code>before|after</code></p></td>
<td align="left"><p>An optional value that specifies whether to process the [`in`](cil_container_statements.md#in) <code>before</code> or <code>after</code> block inheritance. If no value is specified, then the [`in`](cil_container_statements.md#in) will be processed before block inheritance.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>container_id</code></p></td>
<td align="left"><p>A valid <code>block</code>, <code>optional</code> or <code>macro</code> namespace identifier.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>cil_statement</code></p></td>
<td align="left"><p>Zero or more valid CIL statements.</p></td>
</tr>
</tbody>
</table>

**Example:**

This will add rules to the container named `system_server`:

```secil
    (in system_server
        (dontaudit process secmark_demo.dns_packet (packet (send recv)))
        (allow process secmark_demo.dns_packet (packet (send recv)))
    )
```
