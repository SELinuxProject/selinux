Call / Macro Statements
=======================

call
----

Instantiate a [macro](#macro) within the current namespace. There may be zero or more parameters passed to the macro (with zero parameters this is similar to the [`blockinherit`](cil_container_statements.md#blockinherit) ([`call`](cil_call_macro_statements.md#call)) / [`blockabstract`](cil_container_statements.md#blockabstract) ([`macro`](cil_call_macro_statements.md#macro)) statements).

Each parameter passed contains an argument to be resolved by the [macro](#macro), these can be named or anonymous but must conform to the parameter types defined in the [`macro`](cil_call_macro_statements.md#macro) statement.

Macro rules are resolved by searching in the following order:

-   The macro namespace (If found this means that the name was declared in the macro and is now declared in the namespace of one of the parents of the call.)

-   The call arguments

-   The parent namespaces of the macro being called (if any) with the exception of the global namespace.

-   The parent namespaces of the call (if any) with the exception of the global namespace.

-   The global namespace

**Statement definition:**

```secil
    (call macro_id [(param ...)])
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>call</code></p></td>
<td align="left"><p>The <code>call</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>macro_id</code></p></td>
<td align="left"><p>The identifier of the <code>macro</code> to be instantiated.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>param</code></p></td>
<td align="left"><p>Zero or more parameters that are passed to the macro.</p></td>
</tr>
</tbody>
</table>

**Example:**

See the [`macro`](cil_call_macro_statements.md#macro) statement for an example.

macro
-----

Declare a macro in the current namespace with its associated parameters. The macro identifier is used by the [`call`](cil_call_macro_statements.md#call) statement to instantiate the macro and resolve any parameters. The call statement may be within the body of a macro.

[`tunable`](cil_conditional_statements.md#tunable), [`in`](cil_container_statements.md#in), [`block`](cil_container_statements.md#block), [`blockinherit`](cil_container_statements.md#blockinherit), [`blockabstract`](cil_container_statements.md#blockabstract), and other [`macro`](cil_call_macro_statements.md#macro) statements are not allowed in [`macro`](cil_call_macro_statements.md#macro) blocks.

Duplicate [`macro`](cil_call_macro_statements.md#macro) declarations in the same namespace will normally cause an error, but inheriting a macro into a namespace (with [`blockinherit`](cil_container_statements.md#blockinherit)) that already has a macro with the same name will only result in a warning message and not cause an error. This behavior allows inherited macros to be overridden with local ones.

**Statement definition:**

```secil
    (macro macro_id ([(param_type param_id) ...])
        cil_statements
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
<td align="left"><p><code>macro</code></p></td>
<td align="left"><p>The <code>macro</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>macro_id</code></p></td>
<td align="left"><p>The <code>macro</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>param_type</code></p></td>
<td align="left"><p>Zero or more parameters that are passed to the macro. The <code>param_type</code> is a keyword used to determine the declaration type (e.g. <code>type</code>, <code>class</code>, <code>categoryset</code>).</p>
<p>The list of valid <code>param_type</code> entries are: <code>string</code>, <code>name</code>, <code>type</code>, <code>role</code>, <code>user</code>, <code>sensitivity</code>, <code>category</code>, <code>bool</code>, <code>categoryset</code>, <code>level</code>, <code>levelrange</code>, <code>ipaddr</code>, <code>class</code>, <code>classmap</code>, and <code>classpermission</code>.
<p>The <code>param_types</code> <code>categoryset</code>, <code>level</code>, <code>levelrange</code>, <code>classpermission</code>, and <code>ipaddr</code> can by named or anonymous.</p>
<p>The <code>param_types</code> <code>type</code>, <code>role</code>, and <code>user</code> can be used for attributes.</p>
<p>The <code>param_types</code> <code>type</code>, <code>sensitivity</code> and <code>category</code> can be used for aliases.</p>
<p>The <code>param_types</code> <code>name</code> and <code>string</node> can be used interchangeably for an <code>object_name</code> in [`typetransition`](cil_type_statements.md#typetransition) and the <code>path</code> in [`filecon`](cil_file_labeling_statements.md#filecon) statements.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>param_id</code></p></td>
<td align="left"><p>The parameter identifier used to reference the entry within the macro body (e.g. <code>ARG1</code>).</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>cil_statement</code></p></td>
<td align="left"><p>Zero or more valid CIL statements.</p></td>
</tr>
</tbody>
</table>

**Examples:**

This example will instantiate the `binder_call` macro in the calling namespace (`my_domain`) and replace `ARG1` with `appdomain` and `ARG2` with `binderservicedomain`:

```secil
    (block my_domain
        (call binder_call (appdomain binderservicedomain))
    )

    (macro binder_call ((type ARG1) (type ARG2))
        (allow ARG1 ARG2 (binder (call transfer)))
        (allow ARG2 ARG1 (binder (transfer)))
        (allow ARG1 ARG2 (fd (use)))
    )
```

This example does not pass any parameters to the macro but adds a [`type`](cil_type_statements.md#type) identifier to the current namespace:

```secil
    (block unconfined
        (call add_type)
        ....

        (macro add_type ()
            (type exec)
        )
    )
```

This example passes an anonymous and named IP address to the macro:

```secil
    (ipaddr netmask_1 255.255.255.0)
    (context netlabel_1 (system.user object_r unconfined.object low_low))

    (call build_nodecon ((192.168.1.64) netmask_1))

    (macro build_nodecon ((ipaddr ARG1) (ipaddr ARG2))
        (nodecon ARG1 ARG2  netlabel_1)
    )
```
