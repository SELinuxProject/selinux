Call / Macro Statements
=======================

call
----

Instantiate a [macro](#macro) within the current namespace. There may be zero or more parameters passed to the macro (with zero parameters this is similar to the [`blockinherit`](cil_container_statements.md#blockinherit) ([`call`](cil_call_macro_statements.md#call)) / [`blockabstract`](cil_container_statements.md#blockabstract) ([`macro`](cil_call_macro_statements.md#macro)) statements).

Each parameter passed contains an argument to be resolved by the [macro](#macro), these can be named or anonymous but must conform to the parameter types defined in the [`macro`](cil_call_macro_statements.md#macro) statement.

**Statement definition:**

    (call macro_id [(param ...)])

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

Note that when resolving macros the callers namespace is not checked, only the following places:

-   Items defined inside the macro

-   Items passed into the macro as arguments

-   Items defined in the same namespace of the macro

-   Items defined in the global namespace

**Statement definition:**

    (macro macro_id ([(param_type param_id) ...])
        cil_statements
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
<p>The list of valid <code>param_type</code> entries are: <code>type</code>, <code>typealias</code>, <code>role</code>, <code>user</code>, <code>sensitivity</code>, <code>sensitivityalias</code>, <code>category</code>, <code>categoryalias</code>, <code>categoryset</code> (named or anonymous), <code>level</code> (named or anonymous), <code>levelrange</code> (named or anonymous), <code>class</code>, <code>classpermission</code> (named or anonymous), <code>ipaddr</code> (named or anonymous), <code>block</code>, <code>name</code> (a string), <code>classmap</code></p></td>
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

    (block my_domain
        (call binder_call (appdomain binderservicedomain))
    )

    (macro binder_call ((type ARG1) (type ARG2))
        (allow ARG1 ARG2 (binder (call transfer)))
        (allow ARG2 ARG1 (binder (transfer)))
        (allow ARG1 ARG2 (fd (use)))
    )

This example does not pass any parameters to the macro but adds a [`type`](cil_type_statements.md#type) identifier to the current namespace:

    (block unconfined
        (call add_type)
        ....

        (macro add_type ()
            (type exec)
        )
    )

This example passes an anonymous and named IP address to the macro:

    (ipaddr netmask_1 255.255.255.0)
    (context netlabel_1 (system.user object_r unconfined.object low_low)

    (call build_nodecon ((192.168.1.64) netmask_1))

    (macro build_nodecon ((ipaddr ARG1) (ipaddr ARG2))
        (nodecon ARG1 ARG2  netlabel_1)
    )
