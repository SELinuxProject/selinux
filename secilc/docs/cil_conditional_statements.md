Conditional Statements
======================

boolean
-------

Declares a run time boolean as true or false in the current namespace. The [`booleanif`](cil_conditional_statements.md#booleanif) statement contains the CIL code that will be in the binary policy file.

[`boolean`](cil_conditional_statements.md#boolean) are not allowed in [`booleanif`](cil_conditional_statements.md#booleanif) blocks.

**Statement definition:**

```secil
    (boolean boolean_id true|false)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>boolean</code></p></td>
<td align="left"><p>The <code>boolean</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>boolean_id</code></p></td>
<td align="left"><p>The <code>boolean</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>true | false</code></p></td>
<td align="left"><p>The initial state of the boolean. This can be changed at run time using <strong><code>setsebool</code></strong><code>(8)</code> and its status queried using <strong><code>getsebool</code></strong><code>(8)</code>.</p></td>
</tr>
</tbody>
</table>

**Example:**

See the [`booleanif`](cil_conditional_statements.md#booleanif) statement for an example.

booleanif
---------

Contains the run time conditional statements that are instantiated in the binary policy according to the computed boolean identifier(s) state.

[`call`](cil_call_macro_statements.md#call) statements are allowed within a [`booleanif`](cil_conditional_statements.md#booleanif), however the contents of the resulting macro must be limited to those of the [`booleanif`](cil_conditional_statements.md#booleanif) statement (i.e. [`allow`](cil_access_vector_rules.md#allow), [`auditallow`](cil_access_vector_rules.md#auditallow), [`dontaudit`](cil_access_vector_rules.md#dontaudit), [`typemember`](cil_type_statements.md#typemember), [`typetransition`](cil_type_statements.md#typetransition), [`typechange`](cil_type_statements.md#typechange) and the compile time [`tunableif`](cil_conditional_statements.md#tunableif) statement)).

**Statement definition:**

```secil
    (booleanif boolean_id | expr ...
        (true
            cil_statements
            ...)
        (false
            cil_statements
            ...)
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
<td align="left"><p><code>booleanif</code></p></td>
<td align="left"><p>The <code>booleanif</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>boolean_id</code></p></td>
<td align="left"><p>Either a single <code>boolean</code> identifier or one or more <code>expr</code>'s.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>expr</code></p></td>
<td align="left"><p>Zero or more <code>expr</code>'s, the valid operators and syntax are:</p>
<p><code>    (and boolean_id boolean_id)</code></p>
<p><code>    (or  boolean_id boolean_id)</code></p>
<p><code>    (xor boolean_id boolean_id)</code></p>
<p><code>    (eq  boolean_id boolean_id)</code></p>
<p><code>    (neq boolean_id boolean_id)</code></p>
<p><code>    (not boolean_id)</code></p></td>
</tr>
<tr class="even">
<td align="left"><p><code>true</code></p></td>
<td align="left"><p>An optional set of CIL statements that will be instantiated when the <code>boolean</code> is evaluated as <code>true</code>.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>false</code></p></td>
<td align="left"><p>An optional set of CIL statements that will be instantiated when the <code>boolean</code> is evaluated as <code>false</code>.</p></td>
</tr>
</tbody>
</table>

**Examples:**

The second example also shows the kernel policy language equivalent:

```secil
    (boolean disableAudio false)

    (booleanif disableAudio
        (false
            (allow process mediaserver.audio_device (chr_file_set (rw_file_perms)))
        )
    )

    (boolean disableAudioCapture false)

    ;;; if(!disableAudio && !disableAudioCapture) {
    (booleanif (and (not disableAudio) (not disableAudioCapture))
        (true
            (allow process mediaserver.audio_capture_device (chr_file_set (rw_file_perms)))
        )
    )
```

tunable
-------

Tunables are similar to booleans, however they are used to manage areas of CIL statements that may or may not be in the final CIL policy that will be compiled (whereas booleans are embedded in the binary policy and can be enabled or disabled during run-time).

Note that tunables can be treated as booleans by the CIL compiler command line parameter `-P` or `--preserve-tunables` flags.

Since [`tunableif`](cil_conditional_statements.md#tunableif) statements are resolved first, [`tunable`](cil_conditional_statements.md#tunable) statements are not allowed in [`in`](cil_container_statements.md#in), [`macro`](cil_call_macro_statements.md#macro), [`optional`](cil_container_statements.md#optional), and [`booleanif`](cil_conditional_statements.md#booleanif) blocks. To simplify processing, they are also not allowed in [`tunableif`](cil_conditional_statements.md#tunableif) blocks.

**Statement definition:**

```secil
    (tunable tunable_id true|false)
```

**Where:**

<table>
<colgroup>
<col width="25%" />
<col width="75%" />
</colgroup>
<tbody>
<tr class="odd">
<td align="left"><p><code>tunable</code></p></td>
<td align="left"><p>The <code>tunable</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>tunable_id</code></p></td>
<td align="left"><p>The <code>tunable</code> identifier.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>true | false</code></p></td>
<td align="left"><p>The initial state of the <code>tunable</code>.</p></td>
</tr>
</tbody>
</table>

**Example:**

See the [`tunableif`](cil_conditional_statements.md#tunableif) statement for an example.

tunableif
---------

Compile time conditional statement that may or may not add CIL statements to be compiled.

If tunables are being treated as booleans (by using the CIL compiler command line parameter `-P` or `--preserve-tunables` flag), then only the statements allowed in a [`booleanif`](cil_conditional_statements.md#booleanif) block are allowed in a [`tunableif`](cil_conditional_statements.md#tunableif) block. Otherwise, [`tunable`](cil_conditional_statements.md#tunable) statements are not allowed in a [`tunableif`](cil_conditional_statements.md#tunableif) block.

**Statement definition:**

```secil
    (tunableif tunable_id | expr ...
        (true
            cil_statements
            ...)
        (false
            cil_statements
            ...)
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
<td align="left"><p><code>tunableif</code></p></td>
<td align="left"><p>The <code>tunableif</code> keyword.</p></td>
</tr>
<tr class="even">
<td align="left"><p><code>tunable_id</code></p></td>
<td align="left"><p>Either a single <code>tunable</code> identifier or one or more <code>expr</code>'s.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>expr</code></p></td>
<td align="left"><p>Zero or more <code>expr</code>'s, the valid operators and syntax are:</p>
<p><code>    (and tunable_id tunable_id)</code></p>
<p><code>    (or  tunable_id tunable_id)</code></p>
<p><code>    (xor tunable_id tunable_id)</code></p>
<p><code>    (eq  tunable_id tunable_id)</code></p>
<p><code>    (neq tunable_id tunable_id)</code></p>
<p><code>    (not tunable_id)</code></p></td>
</tr>
<tr class="even">
<td align="left"><p><code>true</code></p></td>
<td align="left"><p>An optional set of CIL statements that will be instantiated when the <code>tunable</code> is evaluated as <code>true</code>.</p></td>
</tr>
<tr class="odd">
<td align="left"><p><code>false</code></p></td>
<td align="left"><p>An optional set of CIL statements that will be instantiated when the <code>tunable</code> is evaluated as <code>false</code>.</p></td>
</tr>
</tbody>
</table>

**Example:**

This example will not add the range transition rule to the binary policy:

```secil
    (tunable range_trans_rule false)

    (block init
        (class process (process))
        (type process)

        (tunableif range_trans_rule
            (true
                (rangetransition process sshd.exec process low_high)
            )
        ) ; End tunableif
    ) ; End block
```
